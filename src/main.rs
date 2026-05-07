mod cert;
mod error;
mod nshield;
mod session;
mod signer;

use std::io::Write as IoWrite;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use sequoia_openpgp::{
    armor, packet::signature::SignatureBuilder, serialize::stream::*, types::SignatureType,
};

use session::{KeySelector, LoginMode, Pkcs11Uri};
use signer::Pkcs11Signer;

/// OpenPGP signing tool backed by a PKCS#11 HSM.
#[derive(Parser)]
#[command(name = "sq-pkcs11", version)]
struct Cli {
    /// Path to the PKCS#11 shared library (vendor module).
    ///
    /// May also be set via the PKCS11_MODULE_PATH environment variable
    /// (standard, used by pkcs11-tool / p11-kit) or SQ_PKCS11_MODULE
    /// (tool-specific fallback, checked when PKCS11_MODULE_PATH is unset).
    #[arg(short = 'm', long, env = "PKCS11_MODULE_PATH", value_name = "PATH")]
    module: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a detached OpenPGP signature for a file.
    Sign(SignArgs),
    /// Export the OpenPGP public certificate from an HSM key.
    CertExport(CertExportArgs),
    /// Issue a primary-key revocation certificate.
    CertRevoke(CertRevokeArgs),
    /// Issue a subkey-revocation certificate.
    SubkeyRevoke(SubkeyRevokeArgs),
    /// List signing keys visible in the PKCS#11 token.
    ListKeys(ListKeysArgs),
}

// ---------------------------------------------------------------------------
// Key selection flags — shared between subcommands via flatten.
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
struct KeySelectionArgs {
    /// PKCS#11 URI, e.g. pkcs11:token=release;object=signing-key;type=private
    #[arg(long, group = "key_selector", value_name = "URI")]
    key_uri: Option<String>,

    /// Select key by CKA_LABEL.
    #[arg(long, group = "key_selector", value_name = "LABEL")]
    key_label: Option<String>,

    /// Select key by CKA_ID (hex string, e.g. 01ab02).
    #[arg(long, group = "key_selector", value_name = "HEX")]
    key_id: Option<String>,

    /// Auto-select if exactly one usable key is present.
    #[arg(long, group = "key_selector")]
    auto: bool,
}

impl KeySelectionArgs {
    fn resolve(&self) -> anyhow::Result<KeySelector> {
        if let Some(uri) = &self.key_uri {
            let parsed: Pkcs11Uri = uri.parse()?;
            return Ok(KeySelector::Uri(parsed));
        }
        if let Some(label) = &self.key_label {
            return Ok(KeySelector::Label(label.clone()));
        }
        if let Some(id_hex) = &self.key_id {
            let bytes = hex::decode(id_hex)
                .with_context(|| format!("invalid hex in --key-id: {id_hex}"))?;
            return Ok(KeySelector::Id(bytes));
        }
        if self.auto {
            return Ok(KeySelector::Auto);
        }
        anyhow::bail!("specify one of --key-uri, --key-label, --key-id, or --auto")
    }
}

// ---------------------------------------------------------------------------
// Auth flags — shared between sign and cert-export.
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
struct AuthArgs {
    /// Read the softcard / K=1 OCS passphrase from this file.  A single
    /// trailing newline (CR, LF, or CRLF) is removed; no other characters
    /// are trimmed, so leading or interior whitespace in the passphrase is
    /// preserved.  Omit entirely for module-protected keys.
    ///
    /// As an alternative, the `SQ_PKCS11_PIN` environment variable is read
    /// when this flag is absent.  There is no `--pin <PASS>` value flag
    /// because passphrases on the command line leak through process
    /// listings and shell history.
    #[arg(long, value_name = "FILE", group = "auth")]
    pin_file: Option<PathBuf>,

    /// Interactive OCS quorum login (K > 1 card sets).
    /// The tool will prompt for each card's passphrase in turn using the
    /// nShield C_LoginBegin / C_LoginNext / C_LoginEnd extension API.
    #[arg(long, group = "auth")]
    ocs: bool,
}

impl AuthArgs {
    fn login_mode<'a>(&'a self, module: &'a std::path::Path) -> anyhow::Result<LoginMode<'a>> {
        if self.ocs {
            return Ok(LoginMode::OcsQuorum {
                module_path: module,
            });
        }
        if let Some(path) = &self.pin_file {
            return Ok(LoginMode::Pin(read_pin_file(path)?));
        }
        if let Ok(pin) = std::env::var("SQ_PKCS11_PIN") {
            return Ok(LoginMode::Pin(pin));
        }
        Ok(LoginMode::None)
    }
}

/// Read a passphrase from a file: drop the trailing newline (if any),
/// reject totally-empty contents.
fn read_pin_file(path: &std::path::Path) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading pin file {}", path.display()))?;
    let pin = raw.trim_end_matches(['\n', '\r']).to_string();
    if pin.is_empty() {
        anyhow::bail!("pin file {} is empty", path.display());
    }
    Ok(pin)
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
struct SignArgs {
    #[command(flatten)]
    key: KeySelectionArgs,

    #[command(flatten)]
    auth: AuthArgs,

    /// File to sign.
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// Write signature to this path (default: <input>.asc).  Pass `-` to
    /// stream the signature to stdout instead of writing a file — useful
    /// when the wrapping script (e.g. a `git config gpg.program` shim)
    /// needs to capture the signature without a temp-file dance.
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// Produce binary signature instead of ASCII-armored.
    /// (Default output is ASCII-armored, matching GnuPG and Sequoia conventions.)
    #[arg(long)]
    binary: bool,

    /// Overwrite the output file if it already exists.  Without this flag,
    /// sq-pkcs11 refuses to overwrite an existing file — protects against
    /// accidentally clobbering a previously-signed release artefact.
    #[arg(long)]
    force: bool,

    /// Key creation time used to compute the OpenPGP fingerprint embedded in
    /// the signature's issuer field (RFC 3339, e.g. 2026-04-30T16:29:30Z).
    ///
    /// Must match the value used during cert-export so verifiers can resolve
    /// the issuer fingerprint to the distributed certificate.
    /// Defaults to Unix epoch when omitted — use this default consistently
    /// if you did not pass --creation-time during cert-export either.
    #[arg(long, value_name = "TIMESTAMP")]
    creation_time: Option<String>,
}

// ---------------------------------------------------------------------------
// cert-export
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
struct CertExportArgs {
    #[command(flatten)]
    key: KeySelectionArgs,

    #[command(flatten)]
    auth: AuthArgs,

    /// User ID to embed, e.g. "OpenSSL Release Key <openssl-security@openssl.org>".
    /// Repeat to add multiple User IDs.  Matches `sq key generate --userid`.
    ///
    /// Required for fresh certs.  Optional with --merge-cert: omitted means
    /// keep the existing cert's UIDs as-is; supplied UIDs are *added*.
    #[arg(
        long = "userid",
        value_name = "USERID",
        required_unless_present = "merge_cert"
    )]
    user_ids: Vec<String>,

    /// Write certificate to this path (default: stdout).
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// Merge new packets (UIDs and/or subkey) into an existing certificate
    /// rather than building a fresh one.
    ///
    /// Use this for **subkey rotation**: re-running cert-export with a new
    /// `--subkey-label` and the original cert preserves all existing
    /// subkeys (so old signatures keep verifying), revocations, and UIDs,
    /// while adding the new subkey-binding signature.
    ///
    /// The primary fingerprint of the existing cert must match what the
    /// HSM key + `--creation-time` would produce — the tool refuses to
    /// merge across different primary keys.
    #[arg(long, value_name = "FILE")]
    merge_cert: Option<PathBuf>,

    /// Output a binary OpenPGP certificate instead of ASCII-armored.
    #[arg(long)]
    binary: bool,

    /// Overwrite the output file if it already exists.  Without this flag,
    /// sq-pkcs11 refuses to overwrite an existing file — protects against
    /// accidentally clobbering a previously-published certificate.
    #[arg(long)]
    force: bool,

    /// Key creation time to embed in the certificate (RFC 3339,
    /// e.g. 2026-04-30T16:29:30Z).
    ///
    /// The OpenPGP fingerprint is derived from key material + creation time,
    /// so this value must be used consistently in every subsequent `sign`
    /// invocation.  Defaults to Unix epoch when omitted, which is a stable
    /// value that requires no coordination between cert-export and sign.
    #[arg(long, value_name = "TIMESTAMP")]
    creation_time: Option<String>,

    /// Key validity period, relative to the creation time.
    ///
    /// Format: integer + unit (y = years, w = weeks, d = days, h = hours).
    /// Examples: "5y", "730d", "260w".  Defaults to 5 years.
    /// Years use the calendar approximation 1y = 365.25 days.
    ///
    /// Re-issue the certificate before expiry to extend it.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = "5y",
        group = "validity"
    )]
    validity_period: String,

    /// Issue a certificate with no expiration.
    ///
    /// Mutually exclusive with --validity-period.  Use sparingly: an
    /// expiration bounds the blast radius if the HSM is ever compromised.
    #[arg(long, group = "validity")]
    no_expiration: bool,

    // ────────────────────────────────────────────────────────────────────
    // Optional signing subkey.
    //
    // When a --subkey-* selector is present, the primary key becomes
    // Certify-only and the subkey carries the Sign capability.  Each tier
    // is authenticated independently — typically primary on OCS, subkey
    // module-protected.
    // ────────────────────────────────────────────────────────────────────
    /// Subkey selector — PKCS#11 URI form.
    #[arg(long, value_name = "URI", group = "subkey_selector")]
    subkey_uri: Option<String>,

    /// Subkey selector — by CKA_LABEL.
    #[arg(long, value_name = "LABEL", group = "subkey_selector")]
    subkey_label: Option<String>,

    /// Subkey selector — by CKA_ID (hex).
    #[arg(long, value_name = "HEX", group = "subkey_selector")]
    subkey_id: Option<String>,

    /// Subkey selector — auto-pick when exactly one usable subkey is visible.
    #[arg(long, group = "subkey_selector")]
    subkey_auto: bool,

    /// File containing the subkey passphrase, if it is softcard- or
    /// single-card-OCS-protected.  Same semantics as --pin-file.  The
    /// `SQ_PKCS11_SUBKEY_PIN` environment variable is read when this flag
    /// is absent.  No `--subkey-pin <PASS>` value flag — see --pin-file.
    #[arg(
        long,
        value_name = "FILE",
        group = "subkey_auth",
        requires = "subkey_selector"
    )]
    subkey_pin_file: Option<PathBuf>,

    /// Use nShield K/N quorum login for the subkey.
    #[arg(long, group = "subkey_auth", requires = "subkey_selector")]
    subkey_ocs: bool,

    /// Subkey creation time (RFC 3339).  Same semantics as --creation-time.
    #[arg(long, value_name = "TIMESTAMP", requires = "subkey_selector")]
    subkey_creation_time: Option<String>,

    /// Subkey validity period (default: 2y).  Same format as --validity-period.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = "2y",
        group = "subkey_validity",
        requires = "subkey_selector"
    )]
    subkey_validity_period: String,

    /// Issue the subkey with no expiration.
    #[arg(long, group = "subkey_validity", requires = "subkey_selector")]
    subkey_no_expiration: bool,
}

// ---------------------------------------------------------------------------
// cert-revoke / subkey-revoke
// ---------------------------------------------------------------------------

/// Reasons a key may be revoked, mapping 1:1 to OpenPGP RFC 9580 §5.2.3.31.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum RevocationReason {
    /// 0x00 — generic revocation, no detail given.
    Unspecified,
    /// 0x01 — the key is being replaced by a new one.
    Superseded,
    /// 0x02 — the secret material is believed to be compromised.
    Compromised,
    /// 0x03 — the key is no longer used (and not replaced).
    Retired,
}

impl From<RevocationReason> for sequoia_openpgp::types::ReasonForRevocation {
    fn from(r: RevocationReason) -> Self {
        use sequoia_openpgp::types::ReasonForRevocation as R;
        match r {
            RevocationReason::Unspecified => R::Unspecified,
            RevocationReason::Superseded => R::KeySuperseded,
            RevocationReason::Compromised => R::KeyCompromised,
            RevocationReason::Retired => R::KeyRetired,
        }
    }
}

#[derive(clap::Args)]
struct CertRevokeArgs {
    #[command(flatten)]
    key: KeySelectionArgs,

    #[command(flatten)]
    auth: AuthArgs,

    /// Primary key creation time used to derive the OpenPGP fingerprint.
    /// Must match the value used during cert-export so the revocation
    /// targets the right key.  Defaults to Unix epoch.
    #[arg(long, value_name = "TIMESTAMP")]
    creation_time: Option<String>,

    /// Revocation reason code.
    #[arg(long, value_enum, value_name = "REASON")]
    reason: RevocationReason,

    /// Free-form human-readable message embedded in the revocation.
    #[arg(long, value_name = "TEXT", default_value = "")]
    message: String,

    /// Time the revocation takes effect (RFC 3339).  Defaults to now.
    #[arg(long, value_name = "TIMESTAMP")]
    revocation_time: Option<String>,

    /// Write revocation to this path (default: stdout).
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output a binary OpenPGP signature packet instead of ASCII-armored.
    #[arg(long)]
    binary: bool,

    /// Overwrite the output file if it already exists.  Without this flag,
    /// sq-pkcs11 refuses to overwrite an existing file — protects against
    /// accidentally clobbering a previously-issued revocation.
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args)]
struct SubkeyRevokeArgs {
    #[command(flatten)]
    key: KeySelectionArgs,

    #[command(flatten)]
    auth: AuthArgs,

    /// Primary key creation time (RFC 3339).
    #[arg(long, value_name = "TIMESTAMP")]
    creation_time: Option<String>,

    /// Path to the published certificate that contains the subkey to be
    /// revoked.  The subkey's public material is read from this cert so
    /// the HSM does not need to hold the subkey's private key — the
    /// signing-subkey's secret can have been deleted, lost, or
    /// compromised.  Only the primary's private key is exercised.
    #[arg(long, value_name = "FILE")]
    input_cert: PathBuf,

    /// Full 40-hex-char OpenPGP fingerprint of the subkey within
    /// --input-cert to revoke.  Whitespace and an optional `0x` prefix
    /// are ignored.  Short 16-hex key IDs are NOT accepted because they
    /// are not collision-resistant — for revocation the unambiguous
    /// fingerprint is required.  Look it up with
    /// `sq inspect <input-cert>` or
    /// `gpg --list-keys --with-subkey-fingerprint`.
    #[arg(long, value_name = "FINGERPRINT")]
    subkey_fingerprint: String,

    /// Revocation reason code.
    #[arg(long, value_enum, value_name = "REASON")]
    reason: RevocationReason,

    /// Free-form human-readable message embedded in the revocation.
    #[arg(long, value_name = "TEXT", default_value = "")]
    message: String,

    /// Time the revocation takes effect (RFC 3339).  Defaults to now.
    #[arg(long, value_name = "TIMESTAMP")]
    revocation_time: Option<String>,

    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    #[arg(long)]
    binary: bool,

    /// Overwrite the output file if it already exists.  Without this flag,
    /// sq-pkcs11 refuses to overwrite an existing file — protects against
    /// accidentally clobbering a previously-issued revocation.
    #[arg(long)]
    force: bool,
}

// ---------------------------------------------------------------------------
// list-keys
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
struct ListKeysArgs {
    /// Show keys on all slots, not just initialised ones.
    #[arg(long)]
    all_slots: bool,

    /// File containing a PIN to attempt login with (softcard /
    /// single-card OCS).  Same format and rationale as the sign /
    /// cert-export `--pin-file`.  `SQ_PKCS11_PIN` env var is read when
    /// this flag is absent.
    #[arg(long, value_name = "FILE")]
    pin_file: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let module = resolve_module(cli.module)?;

    let pkcs11 = Pkcs11::new(&module)
        .with_context(|| format!("failed to load PKCS#11 module {}", module.display()))?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

    match cli.command {
        Command::Sign(args) => cmd_sign(&pkcs11, &module, args),
        Command::CertExport(args) => cmd_cert_export(&pkcs11, &module, args),
        Command::CertRevoke(args) => cmd_cert_revoke(&pkcs11, &module, args),
        Command::SubkeyRevoke(args) => cmd_subkey_revoke(&pkcs11, &module, args),
        Command::ListKeys(args) => cmd_list_keys(&pkcs11, args),
    }
}

/// Common interface over args structs that carry a subkey selector +
/// subkey auth pair (cert-export and subkey-revoke).
trait HasSubkeyArgs {
    fn subkey_uri(&self) -> Option<&str>;
    fn subkey_label(&self) -> Option<&str>;
    fn subkey_id(&self) -> Option<&str>;
    fn subkey_auto(&self) -> bool;
    fn subkey_pin_file(&self) -> Option<&std::path::Path>;
    fn subkey_ocs(&self) -> bool;
}

impl HasSubkeyArgs for CertExportArgs {
    fn subkey_uri(&self) -> Option<&str> {
        self.subkey_uri.as_deref()
    }
    fn subkey_label(&self) -> Option<&str> {
        self.subkey_label.as_deref()
    }
    fn subkey_id(&self) -> Option<&str> {
        self.subkey_id.as_deref()
    }
    fn subkey_auto(&self) -> bool {
        self.subkey_auto
    }
    fn subkey_pin_file(&self) -> Option<&std::path::Path> {
        self.subkey_pin_file.as_deref()
    }
    fn subkey_ocs(&self) -> bool {
        self.subkey_ocs
    }
}

/// Resolve the subkey key selector from CLI args.
///
/// Returns `None` if no subkey selector was provided.
fn resolve_subkey_selector<A: HasSubkeyArgs>(args: &A) -> anyhow::Result<Option<KeySelector>> {
    if let Some(uri) = args.subkey_uri() {
        return Ok(Some(KeySelector::Uri(uri.parse()?)));
    }
    if let Some(label) = args.subkey_label() {
        return Ok(Some(KeySelector::Label(label.to_owned())));
    }
    if let Some(id_hex) = args.subkey_id() {
        let bytes =
            hex::decode(id_hex).with_context(|| format!("invalid hex in --subkey-id: {id_hex}"))?;
        return Ok(Some(KeySelector::Id(bytes)));
    }
    if args.subkey_auto() {
        return Ok(Some(KeySelector::Auto));
    }
    Ok(None)
}

/// Build a `LoginMode` for the subkey from --subkey-pin / --subkey-ocs.
fn build_subkey_login<'a, A: HasSubkeyArgs>(
    args: &'a A,
    module: &'a std::path::Path,
) -> anyhow::Result<LoginMode<'a>> {
    if args.subkey_ocs() {
        return Ok(LoginMode::OcsQuorum {
            module_path: module,
        });
    }
    if let Some(path) = args.subkey_pin_file() {
        return Ok(LoginMode::Pin(read_pin_file(path)?));
    }
    if let Ok(pin) = std::env::var("SQ_PKCS11_SUBKEY_PIN") {
        return Ok(LoginMode::Pin(pin));
    }
    Ok(LoginMode::None)
}

/// Parse a validity-period string into a `Duration`.
///
/// Accepts:
/// - `Ny` for years (1y = 365.25 days, calendar-approximate)
/// - Anything else is delegated to `humantime` (`Nd`, `Nw`, `Nh`, `5d 12h`, ...)
fn parse_validity(s: &str) -> anyhow::Result<std::time::Duration> {
    let s = s.trim();
    if let Some(num_str) = s.strip_suffix('y') {
        let n: f64 = num_str
            .trim()
            .parse()
            .with_context(|| format!("invalid years value in --validity-period {s:?}"))?;
        if !n.is_finite() || n < 0.0 {
            anyhow::bail!("--validity-period must be non-negative");
        }
        return Ok(std::time::Duration::from_secs(
            (n * 365.25 * 86400.0) as u64,
        ));
    }
    humantime::parse_duration(s).with_context(|| {
        format!("invalid --validity-period {s:?}; use Ny, Nw, Nd, or Nh (e.g. 5y, 60d)")
    })
}

/// Parse an optional RFC 3339 timestamp, defaulting to Unix epoch.
///
/// Unix epoch as default means the fingerprint is stable across runs without
/// requiring the user to remember and pass a specific timestamp.
fn parse_creation_time(s: Option<&str>) -> anyhow::Result<std::time::SystemTime> {
    match s {
        None => Ok(std::time::SystemTime::UNIX_EPOCH),
        Some(ts) => humantime::parse_rfc3339(ts).with_context(|| {
            format!("invalid --creation-time {ts:?}; use RFC 3339, e.g. 2026-04-30T16:29:30Z")
        }),
    }
}

/// Refuse to clobber an existing output file *before* any HSM round
/// trip.  Used by every command that writes file output: an accidental
/// rerun of e.g. `sign` against the same `--output` previously failed
/// only after we'd already asked the HSM to sign — wasted work, and an
/// extraneous key-usage audit-log entry for an attempt that never
/// produced an artefact.  Calling this preflight at the top of each
/// command catches the common case before opening any session.
///
/// `write_or_refuse` still does its own atomic create_new check at write
/// time to close the TOCTOU window.  This helper is the fast path.
fn preflight_overwrite(output: Option<&std::path::Path>, force: bool) -> anyhow::Result<()> {
    if force {
        return Ok(());
    }
    let path = match output {
        Some(p) => p,
        None => return Ok(()),
    };
    // `--output -` means stdout; never a file.
    if path == std::path::Path::new("-") {
        return Ok(());
    }
    // try_exists() distinguishes "exists" from "permission-denied while
    // checking"; the latter we surface as an error rather than a refusal.
    match path.try_exists() {
        Ok(true) => anyhow::bail!(
            "refusing to overwrite existing file {}; pass --force to overwrite",
            path.display()
        ),
        Ok(false) => Ok(()),
        Err(e) => Err(anyhow::Error::from(e).context(format!(
            "checking whether {} already exists",
            path.display()
        ))),
    }
}

/// Write `bytes` to `path`, refusing to overwrite an existing file unless
/// `force` is set.  Used by every command that writes a non-stdout output —
/// signatures, certs, revocation files — so a stale `release.asc` cannot be
/// silently replaced by an accidental rerun.
fn write_or_refuse(path: &std::path::Path, bytes: &[u8], force: bool) -> anyhow::Result<()> {
    use std::io::Write as _;
    let result = if force {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
    };
    let mut file = result.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "refusing to overwrite existing file {}; pass --force to overwrite",
                path.display()
            )
        } else {
            anyhow::Error::from(e).context(format!("opening {} for writing", path.display()))
        }
    })?;
    file.write_all(bytes)
        .with_context(|| format!("writing to {}", path.display()))?;
    Ok(())
}

fn resolve_module(from_cli: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = from_cli {
        return Ok(p);
    }
    // PKCS11_MODULE_PATH already handled by clap env; reaching here means it
    // was unset. Check the tool-specific fallback variable.
    if let Ok(val) = std::env::var("SQ_PKCS11_MODULE") {
        return Ok(PathBuf::from(val));
    }
    anyhow::bail!(
        "PKCS#11 module not specified.\n\
         Use -m/--module <path>, or set PKCS11_MODULE_PATH or SQ_PKCS11_MODULE.\n\
         Example: -m /opt/nfast/toolkits/pkcs11/libcknfast.so"
    )
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

fn cmd_sign(pkcs11: &Pkcs11, module: &std::path::Path, args: SignArgs) -> anyhow::Result<()> {
    let selector = args.key.resolve()?;
    let login = args.auth.login_mode(module)?;
    let creation_time = parse_creation_time(args.creation_time.as_deref())?;

    // Resolve the output path first, then preflight the overwrite check
    // BEFORE opening the HSM session.  Without this, an accidental
    // rerun against the same `--output` would consume an HSM signing
    // operation (and the corresponding key-usage audit-log entry)
    // before failing on the existing file.
    let output_target = match args.output.as_deref() {
        Some(p) if p == std::path::Path::new("-") => SignOutput::Stdout,
        Some(p) => SignOutput::File(p.to_path_buf()),
        None => {
            let mut p = args.file.clone();
            let new_ext = match p.extension().and_then(|e| e.to_str()) {
                Some(ext) => format!("{ext}.asc"),
                None => "asc".into(),
            };
            p.set_extension(new_ext);
            SignOutput::File(p)
        }
    };
    if let SignOutput::File(path) = &output_target {
        preflight_overwrite(Some(path), args.force)?;
    }

    let (session, _slot) = session::open_session(pkcs11, &selector, &login)?;
    let priv_handle = session::resolve_single_key(&session, &selector)?;
    let mut signer = Pkcs11Signer::new(session, priv_handle)?;
    signer.set_creation_time(creation_time)?;

    // Pick the hash algorithm to match the signing key strength — same
    // policy used for cert self-signatures (cert::preferred_hash_for).
    let hash_algo = cert::preferred_hash_for(signer.public_key());

    let data =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;

    let mut sig_buf = Vec::new();
    {
        let sink = Message::new(&mut sig_buf);
        // Armorer defaults to Kind::Message which would emit
        // `-----BEGIN PGP MESSAGE-----`.  A detached signature must be
        // wrapped in Kind::Signature so verifiers (and `sq inspect`) see
        // `-----BEGIN PGP SIGNATURE-----` and treat the bytes as a
        // standalone signature rather than an OpenPGP message.
        let sink = if args.binary {
            sink
        } else {
            Armorer::new(sink).kind(armor::Kind::Signature).build()?
        };
        let template = SignatureBuilder::new(SignatureType::Binary).set_hash_algo(hash_algo);
        let mut signing_stream = Signer::with_template(sink, signer, template)?
            .detached()
            .build()?;
        signing_stream.write_all(&data)?;
        signing_stream.finalize()?;
    }

    match output_target {
        SignOutput::Stdout => {
            std::io::stdout()
                .write_all(&sig_buf)
                .context("writing signature to stdout")?;
        }
        SignOutput::File(sig_path) => {
            write_or_refuse(&sig_path, &sig_buf, args.force)?;
            eprintln!("Signature written to {}", sig_path.display());
        }
    }
    Ok(())
}

enum SignOutput {
    Stdout,
    File(PathBuf),
}

// ---------------------------------------------------------------------------
// cert-export
// ---------------------------------------------------------------------------

fn cmd_cert_export(
    pkcs11: &Pkcs11,
    module: &std::path::Path,
    args: CertExportArgs,
) -> anyhow::Result<()> {
    // Preflight overwrite before any HSM round trip.  cert-export
    // produces multiple signatures (direct-key, every UID binding, and
    // the subkey binding + cross-sig if a subkey is requested) — wasting
    // all of those against an existing file is especially expensive.
    preflight_overwrite(args.output.as_deref(), args.force)?;

    // ── Primary tier ─────────────────────────────────────────────────
    let primary_selector = args.key.resolve()?;
    let primary_login = args.auth.login_mode(module)?;
    let primary_creation_time = parse_creation_time(args.creation_time.as_deref())?;
    let primary_validity = if args.no_expiration {
        None
    } else {
        Some(parse_validity(&args.validity_period)?)
    };

    let (primary_session, _) = session::open_session(pkcs11, &primary_selector, &primary_login)?;
    let primary_handle = session::resolve_single_key(&primary_session, &primary_selector)?;
    let mut primary_signer = Pkcs11Signer::new(primary_session, primary_handle)?;

    // ── Optional subkey tier ─────────────────────────────────────────
    let subkey_selector = resolve_subkey_selector(&args)?;
    let mut subkey_signer_holder: Option<Pkcs11Signer> = None;
    let subkey_creation_time;
    let subkey_validity;

    if let Some(sel) = &subkey_selector {
        let subkey_login = build_subkey_login(&args, module)?;
        subkey_creation_time = parse_creation_time(args.subkey_creation_time.as_deref())?;
        subkey_validity = if args.subkey_no_expiration {
            None
        } else {
            Some(parse_validity(&args.subkey_validity_period)?)
        };
        let (sk_session, _) = session::open_session(pkcs11, sel, &subkey_login)?;
        let sk_handle = session::resolve_single_key(&sk_session, sel)?;
        subkey_signer_holder = Some(Pkcs11Signer::new(sk_session, sk_handle)?);
    } else {
        // Unused but the compiler requires they be initialised on all paths.
        subkey_creation_time = std::time::SystemTime::UNIX_EPOCH;
        subkey_validity = None;
    }

    // ── Assemble the cert spec and build ─────────────────────────────
    let primary_spec = cert::KeySpec {
        signer: &mut primary_signer,
        creation_time: primary_creation_time,
        validity_period: primary_validity,
    };
    let subkey_spec = subkey_signer_holder.as_mut().map(|signer| cert::KeySpec {
        signer,
        creation_time: subkey_creation_time,
        validity_period: subkey_validity,
    });

    // ── Optionally read the existing cert for merge mode ────────────────
    let merge_into = match &args.merge_cert {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading existing cert {}", path.display()))?;
            Some(cert::parse_cert(&bytes)?)
        }
        None => None,
    };

    let spec = cert::CertSpec {
        primary: primary_spec,
        subkey: subkey_spec,
        user_ids: &args.user_ids,
        merge_into: merge_into.as_ref(),
    };

    let cert = cert::build_cert(spec)?;

    if args.binary {
        let bytes = cert::export_binary_cert(&cert)?;
        match args.output {
            Some(path) => {
                write_or_refuse(&path, &bytes, args.force)?;
                eprintln!("Certificate written to {}", path.display());
            }
            None => std::io::stdout().write_all(&bytes)?,
        }
    } else {
        let armored = cert::export_armored_cert(&cert)?;
        match args.output {
            Some(path) => {
                write_or_refuse(&path, armored.as_bytes(), args.force)?;
                eprintln!("Certificate written to {}", path.display());
            }
            None => print!("{armored}"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cert-revoke
// ---------------------------------------------------------------------------

fn cmd_cert_revoke(
    pkcs11: &Pkcs11,
    module: &std::path::Path,
    args: CertRevokeArgs,
) -> anyhow::Result<()> {
    // Preflight overwrite before opening any HSM session.
    preflight_overwrite(args.output.as_deref(), args.force)?;

    let selector = args.key.resolve()?;
    let login = args.auth.login_mode(module)?;
    let creation_time = parse_creation_time(args.creation_time.as_deref())?;
    let revocation_time = match args.revocation_time.as_deref() {
        Some(s) => parse_creation_time(Some(s))?,
        None => std::time::SystemTime::now(),
    };

    let (session, _) = session::open_session(pkcs11, &selector, &login)?;
    let handle = session::resolve_single_key(&session, &selector)?;
    let mut signer = Pkcs11Signer::new(session, handle)?;

    let spec = cert::CertRevocationSpec {
        primary: cert::KeySpec {
            signer: &mut signer,
            creation_time,
            validity_period: None,
        },
        reason: args.reason.into(),
        message: args.message.as_bytes(),
        revocation_time,
    };

    let sig = cert::build_cert_revocation(spec)?;
    write_revocation_output(&sig, args.binary, args.output.as_deref(), args.force)
}

// ---------------------------------------------------------------------------
// subkey-revoke
// ---------------------------------------------------------------------------

fn cmd_subkey_revoke(
    pkcs11: &Pkcs11,
    module: &std::path::Path,
    args: SubkeyRevokeArgs,
) -> anyhow::Result<()> {
    let primary_selector = args.key.resolve()?;
    let primary_login = args.auth.login_mode(module)?;
    let primary_creation_time = parse_creation_time(args.creation_time.as_deref())?;
    let revocation_time = match args.revocation_time.as_deref() {
        Some(s) => parse_creation_time(Some(s))?,
        None => std::time::SystemTime::now(),
    };

    // Preflight: refuse to overwrite output BEFORE any HSM round trip
    // so an accidental rerun does not consume an HSM signing operation
    // (and the corresponding key-usage audit-log entry).
    preflight_overwrite(args.output.as_deref(), args.force)?;

    // Parse the cert, parse the fingerprint, locate the subkey.  No HSM
    // access yet — these are all local checks.
    let target_fpr = parse_full_fingerprint(&args.subkey_fingerprint)?;
    let cert_bytes = std::fs::read(&args.input_cert)
        .with_context(|| format!("reading --input-cert {}", args.input_cert.display()))?;
    let cert = cert::parse_cert(&cert_bytes)?;
    let subkey_public = locate_subkey_in_cert(&cert, &target_fpr)?;

    let (primary_session, _) = session::open_session(pkcs11, &primary_selector, &primary_login)?;
    let primary_handle = session::resolve_single_key(&primary_session, &primary_selector)?;
    let mut primary_signer = Pkcs11Signer::new(primary_session, primary_handle)?;
    primary_signer.set_creation_time(primary_creation_time)?;

    // Verify the HSM-derived primary fingerprint matches the cert's
    // primary fingerprint.  Without this check, an operator who picks
    // the wrong --key-label (or the right label with the wrong
    // --creation-time) could produce a revocation signed by primary A
    // for a subkey of cert B — a footgun that wastes an HSM signing
    // operation and may not even fail loudly downstream.
    let hsm_primary = sequoia_openpgp::packet::Key::V4(sequoia_openpgp::packet::key::Key4::<
        sequoia_openpgp::packet::key::PublicParts,
        sequoia_openpgp::packet::key::PrimaryRole,
    >::new(
        primary_creation_time,
        primary_signer.public_key().pk_algo(),
        primary_signer.public_key().mpis().clone(),
    )?);
    let hsm_fpr = hsm_primary.fingerprint();
    let cert_fpr = cert.primary_key().key().fingerprint();
    if hsm_fpr != cert_fpr {
        anyhow::bail!(
            "primary fingerprint mismatch: --input-cert primary is {cert_fpr}, \
             selected HSM primary is {hsm_fpr} \
             (check --key-label/--creation-time match the input cert)"
        );
    }

    let spec = cert::SubkeyRevocationSpec {
        primary: cert::KeySpec {
            signer: &mut primary_signer,
            creation_time: primary_creation_time,
            validity_period: None,
        },
        subkey_public,
        reason: args.reason.into(),
        message: args.message.as_bytes(),
        revocation_time,
    };

    let sig = cert::build_subkey_revocation(spec)?;
    write_revocation_output(&sig, args.binary, args.output.as_deref(), args.force)
}

/// Parse a 40-hex-char OpenPGP fingerprint, with whitespace and an
/// optional `0x` prefix stripped (handles strings copy-pasted from
/// `gpg --fingerprint` output).
///
/// Short 16-hex key IDs are intentionally NOT accepted: revocation is
/// rare and high-stakes, and a hostile or malformed cert can carry a
/// secondary subkey whose key ID aliases another, silently shifting
/// the revocation to the wrong subkey.  Requiring the full fingerprint
/// removes that ambiguity at the cost of a longer paste.
fn parse_full_fingerprint(needle: &str) -> anyhow::Result<sequoia_openpgp::Fingerprint> {
    let cleaned: String = needle
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_string();
    if cleaned.len() != 40 {
        anyhow::bail!(
            "{needle:?} is not a full OpenPGP fingerprint (got {} hex chars after \
             stripping whitespace and 0x prefix; need exactly 40); short 16-char \
             key IDs are not accepted because they are not collision-resistant",
            cleaned.len()
        );
    }
    sequoia_openpgp::Fingerprint::from_hex(&cleaned)
        .with_context(|| format!("parsing {needle:?} as a 40-hex-char fingerprint"))
}

/// Locate a subkey within an already-parsed cert by full fingerprint.
fn locate_subkey_in_cert(
    cert: &sequoia_openpgp::Cert,
    fingerprint: &sequoia_openpgp::Fingerprint,
) -> anyhow::Result<
    sequoia_openpgp::packet::Key<
        sequoia_openpgp::packet::key::PublicParts,
        sequoia_openpgp::packet::key::SubordinateRole,
    >,
> {
    for sub in cert.keys().subkeys() {
        let key = sub.key();
        if &key.fingerprint() == fingerprint {
            return Ok(key.clone().role_into_subordinate());
        }
    }
    anyhow::bail!("no subkey in the input cert matches fingerprint {fingerprint}")
}

/// Shared output handler for cert-revoke and subkey-revoke.
fn write_revocation_output(
    sig: &sequoia_openpgp::packet::Signature,
    binary: bool,
    output: Option<&std::path::Path>,
    force: bool,
) -> anyhow::Result<()> {
    if binary {
        let bytes = cert::export_binary_signature(sig)?;
        match output {
            Some(path) => {
                write_or_refuse(path, &bytes, force)?;
                eprintln!("Revocation written to {}", path.display());
            }
            None => std::io::stdout().write_all(&bytes)?,
        }
    } else {
        let armored = cert::export_armored_signature(sig)?;
        match output {
            Some(path) => {
                write_or_refuse(path, armored.as_bytes(), force)?;
                eprintln!("Revocation written to {}", path.display());
            }
            None => print!("{armored}"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// list-keys
// ---------------------------------------------------------------------------

fn cmd_list_keys(pkcs11: &Pkcs11, args: ListKeysArgs) -> anyhow::Result<()> {
    use cryptoki::object::{Attribute, AttributeType, ObjectClass};
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;

    // Resolve the optional PIN once: --pin-file beats env var.
    let pin: Option<String> = match &args.pin_file {
        Some(path) => Some(read_pin_file(path)?),
        None => std::env::var("SQ_PKCS11_PIN").ok(),
    };

    let slots = if args.all_slots {
        pkcs11.get_all_slots()?
    } else {
        pkcs11.get_slots_with_initialized_token()?
    };

    if slots.is_empty() {
        println!("No slots found.");
        return Ok(());
    }

    for slot in slots {
        let token_info = pkcs11.get_token_info(slot);

        // Skip empty card reader slots when listing — they have no token.
        if token_info.is_err() {
            if args.all_slots {
                println!("Slot {}  [no token present]", slot.id());
            }
            continue;
        }
        let info = token_info.unwrap();
        let token_label = info.label().trim().to_string();
        let protection = if info.login_required() {
            "token-protected (OCS or softcard)"
        } else {
            "module-protected"
        };
        println!("Slot {}  token: {token_label}  [{protection}]", slot.id());

        let session = match pkcs11.open_ro_session(slot) {
            Ok(s) => s,
            Err(e) => {
                println!("  (could not open session: {e})");
                continue;
            }
        };

        if let Some(p) = &pin {
            let _ = session.login(UserType::User, Some(&AuthPin::from(p.clone())));
        }

        let handles = session.find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Sign(true),
        ])?;

        if handles.is_empty() {
            println!("  (no signing keys)");
            continue;
        }

        for handle in handles {
            let label = get_str_attr(&session, handle, AttributeType::Label)
                .unwrap_or_else(|| "<no label>".into());
            // Treat both "no Id attribute" and "Id attribute with zero
            // bytes" as missing — nShield assigns an empty CKA_ID to some
            // EC keys, and a literal `id=` followed by whitespace would
            // confuse downstream parsers (e.g. the integration tests that
            // grep this output for the hex id of a label).
            let id = session
                .get_attributes(handle, &[AttributeType::Id])
                .ok()
                .and_then(|attrs| {
                    attrs.into_iter().find_map(|a| match a {
                        Attribute::Id(v) if !v.is_empty() => Some(hex::encode(v)),
                        _ => None,
                    })
                })
                .unwrap_or_else(|| "<no id>".into());
            let key_type = session
                .get_attributes(handle, &[AttributeType::KeyType])
                .ok()
                .and_then(|attrs| {
                    attrs.into_iter().find_map(|a| match a {
                        Attribute::KeyType(kt) => Some(key_type_name(kt)),
                        _ => None,
                    })
                })
                .unwrap_or_else(|| "?".into());

            println!("  label={label:?}  id={id}  type={key_type}");
        }
    }
    Ok(())
}

fn key_type_name(kt: cryptoki::object::KeyType) -> String {
    use cryptoki::object::KeyType as KT;
    match kt {
        KT::RSA => "RSA".into(),
        KT::EC => "EC (ECDSA/ECDH)".into(),
        KT::EC_EDWARDS => "EC-Edwards (EdDSA)".into(),
        KT::EC_MONTGOMERY => "EC-Montgomery (X25519)".into(),
        KT::DSA => "DSA".into(),
        KT::DH => "DH".into(),
        KT::AES => "AES".into(),
        KT::DES3 => "DES3".into(),
        KT::GENERIC_SECRET => "Generic secret".into(),
        _ => format!("unknown ({kt:?})"),
    }
}

fn get_str_attr(
    session: &cryptoki::session::Session,
    handle: cryptoki::object::ObjectHandle,
    attr_type: cryptoki::object::AttributeType,
) -> Option<String> {
    use cryptoki::object::Attribute;
    session
        .get_attributes(handle, &[attr_type])
        .ok()?
        .into_iter()
        .find_map(|a| match a {
            // CKA_LABEL is a raw byte array; nShield always writes UTF-8 labels.
            Attribute::Label(bytes) => String::from_utf8(bytes).ok(),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_time_default_is_epoch() {
        assert_eq!(
            parse_creation_time(None).unwrap(),
            std::time::SystemTime::UNIX_EPOCH
        );
    }

    #[test]
    fn creation_time_rfc3339_round_trip() {
        let t = parse_creation_time(Some("2026-04-30T16:29:30Z")).unwrap();
        let expected = humantime::parse_rfc3339("2026-04-30T16:29:30Z").unwrap();
        assert_eq!(t, expected);
    }

    #[test]
    fn creation_time_garbage_rejected() {
        assert!(parse_creation_time(Some("not a date")).is_err());
        assert!(parse_creation_time(Some("")).is_err());
    }

    #[test]
    fn creation_time_requires_timezone() {
        // RFC 3339 requires an explicit timezone.  A bare datetime without 'Z'
        // or an offset is ambiguous and must be rejected so users don't
        // accidentally embed a localtime-interpreted timestamp in a published
        // certificate.
        assert!(parse_creation_time(Some("2026-04-30T16:29:30")).is_err());
    }

    #[test]
    fn validity_years_uses_calendar_approximation() {
        // 1y = 365.25 * 86400 = 31,557,600 s
        let d = parse_validity("1y").unwrap();
        assert_eq!(d.as_secs(), 31_557_600);
        // 5y = 5 * 31,557,600
        assert_eq!(parse_validity("5y").unwrap().as_secs(), 157_788_000);
    }

    #[test]
    fn validity_humantime_units() {
        // Days, weeks, hours go through humantime.
        assert_eq!(parse_validity("30d").unwrap().as_secs(), 30 * 86_400);
        assert_eq!(parse_validity("1w").unwrap().as_secs(), 7 * 86_400);
        assert_eq!(parse_validity("48h").unwrap().as_secs(), 48 * 3_600);
    }

    #[test]
    fn validity_default_is_5_years() {
        // The clap default value used in the CLI must parse cleanly.
        assert_eq!(parse_validity("5y").unwrap().as_secs(), 157_788_000);
    }

    #[test]
    fn validity_rejects_garbage() {
        assert!(parse_validity("forever").is_err());
        assert!(parse_validity("").is_err());
        assert!(parse_validity("xy").is_err());
    }

    #[test]
    fn validity_rejects_negative() {
        assert!(parse_validity("-3y").is_err());
    }
}
