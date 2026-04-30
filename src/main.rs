mod cert;
mod error;
mod nfast;
mod session;
mod signer;

use std::io::Write as IoWrite;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use sequoia_openpgp::{
    packet::signature::SignatureBuilder,
    serialize::stream::*,
    types::SignatureType,
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
    #[arg(
        short = 'm',
        long,
        env = "PKCS11_MODULE_PATH",
        value_name = "PATH"
    )]
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
    /// PIN / passphrase for softcard- or single-card OCS-protected keys.
    /// Omit entirely for module-protected keys.
    /// Prefer the SQ_PKCS11_PIN env var to avoid the value in process listings.
    #[arg(long, env = "SQ_PKCS11_PIN", group = "auth")]
    pin: Option<String>,

    /// Interactive OCS quorum login (K > 1 card sets).
    /// The tool will prompt for each card's passphrase in turn using the
    /// nShield C_LoginBegin / C_LoginNext / C_LoginEnd extension API.
    #[arg(long, group = "auth")]
    ocs: bool,
}

impl AuthArgs {
    fn login_mode<'a>(&'a self, module: &'a std::path::Path) -> LoginMode<'a> {
        if self.ocs {
            return LoginMode::OcsQuorum { module_path: module };
        }
        match self.pin.as_deref() {
            Some(pin) => LoginMode::Pin(pin),
            None => LoginMode::None,
        }
    }
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

    /// Write signature to this path (default: <input>.asc).
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// Produce binary signature instead of ASCII-armored.
    #[arg(long)]
    no_armor: bool,

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
    /// Repeat to add multiple User IDs.
    #[arg(long = "uid", value_name = "UID", required = true)]
    user_ids: Vec<String>,

    /// Write certificate to this path (default: stdout).
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// Key creation time to embed in the certificate (RFC 3339,
    /// e.g. 2026-04-30T16:29:30Z).
    ///
    /// The OpenPGP fingerprint is derived from key material + creation time,
    /// so this value must be used consistently in every subsequent `sign`
    /// invocation.  Defaults to Unix epoch when omitted, which is a stable
    /// value that requires no coordination between cert-export and sign.
    #[arg(long, value_name = "TIMESTAMP")]
    creation_time: Option<String>,
}

// ---------------------------------------------------------------------------
// list-keys
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
struct ListKeysArgs {
    /// Show keys on all slots, not just initialised ones.
    #[arg(long)]
    all_slots: bool,

    /// PIN to attempt login with (softcard / single-card OCS).
    #[arg(long, env = "SQ_PKCS11_PIN")]
    pin: Option<String>,
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
        Command::ListKeys(args) => cmd_list_keys(&pkcs11, args),
    }
}

/// Parse an optional RFC 3339 timestamp, defaulting to Unix epoch.
///
/// Unix epoch as default means the fingerprint is stable across runs without
/// requiring the user to remember and pass a specific timestamp.
fn parse_creation_time(s: Option<&str>) -> anyhow::Result<std::time::SystemTime> {
    match s {
        None => Ok(std::time::SystemTime::UNIX_EPOCH),
        Some(ts) => humantime::parse_rfc3339(ts)
            .with_context(|| format!("invalid --creation-time {ts:?}; use RFC 3339, e.g. 2026-04-30T16:29:30Z")),
    }
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
    let login = args.auth.login_mode(module);
    let creation_time = parse_creation_time(args.creation_time.as_deref())?;

    let (session, _slot) = session::open_session(pkcs11, &selector, &login)?;
    let priv_handle = session::resolve_single_key(&session, &selector)?;
    let mut signer = Pkcs11Signer::new(session, priv_handle)?;
    signer.set_creation_time(creation_time)?;

    let data = std::fs::read(&args.file)
        .with_context(|| format!("reading {}", args.file.display()))?;

    let sig_path = args.output.unwrap_or_else(|| {
        let mut p = args.file.clone();
        let new_ext = match p.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!("{ext}.asc"),
            None => "asc".into(),
        };
        p.set_extension(new_ext);
        p
    });

    let mut sig_buf = Vec::new();
    {
        let sink = Message::new(&mut sig_buf);
        let sink = if args.no_armor {
            sink
        } else {
            Armorer::new(sink).build()?
        };
        let mut signing_stream = Signer::with_template(
            sink,
            signer,
            SignatureBuilder::new(SignatureType::Binary),
        )?
        .detached()
        .build()?;
        signing_stream.write_all(&data)?;
        signing_stream.finalize()?;
    }

    std::fs::write(&sig_path, &sig_buf)
        .with_context(|| format!("writing signature to {}", sig_path.display()))?;
    eprintln!("Signature written to {}", sig_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// cert-export
// ---------------------------------------------------------------------------

fn cmd_cert_export(
    pkcs11: &Pkcs11,
    module: &std::path::Path,
    args: CertExportArgs,
) -> anyhow::Result<()> {
    let selector = args.key.resolve()?;
    let login = args.auth.login_mode(module);

    let creation_time = parse_creation_time(args.creation_time.as_deref())?;

    let (session, _slot) = session::open_session(pkcs11, &selector, &login)?;
    let priv_handle = session::resolve_single_key(&session, &selector)?;
    let mut signer = Pkcs11Signer::new(session, priv_handle)?;

    let cert = cert::build_cert(&mut signer, &args.user_ids, Some(creation_time))?;
    let armored = cert::export_armored_cert(&cert)?;

    match args.output {
        Some(path) => {
            std::fs::write(&path, &armored)
                .with_context(|| format!("writing cert to {}", path.display()))?;
            eprintln!("Certificate written to {}", path.display());
        }
        None => print!("{armored}"),
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

        if let Some(pin) = &args.pin {
            let _ = session.login(UserType::User, Some(&AuthPin::from(pin.as_str())));
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
            let id = session
                .get_attributes(handle, &[AttributeType::Id])
                .ok()
                .and_then(|attrs| {
                    attrs.into_iter().find_map(|a| match a {
                        Attribute::Id(v) => Some(hex::encode(v)),
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
