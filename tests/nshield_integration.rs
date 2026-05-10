//! Integration tests for Entrust nShield (Security World, FIPS 140-3 mode).
//!
//! NSHIELD-SPECIFIC: these tests assume the nShield client tooling
//! (`generatekey`, `nfkminfo`, `gpg`) is available, that `PKCS11_MODULE_PATH`
//! points at `libcknfast.so`, and that the test keys exist (see
//! `tests/nshield/README.md` for provisioning).
//!
//! Each test early-returns with a `skipping:` line on stderr when
//! `tests/nshield/test.env` is absent / incomplete, or when the configured
//! `PKCS11_MODULE_PATH` does not point at an existing file (vendor client
//! not installed).  Rust's libtest has no native "skipped" status, so the
//! tests still report as "ok" — the stderr message is the only signal.
//!
//! In CI, the workflow runs `cargo test --bins` which excludes this file
//! entirely, so the misleading "ok" is only ever seen when a developer
//! runs `cargo test` locally without an HSM environment.

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::OnceLock;

use assert_cmd::Command;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test environment loading.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TestEnv {
    module_path: String,
    rsa_label: String,
    ec_label: String,
    primary_label: String,
    subkey_label: String,
    subkey2_label: String,
}

/// Load `tests/nshield/test.env`, read the labels we need, and verify each
/// label actually corresponds to a key present in the Security World.
/// Returns `Err(reason)` for any of:
///   - `tests/nshield/test.env` absent / incomplete (CI, dev machines)
///   - `PKCS11_MODULE_PATH` does not exist (nShield client not installed)
///   - `sq-pkcs11 list-keys` fails (HSM unreachable)
///   - any configured CKA_LABEL is not present in the token
///
/// The result is cached for the lifetime of the test process so the
/// list-keys probe only runs once even with `cargo test`'s parallel test
/// execution.  Rust's libtest has no native "skipped" status, so the
/// calling test prints `reason` on stderr and early-returns; the line
/// shows up in test logs even though the test still reports as "ok".
fn test_env() -> Result<TestEnv, String> {
    static CACHE: OnceLock<Result<TestEnv, String>> = OnceLock::new();
    CACHE.get_or_init(compute_test_env).clone()
}

fn compute_test_env() -> Result<TestEnv, String> {
    let env_file: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "nshield", "test.env"]
        .iter()
        .collect();
    let _ = dotenvy::from_path(&env_file);

    let module_path = std::env::var("PKCS11_MODULE_PATH").map_err(|_| {
        "PKCS11_MODULE_PATH not set (tests/nshield/test.env missing or incomplete?)".to_string()
    })?;
    if !Path::new(&module_path).exists() {
        return Err(
            "PKCS#11 module file from PKCS11_MODULE_PATH does not exist (nShield client not installed?)"
                .to_string(),
        );
    }

    let var = |name: &str| {
        std::env::var(name).map_err(|_| format!("{name} not set in tests/nshield/test.env"))
    };
    let env = TestEnv {
        module_path: module_path.clone(),
        rsa_label: var("SQ_PKCS11_NSHIELD_TEST_RSA")?,
        ec_label: var("SQ_PKCS11_NSHIELD_TEST_EC")?,
        primary_label: var("SQ_PKCS11_NSHIELD_TEST_PRIMARY")?,
        subkey_label: var("SQ_PKCS11_NSHIELD_TEST_SUBKEY")?,
        subkey2_label: var("SQ_PKCS11_NSHIELD_TEST_SUBKEY2")?,
    };

    // Confirm each configured label actually exists in the Security World.
    // Without this, a stale or placeholder test.env happily passes the
    // env-var check above, every test then runs and either fails noisily
    // ("key not found") or — worse — short-circuits in a way that makes
    // it look like the suite ran.  Catch it once here.
    let listing = std::process::Command::new(assert_cmd::cargo::cargo_bin("sq-pkcs11"))
        .arg("list-keys")
        .env("PKCS11_MODULE_PATH", &env.module_path)
        .env_remove("SQ_PKCS11_PIN")
        .env_remove("SQ_PKCS11_SUBKEY_PIN")
        .output()
        .map_err(|e| format!("could not run sq-pkcs11 list-keys: {e}"))?;
    if !listing.status.success() {
        return Err(format!(
            "sq-pkcs11 list-keys failed (HSM unreachable?):\nstderr: {}",
            String::from_utf8_lossy(&listing.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&listing.stdout);
    for (var_name, label) in [
        ("SQ_PKCS11_NSHIELD_TEST_RSA", &env.rsa_label),
        ("SQ_PKCS11_NSHIELD_TEST_EC", &env.ec_label),
        ("SQ_PKCS11_NSHIELD_TEST_PRIMARY", &env.primary_label),
        ("SQ_PKCS11_NSHIELD_TEST_SUBKEY", &env.subkey_label),
        ("SQ_PKCS11_NSHIELD_TEST_SUBKEY2", &env.subkey2_label),
    ] {
        // sq-pkcs11 list-keys prints `  label="<value>"  id=<hex>  type=<...>`
        // — match the quoted form so a label that is a substring of another
        // label can't pass.
        let needle = format!("label={label:?}");
        if !stdout.contains(&needle) {
            return Err(format!(
                "{var_name}={label} is not present in the Security World; \
                 check tests/nshield/test.env and run sq-pkcs11 list-keys to verify"
            ));
        }
    }

    Ok(env)
}

/// Macro to bail out cleanly when the test environment isn't available.
macro_rules! require_env {
    () => {
        match test_env() {
            Ok(e) => e,
            Err(why) => {
                eprintln!("skipping: {why}");
                return;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Command helpers.
// ---------------------------------------------------------------------------

/// `sq-pkcs11` binary invocation with `PKCS11_MODULE_PATH` propagated.
fn sq_pkcs11(env: &TestEnv) -> Command {
    let mut c = Command::cargo_bin("sq-pkcs11").unwrap();
    c.env("PKCS11_MODULE_PATH", &env.module_path);
    // We never want our binary to inherit a SQ_PKCS11_PIN from the test
    // shell — every test is supposed to use module-protected keys.
    c.env_remove("SQ_PKCS11_PIN");
    c.env_remove("SQ_PKCS11_SUBKEY_PIN");
    c
}

/// `gpg` invocation pointed at an isolated keyring directory so tests don't
/// touch the operator's real keyring.
fn gpg_in(home: &Path) -> StdCommand {
    let mut c = StdCommand::new("gpg");
    c.env("GNUPGHOME", home);
    // Disable any TTY interaction; keyring import / verify must be unattended.
    c.env("GPG_TTY", "");
    c.arg("--batch").arg("--no-tty");
    c
}

/// Set up a fresh GPG home directory inside `tmp` and return its path.
fn fresh_gpg_home(tmp: &TempDir) -> PathBuf {
    let home = tmp.path().join("gnupg");
    std::fs::create_dir_all(&home).unwrap();
    // GPG insists on tight permissions for GNUPGHOME on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&home, perms).unwrap();
    }
    home
}

/// Stable creation time used across tests so fingerprints are reproducible
/// from one test session to the next.
const STABLE_TIME: &str = "2026-01-01T00:00:00Z";

// ---------------------------------------------------------------------------
// list-keys
// ---------------------------------------------------------------------------

#[test]
fn list_keys_shows_test_keys() {
    let env = require_env!();

    let assert = sq_pkcs11(&env).arg("list-keys").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();

    for label in [
        &env.rsa_label,
        &env.ec_label,
        &env.primary_label,
        &env.subkey_label,
        &env.subkey2_label,
    ] {
        assert!(
            stdout.contains(label.as_str()),
            "expected list-keys output to mention {label:?}, got:\n{stdout}"
        );
    }
}

// ---------------------------------------------------------------------------
// cert-export
// ---------------------------------------------------------------------------

#[test]
fn cert_export_rsa_produces_armored_block() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("rsa.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.rsa_label])
        .args(["--userid", "Test RSA <rsa@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();

    let cert = std::fs::read_to_string(&cert_path).unwrap();
    assert!(cert.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    assert!(cert.contains("-----END PGP PUBLIC KEY BLOCK-----"));
}

#[test]
fn cert_export_ec_produces_armored_block() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("ec.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.ec_label])
        .args(["--userid", "Test EC <ec@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();

    let cert = std::fs::read_to_string(&cert_path).unwrap();
    assert!(cert.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
}

// ---------------------------------------------------------------------------
// Sign + verify round-trip
// ---------------------------------------------------------------------------

fn sign_verify_roundtrip(env: &TestEnv, key_label: &str, userid: &str) {
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.asc");
    let payload = tmp.path().join("payload.txt");
    let signature = tmp.path().join("payload.txt.asc");
    let gpg_home = fresh_gpg_home(&tmp);

    std::fs::write(&payload, b"test payload bytes\n").unwrap();

    // 1. Export the cert.
    sq_pkcs11(env)
        .args(["cert-export"])
        .args(["--key-label", key_label])
        .args(["--userid", userid])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();

    // 2. Import into the isolated GPG keyring.
    let import = gpg_in(&gpg_home)
        .arg("--import")
        .arg(&cert_path)
        .output()
        .expect("gpg --import");
    assert!(
        import.status.success(),
        "gpg --import failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&import.stdout),
        String::from_utf8_lossy(&import.stderr),
    );

    // 3. Produce a detached signature.
    sq_pkcs11(env)
        .args(["sign"])
        .args(["--key-label", key_label])
        .args(["--creation-time", STABLE_TIME])
        .arg(&payload)
        .assert()
        .success();
    assert!(signature.exists(), "sign did not create {signature:?}");

    // 4. Verify.
    let verify = gpg_in(&gpg_home)
        .arg("--verify")
        .arg(&signature)
        .arg(&payload)
        .output()
        .expect("gpg --verify");
    assert!(
        verify.status.success(),
        "gpg --verify failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr),
    );
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(
        stderr.contains("Good signature"),
        "expected 'Good signature' in gpg --verify output, got:\n{stderr}"
    );
}

#[test]
fn rsa_sign_verify_with_gpg() {
    let env = require_env!();
    sign_verify_roundtrip(&env, &env.rsa_label, "Test RSA <rsa@example.com>");
}

#[test]
fn ec_sign_verify_with_gpg() {
    let env = require_env!();
    sign_verify_roundtrip(&env, &env.ec_label, "Test EC <ec@example.com>");
}

// ---------------------------------------------------------------------------
// sq (Sequoia CLI) parity tests.
//
// The gpg-based tests above prove our outputs are accepted by GnuPG.
// The tests below assert the same artefacts verify cleanly through
// Sequoia's own `sq` CLI — different OpenPGP implementation, different
// crypto backend, useful as a sanity check that we don't accidentally
// produce GnuPG-leniency-shaped artefacts.
// ---------------------------------------------------------------------------

/// `sq` invocation pointed at an isolated home directory so tests don't
/// touch the operator's real Sequoia keystore.
fn sq_cli(home: &Path) -> StdCommand {
    let mut c = StdCommand::new("sq");
    c.arg("--home").arg(home).arg("--batch");
    c
}

/// Set up a fresh sq home directory inside `tmp` and return its path.
fn fresh_sq_home(tmp: &TempDir) -> PathBuf {
    let home = tmp.path().join("sq");
    std::fs::create_dir_all(&home).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    home
}

fn sq_sign_verify_roundtrip(env: &TestEnv, key_label: &str, userid: &str) {
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.asc");
    let payload = tmp.path().join("payload.txt");
    let signature = tmp.path().join("payload.txt.asc");
    let sq_home = fresh_sq_home(&tmp);

    std::fs::write(&payload, b"test payload bytes\n").unwrap();

    // 1. Export the cert via sq-pkcs11.
    sq_pkcs11(env)
        .args(["cert-export"])
        .args(["--key-label", key_label])
        .args(["--userid", userid])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();

    // 2. Produce a detached signature via sq-pkcs11.
    sq_pkcs11(env)
        .args(["sign"])
        .args(["--key-label", key_label])
        .args(["--creation-time", STABLE_TIME])
        .arg(&payload)
        .assert()
        .success();
    assert!(signature.exists(), "sign did not create {signature:?}");

    // 3. Verify with sq.  --signer-file gives sq the cert directly so
    //    we don't have to import into a keystore first; --signature-file
    //    points at the detached signature.  sq exits 0 on success.
    let verify = sq_cli(&sq_home)
        .arg("verify")
        .arg("--signer-file")
        .arg(&cert_path)
        .arg("--signature-file")
        .arg(&signature)
        .arg(&payload)
        .output()
        .expect("sq verify");
    assert!(
        verify.status.success(),
        "sq verify failed for {key_label}:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr),
    );
}

#[test]
fn rsa_sign_verify_with_sq() {
    let env = require_env!();
    sq_sign_verify_roundtrip(&env, &env.rsa_label, "SQ Test RSA <sq-rsa@example.com>");
}

#[test]
fn ec_sign_verify_with_sq() {
    let env = require_env!();
    sq_sign_verify_roundtrip(&env, &env.ec_label, "SQ Test EC <sq-ec@example.com>");
}

#[test]
fn sq_honours_standalone_subkey_revocation() {
    // Sequoia's sq (unlike GnuPG — see README's caveat under
    // "Caveat: GnuPG ignores standalone subkey-revocation files")
    // *does* apply a SubkeyRevocation packet imported on its own.
    // This test confirms our subkey-revoke output is structurally
    // correct and would Just Work with any Sequoia-based verifier.
    //
    // Flow: build a two-tier cert, sign a payload with the subkey,
    // verify (must succeed), then issue a "compromised" subkey
    // revocation, merge cert+revocation into one file, and verify
    // again (must fail because the signing subkey is now revoked
    // and "compromised" invalidates past signatures).

    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.asc");
    let merged_cert = tmp.path().join("cert-with-revocation.asc");
    let payload = tmp.path().join("payload.txt");
    let signature = tmp.path().join("payload.txt.asc");
    let revocation = tmp.path().join("subkey-revocation.asc");
    let sq_home = fresh_sq_home(&tmp);

    std::fs::write(&payload, b"sq subkey-revocation parity\n").unwrap();

    // 1. Two-tier cert.
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "SQ Subkey Revoke <sq-skrev@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();

    // 2. Sign with the subkey.
    sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .arg(&payload)
        .assert()
        .success();

    // 3. Verify against the un-revoked cert — must succeed.
    let verify_before = sq_cli(&sq_home)
        .arg("verify")
        .arg("--signer-file")
        .arg(&cert_path)
        .arg("--signature-file")
        .arg(&signature)
        .arg(&payload)
        .output()
        .expect("sq verify (before revocation)");
    assert!(
        verify_before.status.success(),
        "sq verify against the un-revoked cert must succeed:\nstderr: {}",
        String::from_utf8_lossy(&verify_before.stderr),
    );

    // 4. Issue a "compromised" subkey revocation.  The subkey is
    //    identified by fingerprint extracted from the cert, so no HSM
    //    access for the subkey is required (mirrors the real
    //    compromise-response path).
    let subkey_fpr = subkey_fingerprint_hex(&cert_path);
    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert_path)
        .args(["--subkey-fingerprint", &subkey_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--message", "sq subkey revocation parity test"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .success();

    // 5. Merge cert + standalone revocation into one file.  Sequoia's
    //    Cert parser handles the concatenation natively (a TPK followed
    //    by a SubkeyRevocation Signature merges into a cert with the
    //    subkey marked revoked).
    let cert_bytes = std::fs::read(&cert_path).unwrap();
    let rev_bytes = std::fs::read(&revocation).unwrap();
    std::fs::write(&merged_cert, [&cert_bytes[..], &rev_bytes[..]].concat()).unwrap();

    // 6. Verify against the merged cert — must FAIL because the signing
    //    subkey is now revoked with reason "compromised", which
    //    invalidates past signatures.
    let verify_after = sq_cli(&sq_home)
        .arg("verify")
        .arg("--signer-file")
        .arg(&merged_cert)
        .arg("--signature-file")
        .arg(&signature)
        .arg(&payload)
        .output()
        .expect("sq verify (after revocation)");
    assert!(
        !verify_after.status.success(),
        "sq verify against the cert-with-subkey-revocation must FAIL when \
         the subkey was revoked as compromised:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify_after.stdout),
        String::from_utf8_lossy(&verify_after.stderr),
    );
}

// ---------------------------------------------------------------------------
// Output format
// ---------------------------------------------------------------------------

#[test]
fn sign_output_dash_streams_to_stdout() {
    use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
    use sequoia_openpgp::Packet;

    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let payload = tmp.path().join("p.txt");
    std::fs::write(&payload, b"stdout streaming test\n").unwrap();

    let assert = sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.rsa_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output", "-"])
        .arg(&payload)
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout UTF-8");
    assert!(
        stdout.starts_with("-----BEGIN PGP SIGNATURE-----"),
        "armored sig on stdout did not start with PGP armor:\n{stdout}"
    );

    let mut ppr = PacketParser::from_bytes(stdout.as_bytes()).expect("dearmor stdout");
    let mut sigs = 0;
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next) = pp.recurse().expect("packet recurse");
        if matches!(packet, Packet::Signature(_)) {
            sigs += 1;
        }
        ppr = next;
    }
    assert_eq!(sigs, 1, "expected exactly one Signature on stdout");

    // No side-artifact next to the input — --output - must not also write
    // payload.txt.asc.
    let derived = payload.with_extension("txt.asc");
    assert!(
        !derived.exists(),
        "--output - must not also write {}",
        derived.display()
    );
}

#[test]
fn sign_refuses_to_overwrite_existing_output_without_force() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let payload = tmp.path().join("p.txt");
    let signature = tmp.path().join("p.txt.asc");
    std::fs::write(&payload, b"payload\n").unwrap();
    std::fs::write(&signature, b"PRECIOUS DO NOT OVERWRITE\n").unwrap();
    let original = std::fs::read(&signature).unwrap();

    // Without --force, sq-pkcs11 must fail and leave the existing file alone.
    let assert = sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.rsa_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&signature)
        .arg(&payload)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.contains("refusing to overwrite"),
        "expected 'refusing to overwrite' in stderr, got: {stderr}"
    );
    assert_eq!(
        std::fs::read(&signature).unwrap(),
        original,
        "existing output file must be untouched after refusal"
    );

    // With --force, the same invocation succeeds and the file is overwritten.
    sq_pkcs11(&env)
        .args(["sign", "--force"])
        .args(["--key-label", &env.rsa_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&signature)
        .arg(&payload)
        .assert()
        .success();
    let after = std::fs::read(&signature).unwrap();
    assert_ne!(after, original, "--force must overwrite the file");
    assert!(
        String::from_utf8_lossy(&after).starts_with("-----BEGIN PGP SIGNATURE-----"),
        "after --force the file should hold a fresh signature"
    );
}

#[test]
fn cert_export_refuses_to_overwrite_existing_output_without_force() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.asc");
    std::fs::write(&cert_path, b"PRECIOUS PUBLISHED CERT\n").unwrap();
    let original = std::fs::read(&cert_path).unwrap();

    let assert = sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.rsa_label])
        .args(["--userid", "Overwrite Test <ow@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .failure();
    assert!(
        String::from_utf8_lossy(&assert.get_output().stderr).contains("refusing to overwrite"),
        "expected 'refusing to overwrite' in stderr"
    );
    assert_eq!(std::fs::read(&cert_path).unwrap(), original);

    sq_pkcs11(&env)
        .args(["cert-export", "--force"])
        .args(["--key-label", &env.rsa_label])
        .args(["--userid", "Overwrite Test <ow@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();
    assert!(
        String::from_utf8_lossy(&std::fs::read(&cert_path).unwrap())
            .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        "--force must overwrite the file with a fresh cert"
    );
}

#[test]
fn sign_binary_produces_non_armored_output() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let payload = tmp.path().join("p.bin");
    let signature = tmp.path().join("p.bin.sig");
    std::fs::write(&payload, b"binary payload").unwrap();

    sq_pkcs11(&env)
        .args(["sign", "--binary"])
        .args(["--key-label", &env.rsa_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&signature)
        .arg(&payload)
        .assert()
        .success();

    let bytes = std::fs::read(&signature).unwrap();
    assert!(
        !bytes.starts_with(b"-----BEGIN"),
        "binary signature must not start with armor header"
    );
    // First byte of an OpenPGP packet header has the high bit set.
    assert!(
        !bytes.is_empty() && bytes[0] & 0x80 != 0,
        "expected OpenPGP packet header, got {:#04x}",
        bytes.first().copied().unwrap_or(0)
    );
}

// ---------------------------------------------------------------------------
// Fingerprint stability vs --creation-time
// ---------------------------------------------------------------------------

fn fingerprint_of(cert_path: &Path) -> String {
    // We don't want a hard dependency on `sq` for this; parse the armored
    // block manually with `gpg --show-keys` which is universally available
    // and prints the fingerprint deterministically.
    let tmp = TempDir::new().unwrap();
    let home = fresh_gpg_home(&tmp);
    let out = gpg_in(&home)
        .args(["--show-keys", "--with-colons"])
        .arg(cert_path)
        .output()
        .expect("gpg --show-keys");
    assert!(out.status.success(), "gpg --show-keys failed");
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("fpr:") {
            // colon-separated; the fingerprint is in the 9th column (index 8)
            // but easier: it's the only all-hex 40-char run.
            for field in rest.split(':') {
                if field.len() == 40 && field.chars().all(|c| c.is_ascii_hexdigit()) {
                    return field.to_string();
                }
            }
        }
    }
    panic!("no fingerprint found in:\n{s}");
}

fn export_cert(env: &TestEnv, key_label: &str, creation_time: &str, dest: &Path) {
    sq_pkcs11(env)
        .args(["cert-export"])
        .args(["--key-label", key_label])
        .args(["--userid", "Test <stable@example.com>"])
        .args(["--creation-time", creation_time])
        .args(["--output"])
        .arg(dest)
        .assert()
        .success();
}

#[test]
fn fingerprint_stable_across_runs() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("a.asc");
    let b = tmp.path().join("b.asc");

    export_cert(&env, &env.ec_label, STABLE_TIME, &a);
    export_cert(&env, &env.ec_label, STABLE_TIME, &b);

    assert_eq!(
        fingerprint_of(&a),
        fingerprint_of(&b),
        "same key + same --creation-time must yield the same fingerprint"
    );
}

#[test]
fn fingerprint_changes_with_creation_time() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("a.asc");
    let b = tmp.path().join("b.asc");

    export_cert(&env, &env.ec_label, "2026-01-01T00:00:00Z", &a);
    export_cert(&env, &env.ec_label, "2030-01-01T00:00:00Z", &b);

    assert_ne!(
        fingerprint_of(&a),
        fingerprint_of(&b),
        "different --creation-time values must yield different fingerprints"
    );
}

// ---------------------------------------------------------------------------
// Validity period
// ---------------------------------------------------------------------------

#[test]
fn validity_period_appears_in_cert() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");
    let home = fresh_gpg_home(&tmp);

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.ec_label])
        .args(["--userid", "Validity Test <v@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--validity-period", "1y"])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();

    let out = gpg_in(&home)
        .args(["--show-keys", "--with-colons"])
        .arg(&cert)
        .output()
        .expect("gpg --show-keys");
    assert!(out.status.success());

    // In --with-colons output, a "pub:" line has the expiry timestamp in
    // column 7 (index 6) — non-zero means an expiry is set.
    let s = String::from_utf8_lossy(&out.stdout);
    let pub_line = s
        .lines()
        .find(|l| l.starts_with("pub:"))
        .expect("no pub: line");
    let expiry = pub_line.split(':').nth(6).expect("no expiry field");
    assert!(
        !expiry.is_empty() && expiry != "0",
        "expected non-zero expiry field on pub: line, got {expiry:?}\nfull line: {pub_line}"
    );
}

// ---------------------------------------------------------------------------
// Two-tier (primary + signing subkey)
// ---------------------------------------------------------------------------

#[test]
fn two_tier_cert_export_and_subkey_sign() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("two-tier.asc");
    let payload = tmp.path().join("p.txt");
    let signature = tmp.path().join("p.txt.asc");
    let home = fresh_gpg_home(&tmp);

    std::fs::write(&payload, b"two-tier payload\n").unwrap();

    // 1. Build the two-tier cert.
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Two-Tier <2t@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--validity-period", "10y"])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--subkey-validity-period", "2y"])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();

    // 2. Import the cert and check both keys are present with correct flags.
    gpg_in(&home).arg("--import").arg(&cert).assert_success();

    let listing = gpg_in(&home)
        .args(["--list-keys", "--with-colons"])
        .output()
        .expect("gpg --list-keys");
    assert!(listing.status.success());
    let listing_s = String::from_utf8_lossy(&listing.stdout);

    // colon-format: "pub:..." lines for primary, "sub:..." for subkey.
    // Capability flags in column 12 (index 11).
    //
    // GPG distinguishes per-key (lowercase) from cert-wide (uppercase)
    // capabilities.  In a two-tier cert the primary's per-key flags are
    // 'c' only, while the cert-wide flags include 'S' (the subkey can
    // sign) and 'C' (some key can certify).  So we check **lowercase**
    // 'c' on the primary and assert lowercase 's' is absent there.
    let pub_caps = listing_s
        .lines()
        .find(|l| l.starts_with("pub:"))
        .and_then(|l| l.split(':').nth(11))
        .unwrap_or("");
    let sub_caps = listing_s
        .lines()
        .find(|l| l.starts_with("sub:"))
        .and_then(|l| l.split(':').nth(11))
        .unwrap_or("");
    assert!(
        pub_caps.contains('c'),
        "expected primary to have per-key certify capability (lowercase 'c'), caps={pub_caps:?}"
    );
    assert!(
        !pub_caps.contains('s'),
        "primary must not have per-key signing capability (lowercase 's') in two-tier cert, \
         caps={pub_caps:?}"
    );
    assert!(
        sub_caps.contains('s'),
        "expected subkey to have per-key signing capability (lowercase 's'), caps={sub_caps:?}"
    );

    // 3. Sign with the subkey and verify.
    sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .arg(&payload)
        .assert()
        .success();

    let verify = gpg_in(&home)
        .arg("--verify")
        .arg(&signature)
        .arg(&payload)
        .output()
        .expect("gpg --verify");
    assert!(
        verify.status.success(),
        "gpg --verify failed:\nstderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("Good signature"));
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

#[test]
fn cert_revoke_marks_primary_revoked() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");
    let revocation = tmp.path().join("revocation.asc");
    let home = fresh_gpg_home(&tmp);

    // 1. Export a fresh cert.
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.ec_label])
        .args(["--userid", "Revoke Test <revoke@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();

    // 2. Issue a revocation against the same key + creation time.
    sq_pkcs11(&env)
        .args(["cert-revoke"])
        .args(["--key-label", &env.ec_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "superseded"])
        .args(["--message", "test rotation"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .success();

    // 3. Import cert first, then the revocation.
    gpg_in(&home).arg("--import").arg(&cert).assert_success();
    gpg_in(&home)
        .arg("--import")
        .arg(&revocation)
        .assert_success();

    // 4. List the key — colon-format includes 'r' in column 2 of pub: when revoked.
    let listing = gpg_in(&home)
        .args(["--list-keys", "--with-colons"])
        .output()
        .expect("gpg --list-keys");
    assert!(listing.status.success());
    let listing_s = String::from_utf8_lossy(&listing.stdout);
    let pub_line = listing_s
        .lines()
        .find(|l| l.starts_with("pub:"))
        .expect("no pub: line");
    let validity = pub_line.split(':').nth(1).unwrap_or("");
    assert!(
        validity.contains('r'),
        "expected primary to be revoked (validity contains 'r'), got pub: line: {pub_line}"
    );
}

#[test]
fn subkey_revoke_rejects_input_cert_belonging_to_other_primary() {
    // If the operator picks the wrong --key-label (or right label with
    // wrong --creation-time) but supplies an --input-cert whose
    // primary fingerprint doesn't match what the HSM would derive,
    // sq-pkcs11 must refuse before signing.  Without this guard the
    // tool would produce a "revocation" signed by primary A naming a
    // subkey of cert B — a useless artefact that wastes an HSM
    // operation.
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_a = tmp.path().join("cert-a.asc");
    let cert_b = tmp.path().join("cert-b.asc");
    let revocation = tmp.path().join("revocation.asc");

    // Cert A: primary = ec_label.
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.ec_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Cert A <a@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_a)
        .assert()
        .success();

    // Cert B: primary = primary_label (different HSM key, different
    // fingerprint).
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Cert B <b@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_b)
        .assert()
        .success();

    // Mix them: primary selector points at cert A's primary key, but
    // --input-cert is cert B and --subkey-fingerprint is from cert B.
    let cert_b_subkey_fpr = subkey_fingerprint_hex(&cert_b);
    let assert = sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.ec_label]) // ← primary of cert A
        .args(["--input-cert"])
        .arg(&cert_b) // ← cert with a different primary
        .args(["--subkey-fingerprint", &cert_b_subkey_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--message", "wrong primary test"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("primary fingerprint mismatch"),
        "expected 'primary fingerprint mismatch' in stderr, got: {stderr}"
    );
    assert!(
        !revocation.exists(),
        "subkey-revoke must not write output when primary doesn't match the input cert"
    );
}

#[test]
fn sign_rejects_nonexistent_input_file() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let missing = tmp.path().join("does-not-exist.txt");
    let assert = sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.rsa_label])
        .args(["--creation-time", STABLE_TIME])
        .arg(&missing)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("does-not-exist") || stderr.contains("No such file"),
        "expected error mentioning the missing path, got: {stderr}"
    );
}

#[test]
fn sign_rejects_directory_as_input() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    // tmp.path() itself is a directory.
    let assert = sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.rsa_label])
        .args(["--creation-time", STABLE_TIME])
        .arg(tmp.path())
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        // std::fs::read on a directory returns a platform-dependent
        // error (EISDIR on Linux); accept any non-empty diagnostic.
        !stderr.is_empty(),
        "expected a non-empty error when input is a directory"
    );
}

#[test]
fn sign_default_output_refuses_overwrite_without_force() {
    // sign without --output derives <input>.asc as the output path.
    // That derived path must also be subject to the preflight refuse-
    // to-overwrite check, otherwise an accidental rerun against a
    // payload whose `.asc` already exists would clobber it.
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let payload = tmp.path().join("p.txt");
    let derived = tmp.path().join("p.txt.asc");
    std::fs::write(&payload, b"payload\n").unwrap();
    std::fs::write(&derived, b"PRECIOUS\n").unwrap();

    let assert = sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.rsa_label])
        .args(["--creation-time", STABLE_TIME])
        .arg(&payload)
        .assert()
        .failure();
    assert!(
        String::from_utf8_lossy(&assert.get_output().stderr).contains("refusing to overwrite"),
        "expected refuse-to-overwrite for the auto-derived output path"
    );
    assert_eq!(std::fs::read(&derived).unwrap(), b"PRECIOUS\n");
}

#[test]
fn cert_revoke_revocation_time_round_trips_exactly() {
    // The --revocation-time supplied on the command line must end up
    // verbatim in the produced Signature's signature-creation-time
    // subpacket, even when the time is in the future or before the
    // key's creation time (the operator may legitimately want either
    // for a back-dated or scheduled revocation).
    let env = require_env!();
    let tmp = TempDir::new().unwrap();

    for case in [
        ("future", "2030-12-31T23:59:59Z"),
        ("past_pre_key_creation", "2020-01-01T00:00:00Z"),
        ("epoch", "1970-01-01T00:00:00Z"),
    ] {
        let (label, ts) = case;
        let revocation = tmp.path().join(format!("rev-{label}.asc"));
        sq_pkcs11(&env)
            .args(["cert-revoke"])
            .args(["--key-label", &env.ec_label])
            .args(["--creation-time", STABLE_TIME])
            .args(["--revocation-time", ts])
            .args(["--reason", "superseded"])
            .args(["--message", label])
            .args(["--output"])
            .arg(&revocation)
            .assert()
            .success();

        let sig = parse_signature_file(&revocation);
        let actual = sig
            .signature_creation_time()
            .expect("signature creation time present");
        let expected = humantime::parse_rfc3339(ts).unwrap();
        assert_eq!(
            actual, expected,
            "revocation_time {ts:?} must round-trip exactly into the signature \
             creation time subpacket (case: {label})"
        );
    }
}

#[test]
fn cert_revoke_rejects_invalid_revocation_time() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let revocation = tmp.path().join("rev.asc");
    let assert = sq_pkcs11(&env)
        .args(["cert-revoke"])
        .args(["--key-label", &env.ec_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--revocation-time", "not-a-real-timestamp"])
        .args(["--reason", "superseded"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("invalid") || stderr.contains("RFC 3339"),
        "expected RFC 3339 parse error, got: {stderr}"
    );
    assert!(!revocation.exists());
}

#[test]
fn sign_preflights_overwrite_before_hsm_round_trip() {
    // The preflight check must fail BEFORE we open an HSM session.  We
    // arrange a configuration that would otherwise fail with
    // "key not found" deep inside the HSM lookup, and confirm that with
    // an existing output file we instead see "refusing to overwrite" —
    // proof that we never reached the key-resolution step.
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let payload = tmp.path().join("p.txt");
    let signature = tmp.path().join("p.txt.asc");
    std::fs::write(&payload, b"preflight test\n").unwrap();
    std::fs::write(&signature, b"DO NOT TOUCH\n").unwrap();

    let assert = sq_pkcs11(&env)
        .args(["sign"])
        // A label that demonstrably doesn't exist on the HSM — without
        // preflight, this would surface "is not present in the Security
        // World" or similar.  With preflight, we never reach the lookup.
        .args(["--key-label", "this-key-does-not-exist-xyz"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&signature)
        .arg(&payload)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("refusing to overwrite"),
        "expected preflight 'refusing to overwrite' BEFORE HSM key lookup; got: {stderr}"
    );
    assert_eq!(
        std::fs::read(&signature).unwrap(),
        b"DO NOT TOUCH\n",
        "existing output bytes must be untouched"
    );
}

#[test]
fn cert_revoke_refuses_overwrite_without_force() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let revocation = tmp.path().join("rev.asc");
    std::fs::write(&revocation, b"PRECIOUS\n").unwrap();
    let assert = sq_pkcs11(&env)
        .args(["cert-revoke"])
        .args(["--key-label", &env.ec_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "superseded"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .failure();
    assert!(
        String::from_utf8_lossy(&assert.get_output().stderr).contains("refusing to overwrite"),
        "expected 'refusing to overwrite' in stderr"
    );
    assert_eq!(std::fs::read(&revocation).unwrap(), b"PRECIOUS\n");
}

#[test]
fn subkey_revoke_refuses_overwrite_without_force_and_force_overwrites() {
    use sequoia_openpgp::types::SignatureType;

    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");
    let revocation = tmp.path().join("rev.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Force Test <ft@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();
    let subkey_fpr = subkey_fingerprint_hex(&cert);

    // Pre-create the output.  First run (no --force) must refuse and
    // leave the bytes alone.
    std::fs::write(&revocation, b"PRECIOUS\n").unwrap();
    let assert = sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert)
        .args(["--subkey-fingerprint", &subkey_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .failure();
    assert!(
        String::from_utf8_lossy(&assert.get_output().stderr).contains("refusing to overwrite"),
        "expected refuse-to-overwrite"
    );
    assert_eq!(std::fs::read(&revocation).unwrap(), b"PRECIOUS\n");

    // Second run with --force: must overwrite and produce a valid
    // SubkeyRevocation packet.
    sq_pkcs11(&env)
        .args(["subkey-revoke", "--force"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert)
        .args(["--subkey-fingerprint", &subkey_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .success();
    assert_ne!(std::fs::read(&revocation).unwrap(), b"PRECIOUS\n");
    let sig = parse_signature_file(&revocation);
    assert_eq!(sig.typ(), SignatureType::SubkeyRevocation);
}

#[test]
fn subkey_revoke_rejects_malformed_inputs() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");
    let bad_cert = tmp.path().join("bad-cert.asc");
    let revocation = tmp.path().join("rev.asc");

    // Real cert for the cases that need a parseable cert.
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Malformed Test <mt@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();
    let primary_fpr = parse_cert_file(&cert).fingerprint().to_string();

    // 1. Garbage cert input — must fail in the parser, before HSM access.
    std::fs::write(&bad_cert, b"this is not an OpenPGP cert\n").unwrap();
    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&bad_cert)
        .args([
            "--subkey-fingerprint",
            "0000000000000000000000000000000000000000",
        ])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .failure();
    assert!(!revocation.exists());

    // 2. Short (16-hex) key ID is rejected up front: not collision-resistant.
    let assert = sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert)
        .args(["--subkey-fingerprint", "0123456789ABCDEF"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("not a full OpenPGP fingerprint"),
        "expected 'not a full OpenPGP fingerprint' for 16-hex input, got: {stderr}"
    );
    assert!(!revocation.exists());

    // 3. Non-hex characters in fingerprint.
    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert)
        .args([
            "--subkey-fingerprint",
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        ])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .failure();
    assert!(!revocation.exists());

    // 4. Primary fingerprint where a subkey fingerprint is expected:
    //    the primary is in the cert but is not a subkey, so the search
    //    must fail with "no subkey ... matches".
    let assert = sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert)
        .args(["--subkey-fingerprint", &primary_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .failure();
    assert!(
        String::from_utf8_lossy(&assert.get_output().stderr)
            .contains("no subkey in the input cert matches"),
        "expected 'no subkey ... matches' for primary-fingerprint input"
    );
    assert!(!revocation.exists());
}

// ---------------------------------------------------------------------------
// verify-signing-key: pre-flight check that the configured HSM key really is a
// current valid signer of the published cert.
// ---------------------------------------------------------------------------

#[test]
fn verify_signing_key_accepts_current_signing_subkey() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Verify Signing <vs@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();

    // The configured signing subkey IS the cert's current signing
    // subkey — verification must succeed.
    let assert = sq_pkcs11(&env)
        .args(["verify-signing-key"])
        .args(["--key-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--input-cert"])
        .arg(&cert)
        .assert()
        .success();
    assert!(
        String::from_utf8_lossy(&assert.get_output().stdout).contains("is a current signing key"),
        "expected success message"
    );
}

#[test]
fn verify_signing_key_rejects_unrelated_hsm_key() {
    // Operator points at a different HSM key (env.rsa_label) than the
    // one bound in the cert (env.subkey_label).  Verification must
    // fail with "not bound to <cert>" — catches the typo'd
    // OPENSSL_PGP_CURRENT_SUBKEY_LABEL case Codex flagged.
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Stale Signer <ss@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();

    let assert = sq_pkcs11(&env)
        .args(["verify-signing-key"])
        .args(["--key-label", &env.rsa_label]) // ← wrong key
        .args(["--creation-time", STABLE_TIME])
        .args(["--input-cert"])
        .arg(&cert)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("not bound to"),
        "expected 'not bound to ...' for an unrelated HSM key, got: {stderr}"
    );
}

#[test]
fn verify_signing_key_rejects_certify_only_primary() {
    // In a two-tier cert, the primary carries the certification flag
    // only; it is NOT signing-capable.  Verifying the primary as a
    // signing key must therefore fail because no candidate matches the
    // signing-flag filter.
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Two Tier <2t@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();

    let assert = sq_pkcs11(&env)
        .args(["verify-signing-key"])
        .args(["--key-label", &env.primary_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--input-cert"])
        .arg(&cert)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("present in") && stderr.contains("not currently a valid signer"),
        "expected 'present but not valid signer' for the certify-only primary, got: {stderr}"
    );
}

#[test]
fn verify_signing_key_rejects_revoked_subkey() {
    // Revoke the subkey, merge the revocation into the cert, then run
    // verify-signing-key against the merged cert: the previously-valid
    // signing subkey must now be reported as not currently valid.
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");
    let revocation = tmp.path().join("rev.asc");
    let merged_cert = tmp.path().join("cert-with-revocation.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Revoked Signer <rs@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();

    let subkey_fpr = subkey_fingerprint_hex(&cert);
    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert)
        .args(["--subkey-fingerprint", &subkey_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .success();

    let cert_bytes = std::fs::read(&cert).unwrap();
    let rev_bytes = std::fs::read(&revocation).unwrap();
    std::fs::write(&merged_cert, [&cert_bytes[..], &rev_bytes[..]].concat()).unwrap();

    let assert = sq_pkcs11(&env)
        .args(["verify-signing-key"])
        .args(["--key-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--input-cert"])
        .arg(&merged_cert)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("not currently a valid signer"),
        "expected 'not currently a valid signer' after revocation, got: {stderr}"
    );
}

#[test]
fn subkey_revoke_works_without_subkey_hsm_access() {
    // The whole point of the subkey-revoke API redesign: a compromised
    // or lost signing subkey must still be revokable using only the
    // primary HSM key plus the published cert.  Reproduce the
    // compromise scenario by pointing --subkey-fingerprint at a subkey
    // present in the input cert but exercising sq-pkcs11 with
    // SQ_PKCS11_SUBKEY_PIN scrubbed and no --subkey-* HSM selectors —
    // the binary must succeed without ever opening a private-key
    // session for the subkey.
    //
    // (We can't directly assert "no PKCS#11 session was opened for
    // CKA_LABEL X" without a mock layer, but the new CLI shape forbids
    // even expressing that — the --subkey-* selector flags no longer
    // exist on subkey-revoke — so a passing run here proves the
    // private-key-of-subkey is not consulted.)
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");
    let revocation = tmp.path().join("revocation.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "No-Subkey-HSM Test <nsh@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();

    let subkey_fpr = subkey_fingerprint_hex(&cert);
    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert)
        .args(["--subkey-fingerprint", &subkey_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--message", "compromised; subkey HSM access not needed"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .success();

    // The produced packet binds the right subkey: parse and check the
    // SubkeyRevocation signature's hash recovers the same fingerprint.
    use sequoia_openpgp::types::SignatureType;
    let sig = parse_signature_file(&revocation);
    assert_eq!(
        sig.typ(),
        SignatureType::SubkeyRevocation,
        "expected SubkeyRevocation packet, got {:?}",
        sig.typ()
    );
}

#[test]
fn subkey_revoke_marks_only_subkey_revoked() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");
    let revocation = tmp.path().join("subkey-revocation.asc");
    let home = fresh_gpg_home(&tmp);

    // Build a two-tier cert.
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Subkey Revoke Test <skrev@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .success();

    // Revoke only the subkey.  Subkey is addressed by fingerprint
    // extracted from the cert; no HSM access for the subkey itself.
    let subkey_fpr = subkey_fingerprint_hex(&cert);
    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert)
        .args(["--subkey-fingerprint", &subkey_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--message", "subkey lost"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .success();

    // GnuPG will silently drop a standalone subkey-revocation file
    // imported on its own (`Total number processed: 0`); it only attaches
    // the revocation to the matching subkey when the revocation arrives
    // *together with* the cert in a single import stream.  Concatenate
    // the binary forms of the cert and the revocation into one combined
    // file and import that — the same workaround real consumers must
    // apply.
    let combined = tmp.path().join("cert-with-subkey-revocation.asc");
    let cert_bytes = std::fs::read(&cert).unwrap();
    let rev_bytes = std::fs::read(&revocation).unwrap();
    std::fs::write(&combined, [&cert_bytes[..], &rev_bytes[..]].concat()).unwrap();
    gpg_in(&home)
        .arg("--import")
        .arg(&combined)
        .assert_success();

    let listing = gpg_in(&home)
        .args(["--list-keys", "--with-colons"])
        .output()
        .expect("gpg --list-keys");
    assert!(listing.status.success());
    let listing_s = String::from_utf8_lossy(&listing.stdout);

    // Primary validity column 2 must NOT contain 'r'; subkey's MUST.
    let pub_line = listing_s
        .lines()
        .find(|l| l.starts_with("pub:"))
        .expect("no pub: line");
    let pub_validity = pub_line.split(':').nth(1).unwrap_or("");
    assert!(
        !pub_validity.contains('r'),
        "primary must not be revoked when only the subkey is, got pub: line: {pub_line}"
    );

    let sub_line = listing_s
        .lines()
        .find(|l| l.starts_with("sub:"))
        .expect("no sub: line");
    let sub_validity = sub_line.split(':').nth(1).unwrap_or("");
    assert!(
        sub_validity.contains('r'),
        "expected subkey to be revoked, got sub: line: {sub_line}"
    );
}

// ---------------------------------------------------------------------------
// Subkey rotation via cert-export --merge-cert
// ---------------------------------------------------------------------------

#[test]
fn merge_cert_preserves_old_subkey() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_v1 = tmp.path().join("cert-v1.asc");
    let cert_v2 = tmp.path().join("cert-v2.asc");
    let payload_old = tmp.path().join("old.txt");
    let payload_new = tmp.path().join("new.txt");
    let home = fresh_gpg_home(&tmp);

    std::fs::write(&payload_old, b"signed by old subkey\n").unwrap();
    std::fs::write(&payload_new, b"signed by new subkey\n").unwrap();

    // 1. Initial cert with primary + subkey1.
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Rotation Test <rot@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_v1)
        .assert()
        .success();

    // 2. Sign payload_old with subkey1 BEFORE rotation.
    sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .arg(&payload_old)
        .assert()
        .success();

    // 3. Merge — same primary creation time, new subkey, distinct subkey
    //    creation time so the new subkey has its own fingerprint.
    // Pick a creation time DIFFERENT from STABLE_TIME (so the old and new
    // subkeys have distinct fingerprints) but firmly in the past.  An
    // earlier draft used "2026-06-01T00:00:00Z", which fails once the
    // wall clock reaches a date earlier than that — gpg refuses signatures
    // made before the signing key claims to have been created ("public
    // key … is N days newer than the signature").  STABLE_TIME + a few
    // hours is past, distinct, and stable.
    let new_subkey_time = "2026-01-01T06:00:00Z";
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--merge-cert"])
        .arg(&cert_v1)
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey2_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", new_subkey_time])
        .args(["--output"])
        .arg(&cert_v2)
        .assert()
        .success();

    // 4. Sign payload_new with subkey2 AFTER rotation.
    sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.subkey2_label])
        .args(["--creation-time", new_subkey_time])
        .arg(&payload_new)
        .assert()
        .success();

    // 5. Import the merged cert and confirm both subkeys are present.
    gpg_in(&home).arg("--import").arg(&cert_v2).assert_success();
    let listing = gpg_in(&home)
        .args(["--list-keys", "--with-colons"])
        .output()
        .expect("gpg --list-keys");
    assert!(listing.status.success());
    let listing_s = String::from_utf8_lossy(&listing.stdout);
    let sub_count = listing_s.lines().filter(|l| l.starts_with("sub:")).count();
    assert_eq!(
        sub_count, 2,
        "merged cert must contain both old and new subkeys, found {sub_count} sub: lines"
    );

    // 6. Both signatures verify against the merged cert.
    let sig_old = payload_old.with_extension("txt.asc");
    let sig_new = payload_new.with_extension("txt.asc");
    for (sig, payload, label) in [
        (&sig_old, &payload_old, "old subkey"),
        (&sig_new, &payload_new, "new subkey"),
    ] {
        let verify = gpg_in(&home)
            .arg("--verify")
            .arg(sig)
            .arg(payload)
            .output()
            .expect("gpg --verify");
        assert!(
            verify.status.success(),
            "verification with merged cert failed for {label}:\nstderr: {}",
            String::from_utf8_lossy(&verify.stderr),
        );
        let stderr = String::from_utf8_lossy(&verify.stderr);
        assert!(
            stderr.contains("Good signature"),
            "expected Good signature for {label}"
        );
    }
}

// ---------------------------------------------------------------------------
// Revocation file framing
// ---------------------------------------------------------------------------
//
// Regression test for the "Malformed CTB: MSB of ptag (0b00000100) not set"
// bug.  GnuPG is lenient enough to import a Signature serialized as just its
// body (no CTB), so the existing import-and-revoked-flag tests passed despite
// the bug.  Sequoia's PacketParser — the same parser `sq inspect` uses — is
// strict.  Verify both `cert-revoke` and `subkey-revoke` outputs round-trip
// through it.

#[test]
fn revocation_files_are_proper_openpgp_packets() {
    use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
    use sequoia_openpgp::Packet;

    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.asc");
    let cert_revocation = tmp.path().join("cert-revocation.asc");
    let subkey_revocation = tmp.path().join("subkey-revocation.asc");

    // Two-tier cert provides the subkey we'll revoke (subkey-revoke now
    // identifies its target by fingerprint inside an --input-cert).
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Framing Test <fr@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();

    sq_pkcs11(&env)
        .args(["cert-revoke"])
        .args(["--key-label", &env.ec_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "superseded"])
        .args(["--message", "framing regression"])
        .args(["--output"])
        .arg(&cert_revocation)
        .assert()
        .success();

    let subkey_fpr = subkey_fingerprint_hex(&cert_path);
    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert_path)
        .args(["--subkey-fingerprint", &subkey_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--message", "framing regression"])
        .args(["--output"])
        .arg(&subkey_revocation)
        .assert()
        .success();

    for (path, label) in [
        (&cert_revocation, "cert-revoke"),
        (&subkey_revocation, "subkey-revoke"),
    ] {
        let bytes = std::fs::read(path).expect("read revocation");
        let mut ppr = PacketParser::from_bytes(&bytes)
            .unwrap_or_else(|e| panic!("{label} output is not a parseable OpenPGP stream: {e}"));
        let mut count = 0;
        while let PacketParserResult::Some(pp) = ppr {
            let (packet, next) = pp
                .recurse()
                .unwrap_or_else(|e| panic!("{label}: packet recurse failed: {e}"));
            assert!(
                matches!(packet, Packet::Signature(_)),
                "{label}: expected Signature packet, got {packet:?}"
            );
            count += 1;
            ppr = next;
        }
        assert_eq!(
            count, 1,
            "{label}: expected exactly one packet, got {count}"
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers for the cert/signature inspection tests below.
// ---------------------------------------------------------------------------

fn parse_cert_file(path: &Path) -> sequoia_openpgp::Cert {
    use sequoia_openpgp::parse::Parse;
    let bytes = std::fs::read(path).expect("read cert file");
    sequoia_openpgp::Cert::from_bytes(&bytes)
        .unwrap_or_else(|e| panic!("parse cert {}: {e}", path.display()))
}

fn parse_signature_file(path: &Path) -> sequoia_openpgp::packet::Signature {
    use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
    use sequoia_openpgp::Packet;
    let bytes = std::fs::read(path).expect("read signature file");
    let mut ppr = PacketParser::from_bytes(&bytes)
        .unwrap_or_else(|e| panic!("parse signature {}: {e}", path.display()));
    let mut found: Option<sequoia_openpgp::packet::Signature> = None;
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next) = pp.recurse().expect("packet recurse");
        if let Packet::Signature(s) = packet {
            assert!(found.is_none(), "expected one Signature packet, got more");
            found = Some(s);
        }
        ppr = next;
    }
    found.unwrap_or_else(|| panic!("no Signature packet in {}", path.display()))
}

/// Extract the (single) subkey's fingerprint from a cert file as a hex
/// string, ready to feed to `--subkey-fingerprint`.  Used by the
/// subkey-revocation tests, which now address the subkey by fingerprint
/// inside the cert rather than by HSM CKA_LABEL.
fn subkey_fingerprint_hex(path: &Path) -> String {
    let cert = parse_cert_file(path);
    let mut subkeys = cert.keys().subkeys();
    let first = subkeys.next().expect("cert has no subkey");
    assert!(
        subkeys.next().is_none(),
        "cert has multiple subkeys; tests assume exactly one"
    );
    first.key().fingerprint().to_string().replace(' ', "")
}

/// Use `sq-pkcs11 list-keys` to discover the CKA_ID for a given CKA_LABEL.
/// Output line format: `  label="..."  id=HEX  type=...`.  Returns `None`
/// if the key has no CKA_ID populated (nShield's `generatekey` does not
/// always set one — empty CKA_ID has been observed on EC keys).  The
/// caller is expected to handle that case; the --key-id selector is
/// inapplicable to such a key.
fn cka_id_for_label(env: &TestEnv, label: &str) -> Option<String> {
    let assert = sq_pkcs11(env).arg("list-keys").assert().success();
    let stdout =
        String::from_utf8(assert.get_output().stdout.clone()).expect("list-keys stdout is UTF-8");
    let needle = format!("label={label:?}");
    for line in stdout.lines() {
        if !line.contains(&needle) {
            continue;
        }
        if let Some(id_field) = line.split("id=").nth(1) {
            if let Some(id) = id_field.split_whitespace().next() {
                // Validate hex — list-keys prints `<no id>` (or, formerly,
                // an empty string) when the attribute is absent; we must
                // not pass that on as if it were a real id.
                if !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(id.to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Two-tier capability invariants
// ---------------------------------------------------------------------------

#[test]
fn two_tier_cert_has_only_certify_primary_and_signing_subkey() {
    use sequoia_openpgp::policy::StandardPolicy;

    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Caps Test <caps@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--validity-period", "10y"])
        .args(["--subkey-validity-period", "1y"])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();

    let cert = parse_cert_file(&cert_path);
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).expect("cert is valid");

    let primary_flags = valid
        .primary_key()
        .key_flags()
        .expect("primary has key flags");
    assert!(
        primary_flags.for_certification(),
        "primary must have certification capability"
    );
    assert!(
        !primary_flags.for_signing(),
        "primary must not have signing capability in two-tier cert"
    );
    assert!(
        !primary_flags.for_storage_encryption() && !primary_flags.for_transport_encryption(),
        "primary must not have any encryption capability"
    );
    assert!(
        !primary_flags.for_authentication(),
        "primary must not have authentication capability"
    );

    let subkeys: Vec<_> = valid.keys().subkeys().collect();
    assert_eq!(
        subkeys.len(),
        1,
        "expected exactly one subkey, found {}",
        subkeys.len()
    );
    let sub_flags = subkeys[0].key_flags().expect("subkey has key flags");
    assert!(
        sub_flags.for_signing(),
        "subkey must have signing capability"
    );
    assert!(
        !sub_flags.for_certification(),
        "subkey must not have certification capability"
    );
    assert!(
        !sub_flags.for_storage_encryption() && !sub_flags.for_transport_encryption(),
        "subkey must not have any encryption capability"
    );
    assert!(
        !sub_flags.for_authentication(),
        "subkey must not have authentication capability"
    );
}

// ---------------------------------------------------------------------------
// Validity-period encoding (long primary, short subkey)
// ---------------------------------------------------------------------------

#[test]
fn validity_periods_are_recorded_in_signatures() {
    use sequoia_openpgp::policy::StandardPolicy;
    use std::time::Duration;

    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.asc");
    let home = fresh_gpg_home(&tmp);

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Validity Two-Tier <vt@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--validity-period", "10y"])
        .args(["--subkey-validity-period", "1y"])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();

    // ── Sequoia view: signature subpackets carry the durations we asked for.
    let cert = parse_cert_file(&cert_path);
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).expect("cert is valid");

    let primary_validity = valid
        .primary_key()
        .key_validity_period()
        .expect("primary key_validity_period subpacket present");
    let ten_years = Duration::from_secs((10.0 * 365.25 * 86_400.0) as u64);
    let one_year = Duration::from_secs((365.25 * 86_400.0) as u64);
    // 1-day tolerance covers leap-year variability in the calendar-aware
    // year arithmetic done by parse_validity — the actual duration depends
    // on how many Feb 29s fall in the span, which the Julian-year baseline
    // above doesn't capture.
    let tolerance = Duration::from_secs(86_400);
    assert!(
        primary_validity.abs_diff(ten_years) <= tolerance,
        "primary validity {primary_validity:?} is not ~10y (expected {ten_years:?})"
    );

    let subkey = valid.keys().subkeys().next().expect("one subkey");
    let subkey_validity = subkey
        .key_validity_period()
        .expect("subkey key_validity_period subpacket present");
    assert!(
        subkey_validity.abs_diff(one_year) <= tolerance,
        "subkey validity {subkey_validity:?} is not ~1y (expected {one_year:?})"
    );

    // ── GPG view: both pub: and sub: lines have non-zero expiry timestamps,
    //    and the difference between them is roughly 9 years (10y - 1y).
    gpg_in(&home)
        .arg("--import")
        .arg(&cert_path)
        .assert_success();
    let listing = gpg_in(&home)
        .args(["--list-keys", "--with-colons"])
        .output()
        .expect("gpg --list-keys");
    assert!(listing.status.success());
    let s = String::from_utf8_lossy(&listing.stdout);
    let pub_line = s
        .lines()
        .find(|l| l.starts_with("pub:"))
        .expect("pub: line");
    let sub_line = s
        .lines()
        .find(|l| l.starts_with("sub:"))
        .expect("sub: line");
    let pub_expiry: u64 = pub_line
        .split(':')
        .nth(6)
        .and_then(|f| f.parse().ok())
        .expect("pub: expiry int");
    let sub_expiry: u64 = sub_line
        .split(':')
        .nth(6)
        .and_then(|f| f.parse().ok())
        .expect("sub: expiry int");
    assert!(pub_expiry > 0, "primary expiry must be set");
    assert!(sub_expiry > 0, "subkey expiry must be set");
    assert!(
        pub_expiry > sub_expiry,
        "primary should outlive subkey: pub_expiry={pub_expiry} sub_expiry={sub_expiry}"
    );
}

// ---------------------------------------------------------------------------
// Revocation metadata: reason, message, and revocation time round-trip.
// ---------------------------------------------------------------------------

#[test]
fn revocation_signature_records_reason_message_and_time() {
    use sequoia_openpgp::types::ReasonForRevocation;

    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let revocation_time = "2026-07-15T12:34:56Z";

    let cases = [
        ("unspecified", ReasonForRevocation::Unspecified, "no reason"),
        (
            "superseded",
            ReasonForRevocation::KeySuperseded,
            "rotated to fresh key",
        ),
        (
            "compromised",
            ReasonForRevocation::KeyCompromised,
            "smartcard lost in transit",
        ),
        (
            "retired",
            ReasonForRevocation::KeyRetired,
            "service decommissioned",
        ),
    ];

    for (cli_reason, expected_code, message) in cases {
        let revocation = tmp.path().join(format!("rev-{cli_reason}.asc"));
        sq_pkcs11(&env)
            .args(["cert-revoke"])
            .args(["--key-label", &env.ec_label])
            .args(["--creation-time", STABLE_TIME])
            .args(["--reason", cli_reason])
            .args(["--message", message])
            .args(["--revocation-time", revocation_time])
            .args(["--output"])
            .arg(&revocation)
            .assert()
            .success();

        let sig = parse_signature_file(&revocation);

        let (code, reason_bytes) = sig
            .reason_for_revocation()
            .unwrap_or_else(|| panic!("reason subpacket missing in {cli_reason} revocation"));
        assert_eq!(code, expected_code, "reason code mismatch for {cli_reason}");
        assert_eq!(
            reason_bytes,
            message.as_bytes(),
            "reason message mismatch for {cli_reason}"
        );

        let creation = sig
            .signature_creation_time()
            .expect("signature creation time present");
        let expected = humantime::parse_rfc3339(revocation_time).unwrap();
        assert_eq!(
            creation, expected,
            "signature creation time mismatch for {cli_reason}"
        );
    }
}

// ---------------------------------------------------------------------------
// Binary revocation: the --binary path also produces strict-parseable
// packets that GPG accepts and treats as revocation.
// ---------------------------------------------------------------------------

#[test]
fn binary_revocation_outputs_are_packets_accepted_by_gpg() {
    use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
    use sequoia_openpgp::Packet;

    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.asc");
    let cert_revocation = tmp.path().join("cert-rev.bin");
    let subkey_revocation = tmp.path().join("sub-rev.bin");
    let home = fresh_gpg_home(&tmp);

    // Two-tier cert so we can revoke both tiers.
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Bin Revoke <br@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();

    sq_pkcs11(&env)
        .args(["cert-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "superseded"])
        .args(["--message", "binary revocation"])
        .args(["--binary"])
        .args(["--output"])
        .arg(&cert_revocation)
        .assert()
        .success();

    let subkey_fpr = subkey_fingerprint_hex(&cert_path);
    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert_path)
        .args(["--subkey-fingerprint", &subkey_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--message", "binary revocation"])
        .args(["--binary"])
        .args(["--output"])
        .arg(&subkey_revocation)
        .assert()
        .success();

    for (path, label) in [
        (&cert_revocation, "cert-revoke --binary"),
        (&subkey_revocation, "subkey-revoke --binary"),
    ] {
        let bytes = std::fs::read(path).expect("read binary revocation");
        // Binary output must not be ASCII-armored.
        assert!(
            !bytes.starts_with(b"-----BEGIN"),
            "{label} produced armored output despite --binary"
        );
        // Strict parser accepts it as exactly one Signature packet.
        let mut ppr = PacketParser::from_bytes(&bytes).unwrap_or_else(|e| panic!("{label}: {e}"));
        let mut count = 0;
        while let PacketParserResult::Some(pp) = ppr {
            let (packet, next) = pp.recurse().expect("packet recurse");
            assert!(
                matches!(packet, Packet::Signature(_)),
                "{label}: expected Signature, got {packet:?}"
            );
            count += 1;
            ppr = next;
        }
        assert_eq!(count, 1, "{label}: expected one packet");
    }

    // GPG accepts the binary revocations and marks the appropriate tiers.
    gpg_in(&home)
        .arg("--import")
        .arg(&cert_path)
        .assert_success();
    gpg_in(&home)
        .arg("--import")
        .arg(&cert_revocation)
        .assert_success();
    gpg_in(&home)
        .arg("--import")
        .arg(&subkey_revocation)
        .assert_success();

    let listing = gpg_in(&home)
        .args(["--list-keys", "--with-colons"])
        .output()
        .expect("gpg --list-keys");
    assert!(listing.status.success());
    let listing_s = String::from_utf8_lossy(&listing.stdout);
    let pub_line = listing_s
        .lines()
        .find(|l| l.starts_with("pub:"))
        .expect("pub: line");
    let pub_validity = pub_line.split(':').nth(1).unwrap_or("");
    assert!(
        pub_validity.contains('r'),
        "primary should be revoked after binary cert-revoke import: {pub_line}"
    );
}

// ---------------------------------------------------------------------------
// Wrong-creation-time negative cases: verifiers must reject artefacts whose
// fingerprint cannot be matched back to the published certificate.
// ---------------------------------------------------------------------------

#[test]
fn wrong_creation_time_invalidates_signature_and_revocations() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.asc");
    let payload = tmp.path().join("payload.txt");
    let signature = tmp.path().join("payload.txt.asc");
    let bad_cert_revocation = tmp.path().join("bad-cert-rev.asc");
    let bad_subkey_revocation = tmp.path().join("bad-subkey-rev.asc");
    let home = fresh_gpg_home(&tmp);

    let t1 = STABLE_TIME; // cert time
    let t2 = "2027-06-15T00:00:00Z"; // wrong time

    std::fs::write(&payload, b"wrong-time payload\n").unwrap();

    // Build two-tier cert at T1 and import.
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "WrongTime <wt@example.com>"])
        .args(["--creation-time", t1])
        .args(["--subkey-creation-time", t1])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();
    gpg_in(&home)
        .arg("--import")
        .arg(&cert_path)
        .assert_success();

    // 1. Sign with subkey at T2 instead of T1 — verification must fail.
    sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.subkey_label])
        .args(["--creation-time", t2])
        .arg(&payload)
        .assert()
        .success();
    let verify = gpg_in(&home)
        .arg("--verify")
        .arg(&signature)
        .arg(&payload)
        .output()
        .expect("gpg --verify");
    assert!(
        !verify.status.success(),
        "verification must fail when sign --creation-time disagrees with cert; \
         stderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    // 2. cert-revoke with creation-time T2 must not revoke the T1 primary.
    sq_pkcs11(&env)
        .args(["cert-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--creation-time", t2])
        .args(["--reason", "superseded"])
        .args(["--message", "wrong-time revocation"])
        .args(["--output"])
        .arg(&bad_cert_revocation)
        .assert()
        .success();
    // GPG may reject the import outright (mismatched issuer) or import-and-ignore.
    // Either way, the imported public cert must not show 'r' on the pub: line.
    let _ = gpg_in(&home)
        .arg("--import")
        .arg(&bad_cert_revocation)
        .output();
    let listing = gpg_in(&home)
        .args(["--list-keys", "--with-colons"])
        .output()
        .expect("gpg --list-keys");
    let listing_s = String::from_utf8_lossy(&listing.stdout);
    let pub_line = listing_s
        .lines()
        .find(|l| l.starts_with("pub:"))
        .expect("pub: line");
    let pub_validity = pub_line.split(':').nth(1).unwrap_or("");
    assert!(
        !pub_validity.contains('r'),
        "primary must not be marked revoked by a T2 revocation against a T1 cert; pub: {pub_line}"
    );

    // 3. subkey-revoke against a subkey fingerprint that does not appear
    //    in the input cert must fail without producing output.  This is
    //    the new analogue of the old "wrong subkey-creation-time" check:
    //    in the post-fix API the subkey is identified by fingerprint
    //    inside the cert, so a wrong fingerprint is the failure mode the
    //    operator can mis-issue.
    let bogus_fpr = "0000000000000000000000000000000000000000";
    let assert = sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&cert_path)
        .args(["--subkey-fingerprint", bogus_fpr])
        .args(["--creation-time", t1])
        .args(["--reason", "compromised"])
        .args(["--message", "wrong-fingerprint subkey revocation"])
        .args(["--output"])
        .arg(&bad_subkey_revocation)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("no subkey") || stderr.contains("matches"),
        "expected 'no subkey ... matches' error, got: {stderr}"
    );
    assert!(
        !bad_subkey_revocation.exists(),
        "subkey-revoke must not write an output file when the fingerprint is wrong"
    );
    // Suppress the unused t2 binding warning (was used in the old subcase).
    let _ = t2;
}

// ---------------------------------------------------------------------------
// Merge guard: refuse cert-export --merge-cert when the HSM-derived primary
// fingerprint disagrees with the existing cert's primary fingerprint.
// ---------------------------------------------------------------------------

#[test]
fn merge_cert_refuses_duplicate_subkey() {
    // Re-running cert-export --merge-cert with the SAME subkey label
    // and SAME --subkey-creation-time as one already bound in the
    // input cert is almost always an operator mistake — a real
    // rotation needs a distinct fingerprint.  Refuse loudly.
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_v1 = tmp.path().join("cert-v1.asc");
    let cert_v2 = tmp.path().join("cert-v2.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Dup Subkey <dup@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_v1)
        .assert()
        .success();

    // Same subkey, same creation time → would produce identical
    // fingerprint.  Must be rejected.
    let assert = sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--merge-cert"])
        .arg(&cert_v1)
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_v2)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("already bound") || stderr.contains("no-op"),
        "expected duplicate-subkey rejection, got: {stderr}"
    );
    assert!(
        !cert_v2.exists(),
        "duplicate-merge must not write an output cert"
    );
}

#[test]
fn merge_cert_refuses_wrong_primary_creation_time() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_v1 = tmp.path().join("cert-v1.asc");
    let cert_v2 = tmp.path().join("cert-v2.asc");

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "MergeGuard <mg@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_v1)
        .assert()
        .success();

    let assert = sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--merge-cert"])
        .arg(&cert_v1)
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey2_label])
        .args(["--creation-time", "2030-01-01T00:00:00Z"]) // wrong primary time
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_v2)
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr
            .to_lowercase()
            .contains("primary fingerprint mismatch"),
        "expected 'primary fingerprint mismatch' in stderr, got: {stderr}"
    );
    assert!(
        !cert_v2.exists(),
        "merge must not write an output file when the fingerprint check fails"
    );
}

// ---------------------------------------------------------------------------
// Selector forms: --key-label, --key-id, --key-uri all resolve to the same
// underlying private key.
// ---------------------------------------------------------------------------

#[test]
fn key_selector_forms_resolve_same_key() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let by_label = tmp.path().join("by-label.asc");
    let by_id = tmp.path().join("by-id.asc");
    let by_uri = tmp.path().join("by-uri.asc");

    // Pick a label whose key actually has a CKA_ID populated.  nShield
    // sometimes leaves CKA_ID empty (notably on EC keys generated via
    // `generatekey pkcs11`), in which case the --key-id selector is
    // inapplicable.  Prefer the EC key when it has an id (preserves the
    // original test intent), but fall back to the RSA / primary keys.
    let candidates = [
        ("EC", &env.ec_label),
        ("RSA", &env.rsa_label),
        ("primary", &env.primary_label),
    ];
    let (kind, label, id_hex) = candidates
        .iter()
        .find_map(|(kind, label)| cka_id_for_label(&env, label).map(|id| (*kind, *label, id)))
        .unwrap_or_else(|| {
            panic!(
                "no test key has a populated CKA_ID — re-generate at least one of \
                 {:?} with a non-empty id so the --key-id selector can be exercised",
                candidates.iter().map(|(_, l)| l).collect::<Vec<_>>(),
            )
        });
    eprintln!("key_selector_forms_resolve_same_key: using {kind} key {label:?} (id={id_hex})");

    let uri = format!("pkcs11:object={};type=private", label);
    let userid = "Selector <sel@example.com>";

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", label])
        .args(["--userid", userid])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&by_label)
        .assert()
        .success();

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-id", &id_hex])
        .args(["--userid", userid])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&by_id)
        .assert()
        .success();

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-uri", &uri])
        .args(["--userid", userid])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&by_uri)
        .assert()
        .success();

    let fpr_label = parse_cert_file(&by_label).fingerprint();
    let fpr_id = parse_cert_file(&by_id).fingerprint();
    let fpr_uri = parse_cert_file(&by_uri).fingerprint();
    assert_eq!(fpr_label, fpr_id, "label and id must resolve same key");
    assert_eq!(fpr_label, fpr_uri, "label and uri must resolve same key");
}

// ---------------------------------------------------------------------------
// --auto must fail with a clear error when multiple usable keys are visible.
// ---------------------------------------------------------------------------

#[test]
fn auto_selector_with_multiple_keys_fails() {
    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert = tmp.path().join("cert.asc");

    let assert = sq_pkcs11(&env)
        .args(["cert-export"])
        .arg("--auto")
        .args(["--userid", "Ambiguous <amb@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert)
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_lowercase();
    assert!(
        stderr.contains("ambiguous"),
        "expected 'ambiguous' in stderr when --auto sees multiple keys, got: {stderr}"
    );
    assert!(
        !cert.exists(),
        "ambiguous --auto must not produce an output cert"
    );
}

// ---------------------------------------------------------------------------
// stdout output: subcommands write OpenPGP data to stdout when --output is
// omitted, with diagnostics on stderr.
// ---------------------------------------------------------------------------

#[test]
fn subcommands_write_to_stdout_when_output_omitted() {
    use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
    use sequoia_openpgp::Packet;

    let env = require_env!();

    // 1. cert-export (armored) — stdout starts with armor BEGIN.
    let assert = sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.ec_label])
        .args(["--userid", "Stdout <so@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .assert()
        .success();
    let out = assert.get_output();
    let stdout = String::from_utf8(out.stdout.clone()).expect("stdout UTF-8");
    assert!(
        stdout.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        "armored cert-export stdout did not start with PGP armor:\n{stdout}"
    );
    // Diagnostics, if any, must not contain OpenPGP packet bytes on stderr.
    assert!(
        !out.stderr.starts_with(b"-----BEGIN") && !out.stderr.starts_with(&[0x80]),
        "stderr leaked OpenPGP data"
    );

    // 2. cert-export --binary — stdout parses as a strict OpenPGP packet stream
    //    containing a PublicKey packet.
    let assert = sq_pkcs11(&env)
        .args(["cert-export", "--binary"])
        .args(["--key-label", &env.ec_label])
        .args(["--userid", "Stdout <so@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .assert()
        .success();
    let bytes = assert.get_output().stdout.clone();
    assert!(
        !bytes.starts_with(b"-----BEGIN"),
        "--binary stdout was armored"
    );
    let mut ppr = PacketParser::from_bytes(&bytes).expect("parse cert-export --binary stdout");
    let mut saw_public_key = false;
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next) = pp.recurse().expect("packet recurse");
        if matches!(packet, Packet::PublicKey(_)) {
            saw_public_key = true;
        }
        ppr = next;
    }
    assert!(saw_public_key, "binary cert-export stdout had no PublicKey");

    // 3. cert-revoke — stdout is a single Signature packet (armored).
    let assert = sq_pkcs11(&env)
        .args(["cert-revoke"])
        .args(["--key-label", &env.ec_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "unspecified"])
        .args(["--message", "stdout test"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout UTF-8");
    assert!(
        stdout.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        "cert-revoke stdout was not armored:\n{stdout}"
    );
    let mut ppr = PacketParser::from_bytes(stdout.as_bytes()).expect("dearmor cert-revoke stdout");
    let mut sigs = 0;
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next) = pp.recurse().expect("packet recurse");
        if matches!(packet, Packet::Signature(_)) {
            sigs += 1;
        }
        ppr = next;
    }
    assert_eq!(sigs, 1, "cert-revoke stdout must be exactly one Signature");

    // 4. subkey-revoke — same shape.  Need a cert + subkey fingerprint
    //    for the new API.
    let tmp = TempDir::new().unwrap();
    let stdout_cert = tmp.path().join("stdout-cert.asc");
    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Stdout <so@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&stdout_cert)
        .assert()
        .success();
    let subkey_fpr = subkey_fingerprint_hex(&stdout_cert);
    let assert = sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--input-cert"])
        .arg(&stdout_cert)
        .args(["--subkey-fingerprint", &subkey_fpr])
        .args(["--creation-time", STABLE_TIME])
        .args(["--reason", "unspecified"])
        .args(["--message", "stdout test"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout UTF-8");
    let mut ppr =
        PacketParser::from_bytes(stdout.as_bytes()).expect("dearmor subkey-revoke stdout");
    let mut sigs = 0;
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next) = pp.recurse().expect("packet recurse");
        if matches!(packet, Packet::Signature(_)) {
            sigs += 1;
        }
        ppr = next;
    }
    assert_eq!(
        sigs, 1,
        "subkey-revoke stdout must be exactly one Signature"
    );
}

// ---------------------------------------------------------------------------
// Issuer of an artefact signature must be the subkey, not the primary.
// ---------------------------------------------------------------------------

#[test]
fn signature_issuer_is_the_subkey_in_two_tier_cert() {
    use sequoia_openpgp::policy::StandardPolicy;

    let env = require_env!();
    let tmp = TempDir::new().unwrap();
    let cert_path = tmp.path().join("cert.asc");
    let payload = tmp.path().join("p.txt");
    let signature_path = tmp.path().join("p.txt.asc");

    std::fs::write(&payload, b"issuer test\n").unwrap();

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--userid", "Issuer <iss@example.com>"])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--output"])
        .arg(&cert_path)
        .assert()
        .success();

    sq_pkcs11(&env)
        .args(["sign"])
        .args(["--key-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .arg(&payload)
        .assert()
        .success();

    let cert = parse_cert_file(&cert_path);
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).expect("cert is valid");
    let primary_fpr = valid.primary_key().key().fingerprint();
    let subkey_fpr = valid
        .keys()
        .subkeys()
        .next()
        .expect("subkey present")
        .key()
        .fingerprint();

    let sig = parse_signature_file(&signature_path);
    let issuer_fprs: Vec<_> = sig.issuer_fingerprints().cloned().collect();
    assert!(
        issuer_fprs.iter().any(|f| f == &subkey_fpr),
        "signature issuer must be the subkey {subkey_fpr}, got {issuer_fprs:?}"
    );
    assert!(
        issuer_fprs.iter().all(|f| f != &primary_fpr),
        "signature must not be issued by the primary {primary_fpr}, got {issuer_fprs:?}"
    );
}

// ---------------------------------------------------------------------------
// Tiny extension trait so we can write `.assert_success()` on std::Command.
// ---------------------------------------------------------------------------

trait AssertSuccess {
    fn assert_success(&mut self);
}
impl AssertSuccess for StdCommand {
    fn assert_success(&mut self) {
        let out = self.output().expect("command failed to spawn");
        assert!(
            out.status.success(),
            "command exited {:?}\nstdout: {}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}
