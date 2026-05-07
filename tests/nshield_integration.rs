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
use std::sync::Once;

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

/// Load `tests/nshield/test.env` into the process environment exactly once,
/// then read the labels we need.  Returns `Err(reason)` when the suite
/// cannot run — typically because `tests/nshield/test.env` is absent (CI
/// machines, dev workstations without an HSM) or because the configured
/// PKCS#11 module file does not exist (vendor client not installed).
/// Rust's `libtest` has no native "skipped" status, so the calling test
/// prints `reason` on stderr and early-returns; the line shows up in CI
/// logs even though the test still reports as "ok".
fn test_env() -> Result<TestEnv, &'static str> {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let env_file: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "nshield", "test.env"]
            .iter()
            .collect();
        let _ = dotenvy::from_path(&env_file);
    });

    let module_path = std::env::var("PKCS11_MODULE_PATH").map_err(|_| {
        "PKCS11_MODULE_PATH not set (tests/nshield/test.env missing or incomplete?)"
    })?;
    if !Path::new(&module_path).exists() {
        return Err("PKCS#11 module file from PKCS11_MODULE_PATH does not exist (nShield client not installed?)");
    }

    let var = |name: &str, missing: &'static str| std::env::var(name).map_err(move |_| missing);
    Ok(TestEnv {
        module_path,
        rsa_label: var(
            "SQ_PKCS11_NSHIELD_TEST_RSA",
            "SQ_PKCS11_NSHIELD_TEST_RSA not set in tests/nshield/test.env",
        )?,
        ec_label: var(
            "SQ_PKCS11_NSHIELD_TEST_EC",
            "SQ_PKCS11_NSHIELD_TEST_EC not set in tests/nshield/test.env",
        )?,
        primary_label: var(
            "SQ_PKCS11_NSHIELD_TEST_PRIMARY",
            "SQ_PKCS11_NSHIELD_TEST_PRIMARY not set in tests/nshield/test.env",
        )?,
        subkey_label: var(
            "SQ_PKCS11_NSHIELD_TEST_SUBKEY",
            "SQ_PKCS11_NSHIELD_TEST_SUBKEY not set in tests/nshield/test.env",
        )?,
        subkey2_label: var(
            "SQ_PKCS11_NSHIELD_TEST_SUBKEY2",
            "SQ_PKCS11_NSHIELD_TEST_SUBKEY2 not set in tests/nshield/test.env",
        )?,
    })
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

    // Revoke only the subkey.
    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
        .args(["--reason", "compromised"])
        .args(["--message", "subkey lost"])
        .args(["--output"])
        .arg(&revocation)
        .assert()
        .success();

    gpg_in(&home).arg("--import").arg(&cert).assert_success();
    gpg_in(&home)
        .arg("--import")
        .arg(&revocation)
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
    let new_subkey_time = "2026-06-01T00:00:00Z";
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
    let cert_revocation = tmp.path().join("cert-revocation.asc");
    let subkey_revocation = tmp.path().join("subkey-revocation.asc");

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

    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
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

/// Use `sq-pkcs11 list-keys` to discover the CKA_ID for a given CKA_LABEL.
/// Output line format: `  label="..."  id=HEX  type=...`.
fn cka_id_for_label(env: &TestEnv, label: &str) -> String {
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
                return id.to_string();
            }
        }
    }
    panic!("could not find id for label {label} in list-keys output:\n{stdout}");
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
    // 1-day tolerance covers any rounding inside the years→seconds conversion.
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

    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
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

    // 3. subkey-revoke with subkey creation-time T2 must not revoke the T1 subkey.
    sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--creation-time", t1])
        .args(["--subkey-creation-time", t2])
        .args(["--reason", "compromised"])
        .args(["--message", "wrong-time subkey revocation"])
        .args(["--output"])
        .arg(&bad_subkey_revocation)
        .assert()
        .success();
    let _ = gpg_in(&home)
        .arg("--import")
        .arg(&bad_subkey_revocation)
        .output();
    let listing = gpg_in(&home)
        .args(["--list-keys", "--with-colons"])
        .output()
        .expect("gpg --list-keys");
    let listing_s = String::from_utf8_lossy(&listing.stdout);
    let sub_line = listing_s
        .lines()
        .find(|l| l.starts_with("sub:"))
        .expect("sub: line");
    let sub_validity = sub_line.split(':').nth(1).unwrap_or("");
    assert!(
        !sub_validity.contains('r'),
        "subkey must not be marked revoked by a T2 revocation against a T1 subkey; sub: {sub_line}"
    );
}

// ---------------------------------------------------------------------------
// Merge guard: refuse cert-export --merge-cert when the HSM-derived primary
// fingerprint disagrees with the existing cert's primary fingerprint.
// ---------------------------------------------------------------------------

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

    let id_hex = cka_id_for_label(&env, &env.ec_label);
    let uri = format!("pkcs11:object={};type=private", env.ec_label);

    let userid = "Selector <sel@example.com>";

    sq_pkcs11(&env)
        .args(["cert-export"])
        .args(["--key-label", &env.ec_label])
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

    // 4. subkey-revoke — same shape.
    let assert = sq_pkcs11(&env)
        .args(["subkey-revoke"])
        .args(["--key-label", &env.primary_label])
        .args(["--subkey-label", &env.subkey_label])
        .args(["--creation-time", STABLE_TIME])
        .args(["--subkey-creation-time", STABLE_TIME])
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
