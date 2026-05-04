//! Integration tests for Entrust nShield (Security World, FIPS 140-3 mode).
//!
//! NSHIELD-SPECIFIC: these tests assume the nShield client tooling
//! (`generatekey`, `nfkminfo`, `gpg`) is available, that `PKCS11_MODULE_PATH`
//! points at `libcknfast.so`, and that the test keys exist (see
//! `tests/nshield/README.md` for provisioning).
//!
//! All tests skip silently when `tests/nshield/test.env` is absent or
//! incomplete, so this file is safe to compile and run on a developer
//! machine without an HSM.

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
/// then read the labels we need.  Returns `None` if the file is missing or
/// any required variable is unset — the calling test will print a skip
/// message and return.
fn test_env() -> Option<TestEnv> {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let env_file: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "nshield", "test.env"]
            .iter()
            .collect();
        let _ = dotenvy::from_path(&env_file);
    });

    Some(TestEnv {
        module_path: std::env::var("PKCS11_MODULE_PATH").ok()?,
        rsa_label: std::env::var("SQ_PKCS11_NSHIELD_TEST_RSA").ok()?,
        ec_label: std::env::var("SQ_PKCS11_NSHIELD_TEST_EC").ok()?,
        primary_label: std::env::var("SQ_PKCS11_NSHIELD_TEST_PRIMARY").ok()?,
        subkey_label: std::env::var("SQ_PKCS11_NSHIELD_TEST_SUBKEY").ok()?,
        subkey2_label: std::env::var("SQ_PKCS11_NSHIELD_TEST_SUBKEY2").ok()?,
    })
}

/// Macro to bail out cleanly when the env isn't available.
macro_rules! require_env {
    () => {
        match test_env() {
            Some(e) => e,
            None => {
                eprintln!(
                    "skipping: tests/nshield/test.env not present or incomplete \
                     — see tests/nshield/README.md"
                );
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
