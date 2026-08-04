"""cert-export: certificate construction, two-tier structure, rotation."""

from __future__ import annotations

from pathlib import Path

import pytest

import _inspect as sq_inspect
from conftest import STABLE_TIME, Gpg, Pkcs11Config, SqPkcs11

pytestmark = pytest.mark.pkcs11


# ---------------------------------------------------------------------------
# Basic export
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["rsa", "ec"])
def test_cert_export_produces_armored_block(export_cert, key: str):
    cert = export_cert(key, userid=f"Test {key} <{key}@example.com>")
    text = cert.read_text()
    assert text.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert "-----END PGP PUBLIC KEY BLOCK-----" in text


def test_cert_export_refuses_to_overwrite_existing_output_without_force(
    sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    cert = work / "cert.asc"
    cert.write_bytes(b"PRECIOUS PUBLISHED CERT\n")
    original = cert.read_bytes()

    result = sqp11.run(
        "cert-export",
        "--key-label",
        pkcs11.rsa,
        "--userid",
        "Overwrite Test <ow@example.com>",
        "--creation-time",
        STABLE_TIME,
        "--output",
        cert,
    ).failure()
    assert "refusing to overwrite" in result.stderr
    assert cert.read_bytes() == original

    sqp11.run(
        "cert-export",
        "--force",
        "--key-label",
        pkcs11.rsa,
        "--userid",
        "Overwrite Test <ow@example.com>",
        "--creation-time",
        STABLE_TIME,
        "--output",
        cert,
    ).success()
    assert cert.read_text().startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")


def test_cert_export_requires_creation_times(sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path):
    """No epoch default: a cert published with a placeholder timestamp is permanent."""
    result = sqp11.run(
        "cert-export",
        "--key-label",
        pkcs11.rsa,
        "--userid",
        "No Time <nt@example.com>",
        "--output",
        work / "a.asc",
    ).failure()
    assert "--creation-time is required" in result.stderr

    # With a subkey selected, the subkey's own creation time is required too:
    # it is an independent value that every later `sign` for that subkey has
    # to repeat.
    result = sqp11.run(
        "cert-export",
        "--key-label",
        pkcs11.primary,
        "--subkey-label",
        pkcs11.subkey,
        "--userid",
        "No Subkey Time <nst@example.com>",
        "--creation-time",
        STABLE_TIME,
        "--output",
        work / "b.asc",
    ).failure()
    assert "--subkey-creation-time is required" in result.stderr


# ---------------------------------------------------------------------------
# Fingerprint stability
# ---------------------------------------------------------------------------


def test_fingerprint_stable_across_runs(export_cert):
    a = export_cert("ec", name="a.asc", userid="Test <stable@example.com>")
    b = export_cert("ec", name="b.asc", userid="Test <stable@example.com>")
    assert sq_inspect.primary_fingerprint(a) == sq_inspect.primary_fingerprint(b), (
        "same key + same --creation-time must yield the same fingerprint"
    )


def test_fingerprint_changes_with_creation_time(export_cert):
    a = export_cert("ec", name="a.asc", creation_time="2026-01-01T00:00:00Z")
    b = export_cert("ec", name="b.asc", creation_time="2030-01-01T00:00:00Z")
    assert sq_inspect.primary_fingerprint(a) != sq_inspect.primary_fingerprint(b), (
        "different --creation-time values must yield different fingerprints"
    )


# ---------------------------------------------------------------------------
# Validity periods
# ---------------------------------------------------------------------------


@pytest.mark.gpg
def test_validity_period_appears_in_cert(export_cert, gpg: Gpg):
    cert = export_cert(
        "ec", userid="Validity Test <v@example.com>", extra=["--validity-period", "1y"]
    )
    lines = gpg.colons("--show-keys", cert)
    # Column 7 (index 6) of the pub: line is the expiry timestamp.
    expiry = gpg.field(lines, "pub", 6)
    assert expiry not in ("", "0"), f"expected a non-zero expiry, got {expiry!r}"


@pytest.mark.gpg
def test_validity_periods_are_recorded_in_signatures(export_cert, gpg: Gpg):
    """A long-lived primary and a short-lived subkey, as recommended."""
    cert_path = export_cert(
        "primary",
        subkey="subkey",
        userid="Validity Two-Tier <vt@example.com>",
        extra=["--validity-period", "10y", "--subkey-validity-period", "1y"],
    )

    # Sequoia's view: with a creation time of 2026-01-01, `10y` and `1y` land
    # on exact calendar anniversaries, so the expected values can be named
    # rather than computed with a tolerance.
    primary, subkey = sq_inspect.inspected_keys(cert_path)
    assert not primary.is_subkey and subkey.is_subkey
    assert primary.creation_time.startswith("2026-01-01")
    assert primary.expiration_time.startswith("2036-01-01"), (
        f"primary should expire 10y after creation, got {primary.expiration_time!r}"
    )
    assert subkey.expiration_time.startswith("2027-01-01"), (
        f"subkey should expire 1y after creation, got {subkey.expiration_time!r}"
    )

    # GnuPG view: both expiries are set, and the primary outlives the subkey.
    gpg.import_(cert_path)
    lines = gpg.list_keys()
    pub_expiry = int(gpg.field(lines, "pub", 6))
    sub_expiry = int(gpg.field(lines, "sub", 6))
    assert pub_expiry > 0, "primary expiry must be set"
    assert sub_expiry > 0, "subkey expiry must be set"
    assert pub_expiry > sub_expiry, (
        f"primary should outlive subkey: {pub_expiry} vs {sub_expiry}"
    )


# ---------------------------------------------------------------------------
# Two-tier structure
# ---------------------------------------------------------------------------


def test_two_tier_cert_has_only_certify_primary_and_signing_subkey(export_cert):
    """The capability split is the whole point of the two-tier layout.

    A primary that could also sign would let an OCS-quorum key be used for
    unattended signing; a subkey that could certify could bind further keys.
    """
    cert_path = export_cert(
        "primary",
        subkey="subkey",
        userid="Caps Test <caps@example.com>",
        extra=["--validity-period", "10y", "--subkey-validity-period", "1y"],
    )
    primary, subkey = sq_inspect.inspected_keys(cert_path)

    assert primary.key_flags == ["certification"], (
        "the primary must be able to certify and nothing else — a primary that "
        f"could sign would let an OCS-quorum key sign unattended; got "
        f"{primary.key_flags}"
    )
    assert subkey.key_flags == ["signing"], (
        "the subkey must be able to sign and nothing else — a subkey that could "
        f"certify could bind further keys; got {subkey.key_flags}"
    )
    assert len(sq_inspect.subkey_fingerprints(cert_path)) == 1

    # A signing subkey needs a cross-signature or a verifier should reject it;
    # this is what stops the subkey being hijacked into another cert.
    dump = sq_inspect.dump(cert_path)
    types = sq_inspect.field_lines(dump, "Type")
    assert any("SubkeyBinding" in line for line in types), types
    assert any("PrimaryKeyBinding" in line for line in types), (
        f"the subkey binding carries no cross-signature: {types}"
    )


@pytest.mark.gpg
def test_two_tier_cert_export_and_subkey_sign(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, gpg: Gpg, work: Path
):
    cert = export_cert(
        "primary",
        subkey="subkey",
        userid="Two-Tier <2t@example.com>",
        extra=["--validity-period", "10y", "--subkey-validity-period", "2y"],
    )
    payload = work / "p.txt"
    payload.write_bytes(b"two-tier payload\n")

    gpg.import_(cert)
    lines = gpg.list_keys()
    # GnuPG distinguishes per-key (lowercase) from cert-wide (uppercase)
    # capabilities in column 12; check the per-key ones.
    pub_caps = gpg.field(lines, "pub", 11)
    sub_caps = gpg.field(lines, "sub", 11)
    assert "c" in pub_caps, f"primary should have per-key certify, caps={pub_caps!r}"
    assert "s" not in pub_caps, f"primary must not have per-key sign, caps={pub_caps!r}"
    assert "s" in sub_caps, f"subkey should have per-key sign, caps={sub_caps!r}"

    sqp11.run(
        "sign",
        "--key-label",
        pkcs11.subkey,
        "--creation-time",
        STABLE_TIME,
        payload,
    ).success()

    result = gpg.run("--verify", work / "p.txt.asc", payload)
    result.success()
    assert "Good signature" in result.stderr


# ---------------------------------------------------------------------------
# Rotation via --merge-cert
# ---------------------------------------------------------------------------


@pytest.mark.gpg
def test_merge_cert_preserves_old_subkey(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, gpg: Gpg, work: Path
):
    """Rotation must not invalidate signatures made by the outgoing subkey."""
    payload_old = work / "old.txt"
    payload_new = work / "new.txt"
    payload_old.write_bytes(b"signed by old subkey\n")
    payload_new.write_bytes(b"signed by new subkey\n")

    cert_v1 = export_cert(
        "primary",
        subkey="subkey",
        userid="Rotation Test <rot@example.com>",
        name="cert-v1.asc",
    )

    sqp11.run(
        "sign",
        "--key-label",
        pkcs11.subkey,
        "--creation-time",
        STABLE_TIME,
        payload_old,
    ).success()

    # A creation time distinct from STABLE_TIME, so the new subkey gets its own
    # fingerprint, but still in the past: gpg rejects a signature made before
    # its signing key claims to exist.
    new_subkey_time = "2026-01-01T06:00:00Z"
    cert_v2 = export_cert(
        "primary",
        subkey="subkey2",
        subkey_creation_time=new_subkey_time,
        userid="",  # merge mode keeps the existing UIDs
        merge=cert_v1,
        name="cert-v2.asc",
    )

    sqp11.run(
        "sign",
        "--key-label",
        pkcs11.subkey2,
        "--creation-time",
        new_subkey_time,
        payload_new,
    ).success()

    merged_subkeys = sq_inspect.subkey_fingerprints(cert_v2)
    assert len(merged_subkeys) == 2, (
        f"merged cert must keep both subkeys, found {merged_subkeys}"
    )

    gpg.import_(cert_v2)
    lines = gpg.list_keys()
    assert len([line for line in lines if line.startswith("sub:")]) == 2

    for sig, payload, label in (
        (work / "old.txt.asc", payload_old, "old subkey"),
        (work / "new.txt.asc", payload_new, "new subkey"),
    ):
        result = gpg.run("--verify", sig, payload)
        result.success()
        assert "Good signature" in result.stderr, f"failed for {label}"


def test_merge_cert_refuses_duplicate_subkey(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """Re-binding the same subkey at the same time is a no-op and a mistake.

    A real rotation needs a distinct fingerprint; silently adding a second
    identical binding would bloat the cert and hide the operator's error.
    """
    cert_v1 = export_cert(
        "primary",
        subkey="subkey",
        userid="Dup Subkey <dup@example.com>",
        name="cert-v1.asc",
    )
    cert_v2 = work / "cert-v2.asc"
    result = sqp11.run(
        "cert-export",
        "--merge-cert",
        cert_v1,
        "--key-label",
        pkcs11.primary,
        "--subkey-label",
        pkcs11.subkey,
        "--creation-time",
        STABLE_TIME,
        "--subkey-creation-time",
        STABLE_TIME,
        "--output",
        cert_v2,
    ).failure()
    assert "already bound" in result.stderr or "no-op" in result.stderr, result.stderr
    assert not cert_v2.exists(), "duplicate merge must not write an output cert"


def test_merge_cert_refuses_wrong_primary_creation_time(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """The primary fingerprint is the cert's identity; merging across two is refused."""
    cert_v1 = export_cert(
        "primary",
        subkey="subkey",
        userid="MergeGuard <mg@example.com>",
        name="cert-v1.asc",
    )
    cert_v2 = work / "cert-v2.asc"
    result = sqp11.run(
        "cert-export",
        "--merge-cert",
        cert_v1,
        "--key-label",
        pkcs11.primary,
        "--subkey-label",
        pkcs11.subkey2,
        "--creation-time",
        "2030-01-01T00:00:00Z",  # wrong primary time
        "--subkey-creation-time",
        STABLE_TIME,
        "--output",
        cert_v2,
    ).failure()
    assert "primary fingerprint mismatch" in result.stderr.lower()
    assert not cert_v2.exists(), "a failed merge must not write an output file"
