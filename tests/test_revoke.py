"""cert-revoke and subkey-revoke.

Both produce a standalone revocation signature.  The recurring theme in these
tests is that a revocation aimed at the wrong fingerprint is *silently
useless* — it is a valid signature over a key nobody has — so the interesting
assertions are about refusing to produce one, and about which tier a
successful one actually marks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import _inspect as sq_inspect
from conftest import STABLE_TIME, Gpg, Pkcs11Config, Sq, SqPkcs11, concat

pytestmark = pytest.mark.pkcs11

REASONS = [
    ("unspecified", "no reason"),
    ("superseded", "rotated to fresh key"),
    ("compromised", "smartcard lost in transit"),
    ("retired", "service decommissioned"),
]


def _subkey_fpr(cert: Path) -> str:
    return sq_inspect.only_subkey_fingerprint(cert)


# ---------------------------------------------------------------------------
# cert-revoke
# ---------------------------------------------------------------------------


@pytest.mark.gpg
def test_cert_revoke_marks_primary_revoked(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, gpg: Gpg, work: Path
):
    cert = export_cert("ec", userid="Revoke Test <revoke@example.com>")
    revocation = work / "revocation.asc"

    sqp11.run(
        "cert-revoke",
        "--key-label",
        pkcs11.ec,
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "superseded",
        "--message",
        "test rotation",
        "--output",
        revocation,
    ).success()

    gpg.import_(cert)
    gpg.import_(revocation)
    # Column 2 of the pub: line carries 'r' when the key is revoked.
    validity = gpg.field(gpg.list_keys(), "pub", 1)
    assert "r" in validity, f"expected the primary to be revoked, validity={validity!r}"


@pytest.mark.sq
@pytest.mark.parametrize(("cli_reason", "message"), REASONS)
def test_revocation_signature_records_reason_message_and_time(
    sqp11: SqPkcs11,
    pkcs11: Pkcs11Config,
    work: Path,
    cli_reason: str,
    message: str,
):
    revocation_time = "2026-07-15T12:34:56Z"
    revocation = work / f"rev-{cli_reason}.asc"

    sqp11.run(
        "cert-revoke",
        "--key-label",
        pkcs11.ec,
        "--creation-time",
        STABLE_TIME,
        "--reason",
        cli_reason,
        "--message",
        message,
        "--revocation-time",
        revocation_time,
        "--output",
        revocation,
    ).success()

    text = sq_inspect.assert_one_signature_packet(revocation, f"{cli_reason} revocation")
    assert sq_inspect.field(text, "Type") == "KeyRevocation"
    assert sq_inspect.field(text, "Reason for revocation") == (
        f"{sq_inspect.REASON_TEXT[cli_reason]}, {message}"
    ), f"reason or message wrong for {cli_reason}"
    assert "2026-07-15 12:34:56 UTC" in sq_inspect.signature_creation_time_line(text), (
        "the revocation time must round-trip into the signature creation time"
    )


@pytest.mark.sq
@pytest.mark.parametrize(
    ("label", "timestamp", "rendered"),
    [
        ("future", "2030-12-31T23:59:59Z", "2030-12-31 23:59:59 UTC"),
        ("past_pre_key_creation", "2020-01-01T00:00:00Z", "2020-01-01 00:00:00 UTC"),
        ("epoch", "1970-01-01T00:00:00Z", "1970-01-01 00:00:00 UTC"),
    ],
)
def test_cert_revoke_revocation_time_round_trips_exactly(
    sqp11: SqPkcs11,
    pkcs11: Pkcs11Config,
    work: Path,
    label: str,
    timestamp: str,
    rendered: str,
):
    """Back-dated and scheduled revocations are both legitimate."""
    revocation = work / f"rev-{label}.asc"
    sqp11.run(
        "cert-revoke",
        "--key-label",
        pkcs11.ec,
        "--creation-time",
        STABLE_TIME,
        "--revocation-time",
        timestamp,
        "--reason",
        "superseded",
        "--message",
        label,
        "--output",
        revocation,
    ).success()

    text = sq_inspect.dump(revocation)
    assert rendered in sq_inspect.signature_creation_time_line(text)


def test_cert_revoke_rejects_invalid_revocation_time(
    sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    revocation = work / "rev.asc"
    result = sqp11.run(
        "cert-revoke",
        "--key-label",
        pkcs11.ec,
        "--creation-time",
        STABLE_TIME,
        "--revocation-time",
        "not-a-real-timestamp",
        "--reason",
        "superseded",
        "--output",
        revocation,
    ).failure()
    assert "invalid" in result.stderr or "RFC 3339" in result.stderr
    # The flag that was wrong must be the flag that is named.
    assert "--revocation-time" in result.stderr, result.stderr
    assert not revocation.exists()


def test_cert_revoke_refuses_overwrite_without_force(
    sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    revocation = work / "rev.asc"
    revocation.write_bytes(b"PRECIOUS\n")
    result = sqp11.run(
        "cert-revoke",
        "--key-label",
        pkcs11.ec,
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "superseded",
        "--output",
        revocation,
    ).failure()
    assert "refusing to overwrite" in result.stderr
    assert revocation.read_bytes() == b"PRECIOUS\n"


# ---------------------------------------------------------------------------
# subkey-revoke
# ---------------------------------------------------------------------------


def test_subkey_revoke_works_without_subkey_hsm_access(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """The point of the API: a lost subkey must still be revokable.

    Only the primary's private key is exercised; the subkey is identified by
    fingerprint out of the published cert.  The CLI has no subkey selector on
    this subcommand, so a passing run proves the subkey's secret was never
    consulted — which is what makes the compromise-response path usable.
    """
    revocation = work / "revocation.asc"
    sqp11.run(
        "subkey-revoke",
        "--key-label",
        pkcs11.primary,
        "--input-cert",
        two_tier_cert,
        "--subkey-fingerprint",
        _subkey_fpr(two_tier_cert),
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "compromised",
        "--message",
        "compromised; subkey HSM access not needed",
        "--output",
        revocation,
    ).success()

    text = sq_inspect.assert_one_signature_packet(revocation, "subkey-revoke")
    assert sq_inspect.field(text, "Type") == "SubkeyRevocation"


@pytest.mark.gpg
def test_subkey_revoke_marks_only_subkey_revoked(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config, gpg: Gpg, work: Path
):
    revocation = work / "subkey-revocation.asc"
    sqp11.run(
        "subkey-revoke",
        "--key-label",
        pkcs11.primary,
        "--input-cert",
        two_tier_cert,
        "--subkey-fingerprint",
        _subkey_fpr(two_tier_cert),
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "compromised",
        "--message",
        "subkey lost",
        "--output",
        revocation,
    ).success()

    # GnuPG drops a standalone subkey revocation imported on its own
    # (`Total number processed: 0`) and only attaches it when it arrives in the
    # same stream as the cert — the workaround real consumers must apply.
    combined = concat(work / "cert-with-subkey-revocation.asc", two_tier_cert, revocation)
    gpg.import_(combined)

    lines = gpg.list_keys()
    assert "r" not in gpg.field(lines, "pub", 1), (
        "the primary must not be revoked when only the subkey is"
    )
    assert "r" in gpg.field(lines, "sub", 1), "expected the subkey to be revoked"


def test_subkey_revoke_rejects_input_cert_belonging_to_other_primary(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """Refuse before signing, rather than produce a useless artefact.

    Without this guard the tool would emit a "revocation" signed by primary A
    naming a subkey of cert B: a valid signature that no verifier will ever
    apply, and an HSM operation spent for nothing.
    """
    export_cert("ec", subkey="subkey", userid="Cert A <a@example.com>", name="cert-a.asc")
    cert_b = export_cert(
        "primary", subkey="subkey", userid="Cert B <b@example.com>", name="cert-b.asc"
    )
    revocation = work / "revocation.asc"

    result = sqp11.run(
        "subkey-revoke",
        "--key-label",
        pkcs11.ec,  # primary of cert A
        "--input-cert",
        cert_b,  # cert with a different primary
        "--subkey-fingerprint",
        _subkey_fpr(cert_b),
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "compromised",
        "--message",
        "wrong primary test",
        "--output",
        revocation,
    ).failure()
    assert "primary fingerprint mismatch" in result.stderr
    assert not revocation.exists()


def test_subkey_revoke_refuses_overwrite_without_force_and_force_overwrites(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    revocation = work / "rev.asc"
    revocation.write_bytes(b"PRECIOUS\n")
    fpr = _subkey_fpr(two_tier_cert)
    args = [
        "subkey-revoke",
        "--key-label",
        pkcs11.primary,
        "--input-cert",
        two_tier_cert,
        "--subkey-fingerprint",
        fpr,
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "compromised",
        "--output",
        revocation,
    ]

    result = sqp11.run(*args).failure()
    assert "refusing to overwrite" in result.stderr
    assert revocation.read_bytes() == b"PRECIOUS\n"

    sqp11.run(args[0], "--force", *args[1:]).success()
    assert revocation.read_bytes() != b"PRECIOUS\n"
    assert sq_inspect.field(sq_inspect.dump(revocation), "Type") == "SubkeyRevocation"


def test_subkey_revoke_rejects_malformed_inputs(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    revocation = work / "rev.asc"
    bad_cert = work / "bad-cert.asc"
    primary_fpr = sq_inspect.primary_fingerprint(two_tier_cert)

    def revoke(*, cert: Path, fingerprint: str):
        return sqp11.run(
            "subkey-revoke",
            "--key-label",
            pkcs11.primary,
            "--input-cert",
            cert,
            "--subkey-fingerprint",
            fingerprint,
            "--creation-time",
            STABLE_TIME,
            "--reason",
            "compromised",
            "--output",
            revocation,
        )

    # 1. Garbage cert — must fail in the parser, before any HSM access.
    bad_cert.write_bytes(b"this is not an OpenPGP cert\n")
    revoke(cert=bad_cert, fingerprint="0" * 40).failure()
    assert not revocation.exists()

    # 2. A short key ID is refused up front: not collision-resistant, and a
    #    hostile cert could carry an aliasing subkey.
    result = revoke(cert=two_tier_cert, fingerprint="0123456789ABCDEF").failure()
    assert "not a full OpenPGP fingerprint" in result.stderr
    assert not revocation.exists()

    # 3. Non-hex characters.
    revoke(cert=two_tier_cert, fingerprint="Z" * 40).failure()
    assert not revocation.exists()

    # 4. The primary's own fingerprint where a subkey's is expected: present in
    #    the cert, but not as a subkey.
    result = revoke(cert=two_tier_cert, fingerprint=primary_fpr).failure()
    assert "no subkey in the input cert matches" in result.stderr
    assert not revocation.exists()

    # 5. A fingerprint that is simply not in the cert.
    result = revoke(cert=two_tier_cert, fingerprint="0" * 40).failure()
    assert "no subkey" in result.stderr or "matches" in result.stderr
    assert not revocation.exists()


# ---------------------------------------------------------------------------
# Packet framing
# ---------------------------------------------------------------------------


def test_revocation_files_are_proper_openpgp_packets(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """Regression for "Malformed CTB: MSB of ptag not set".

    The signature body was once serialized without its packet header.  GnuPG is
    lenient enough to import that, so the revoked-flag tests passed anyway; a
    strict parser is not, which is why this checks the framing directly.
    """
    cert_revocation = work / "cert-revocation.asc"
    subkey_revocation = work / "subkey-revocation.asc"

    sqp11.run(
        "cert-revoke",
        "--key-label",
        pkcs11.ec,
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "superseded",
        "--message",
        "framing regression",
        "--output",
        cert_revocation,
    ).success()

    sqp11.run(
        "subkey-revoke",
        "--key-label",
        pkcs11.primary,
        "--input-cert",
        two_tier_cert,
        "--subkey-fingerprint",
        _subkey_fpr(two_tier_cert),
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "compromised",
        "--message",
        "framing regression",
        "--output",
        subkey_revocation,
    ).success()

    for path, what in ((cert_revocation, "cert-revoke"), (subkey_revocation, "subkey-revoke")):
        sq_inspect.assert_one_signature_packet(path, what)


@pytest.mark.gpg
def test_binary_revocation_outputs_are_packets_accepted_by_gpg(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config, gpg: Gpg, work: Path
):
    cert_revocation = work / "cert-rev.bin"
    subkey_revocation = work / "sub-rev.bin"

    sqp11.run(
        "cert-revoke",
        "--key-label",
        pkcs11.primary,
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "superseded",
        "--message",
        "binary revocation",
        "--binary",
        "--output",
        cert_revocation,
    ).success()

    sqp11.run(
        "subkey-revoke",
        "--key-label",
        pkcs11.primary,
        "--input-cert",
        two_tier_cert,
        "--subkey-fingerprint",
        _subkey_fpr(two_tier_cert),
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "compromised",
        "--message",
        "binary revocation",
        "--binary",
        "--output",
        subkey_revocation,
    ).success()

    for path, what in (
        (cert_revocation, "cert-revoke --binary"),
        (subkey_revocation, "subkey-revoke --binary"),
    ):
        assert not path.read_bytes().startswith(b"-----BEGIN"), (
            f"{what} armored despite --binary"
        )
        sq_inspect.assert_one_signature_packet(path, what)

    gpg.import_(two_tier_cert)
    gpg.import_(cert_revocation)
    gpg.import_(subkey_revocation)
    assert "r" in gpg.field(gpg.list_keys(), "pub", 1), (
        "the primary should be revoked after importing the binary cert-revoke"
    )


# ---------------------------------------------------------------------------
# Sequoia honours what GnuPG drops
# ---------------------------------------------------------------------------


@pytest.mark.sq
def test_sq_honours_standalone_subkey_revocation(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config, sq: Sq, work: Path
):
    """Sequoia applies a standalone subkey revocation; GnuPG does not.

    Confirms the packet is structurally correct rather than merely tolerated:
    a signature that verified before the revocation must stop verifying after
    it, because the subkey was revoked as compromised.
    """
    payload = work / "payload.txt"
    signature = work / "payload.txt.asc"
    revocation = work / "subkey-revocation.asc"
    payload.write_bytes(b"sq subkey-revocation parity\n")

    sqp11.run(
        "sign",
        "--key-label",
        pkcs11.subkey,
        "--creation-time",
        STABLE_TIME,
        payload,
    ).success()

    sq.run(
        "verify",
        "--signer-file",
        two_tier_cert,
        "--signature-file",
        signature,
        payload,
    ).success()

    sqp11.run(
        "subkey-revoke",
        "--key-label",
        pkcs11.primary,
        "--input-cert",
        two_tier_cert,
        "--subkey-fingerprint",
        _subkey_fpr(two_tier_cert),
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "compromised",
        "--message",
        "sq subkey revocation parity test",
        "--output",
        revocation,
    ).success()

    merged = concat(work / "cert-with-revocation.asc", two_tier_cert, revocation)
    result = sq.run(
        "verify",
        "--signer-file",
        merged,
        "--signature-file",
        signature,
        payload,
    )
    assert result.returncode != 0, (
        "verification must fail once the signing subkey is revoked as "
        f"compromised:\n{result.stderr}"
    )
