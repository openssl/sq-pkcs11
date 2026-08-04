"""sign: the three output forms, creation-time handling, and dual verification.

Every artefact this produces is checked against both GnuPG and Sequoia.  That
dual-verifiability is a stated goal of the tool: two independent
implementations agreeing is the only evidence that an artefact is well-formed
rather than merely acceptable to whichever library produced it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import _inspect as sq_inspect
from conftest import STABLE_TIME, Gpg, Pkcs11Config, Sq, SqPkcs11, keyring_for

pytestmark = pytest.mark.pkcs11

# Shaped like a real apt Release file: leading-space checksum lines, a trailing
# newline, no trailing whitespace.
RELEASE = (
    "Origin: Test\n"
    "Label: Test\n"
    "Suite: stable\n"
    "Codename: stable\n"
    "Architectures: amd64\n"
    "Components: main\n"
    "Date: Tue, 26 May 2026 15:08:47 UTC\n"
    "SHA256:\n"
    " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    "                0 main/binary-amd64/Packages\n"
)


# ---------------------------------------------------------------------------
# Sign / verify round-trips
# ---------------------------------------------------------------------------


@pytest.mark.gpg
@pytest.mark.parametrize("key", ["rsa", "ec"])
def test_sign_verify_with_gpg(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, gpg: Gpg, work: Path, key: str
):
    cert = export_cert(key, userid=f"Test {key} <{key}@example.com>")
    payload = work / "payload.txt"
    payload.write_bytes(b"test payload bytes\n")

    gpg.import_(cert)
    sqp11.run(
        "sign",
        "--key-label",
        pkcs11.labels[key],
        "--creation-time",
        STABLE_TIME,
        payload,
    ).success()

    signature = work / "payload.txt.asc"
    assert signature.exists(), f"sign did not create {signature}"
    result = gpg.run("--verify", signature, payload)
    result.success()
    assert "Good signature" in result.stderr


@pytest.mark.sq
@pytest.mark.parametrize("key", ["rsa", "ec"])
def test_sign_verify_with_sq(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, sq: Sq, work: Path, key: str
):
    """Sequoia's own CLI — a different implementation and crypto backend.

    Useful as a check that we are not producing artefacts that only survive
    GnuPG's leniency.
    """
    cert = export_cert(key, userid=f"SQ Test {key} <sq-{key}@example.com>")
    payload = work / "payload.txt"
    payload.write_bytes(b"test payload bytes\n")

    sqp11.run(
        "sign",
        "--key-label",
        pkcs11.labels[key],
        "--creation-time",
        STABLE_TIME,
        payload,
    ).success()

    sq.run(
        "verify",
        "--signer-file",
        cert,
        "--signature-file",
        work / "payload.txt.asc",
        payload,
    ).success()


# ---------------------------------------------------------------------------
# Output forms
# ---------------------------------------------------------------------------


def test_sign_binary_produces_non_armored_output(
    sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    payload = work / "p.bin"
    signature = work / "p.bin.sig"
    payload.write_bytes(b"binary payload")

    sqp11.run(
        "sign",
        "--binary",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        "--output",
        signature,
        payload,
    ).success()

    data = signature.read_bytes()
    assert not data.startswith(b"-----BEGIN"), "binary output must not be armored"
    # The first byte of an OpenPGP packet header has the MSB set.
    assert data and data[0] & 0x80, f"expected a packet header, got 0x{data[0]:02x}"
    sq_inspect.assert_one_signature_packet(signature, "sign --binary")


def test_sign_output_dash_streams_to_stdout(sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path):
    payload = work / "p.txt"
    payload.write_bytes(b"stdout streaming test\n")

    result = sqp11.run(
        "sign",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        "--output",
        "-",
        payload,
    ).success()

    assert result.stdout.startswith("-----BEGIN PGP SIGNATURE-----")
    sq_inspect.assert_one_signature_packet(result.stdout_bytes, "sign --output -")
    derived = work / "p.txt.asc"
    assert not derived.exists(), "--output - must not also write a file"


def test_binary_signature_creation_time_subpacket_is_hashed_but_not_critical(
    sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """rpm 4.16 dispatches subpackets on the raw type byte, unmasked.

    With the critical bit set the byte is 0x82, no case matches, and every
    signed package reports `Signature: RSA/SHA512, Thu Jan  1 00:00:00 1970`.
    Verification is unaffected — rpm re-hashes the area verbatim — but the
    displayed date is wrong on every artefact in the repository.

    Asserted for --binary only, the form rpm consumes.  The armored path still
    runs through Sequoia's streaming signer, which marks this subpacket
    critical; that is not asserted either way, because pinning it would turn
    an upstream implementation detail into a requirement of ours.
    """
    payload = work / "p.bin"
    signature = work / "p.bin.sig"
    payload.write_bytes(b"subpacket encoding\n")

    sqp11.run(
        "sign",
        "--binary",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        "--output",
        signature,
        payload,
    ).success()

    text = sq_inspect.assert_one_signature_packet(signature, "sign --binary")
    line = sq_inspect.signature_creation_time_line(text)
    assert "(critical)" not in line, (
        "the creation-time subpacket must not be critical — rpm 4.16 cannot "
        f"read it in that form and reports a 1970 signature date: {line!r}"
    )
    # `sq packet dump` lists the hashed area before the unhashed one, so a
    # creation time that had moved out of the signed area would show up under
    # "Unhashed area" instead.
    hashed, _, unhashed = text.partition("Unhashed area:")
    assert "Signature creation time" in hashed
    assert "Signature creation time" not in unhashed, (
        "the creation time must never move to the unsigned area"
    )


# ---------------------------------------------------------------------------
# Cleartext Signature Framework (apt's InRelease)
# ---------------------------------------------------------------------------


@pytest.mark.gpg
@pytest.mark.sq
def test_sign_cleartext_produces_a_verifiable_csf_document(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, gpg: Gpg, gpgv, sq: Sq, work: Path
):
    cert = export_cert("rsa", userid="Cleartext <ct@example.com>")
    release = work / "Release"
    in_release = work / "InRelease"
    release.write_text(RELEASE)

    sqp11.run(
        "sign",
        "--cleartext",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        "--output",
        in_release,
        release,
    ).success()

    doc = in_release.read_text()
    lines = doc.splitlines()
    assert lines[0] == "-----BEGIN PGP SIGNED MESSAGE-----"
    assert lines[1].startswith("Hash: "), f"expected a Hash header, got {lines[1]!r}"
    assert "-----BEGIN PGP SIGNATURE-----" in doc

    # apt parses the metadata out of the signed document, so the body has to
    # survive the framing byte for byte.  Body = between the blank line after
    # the headers and the signature armor, minus the framing's final newline.
    after_headers = doc.split("\n\n", 1)[1]
    body = after_headers.split("-----BEGIN PGP SIGNATURE-----", 1)[0]
    body = body[:-1] if body.endswith("\n") else body
    assert body == RELEASE, "the text inside InRelease must be exactly the Release file"

    # The embedded signature is a text signature, per RFC 9580 §7.
    assert sq_inspect.field(sq_inspect.dump(in_release), "Type") == "Text", (
        "a cleartext signature must be a text signature"
    )

    # gpgv, used the way apt uses it.
    keyring = keyring_for(gpg, cert, work / "keyring.gpg")
    result = gpgv(keyring, in_release)
    result.success()
    assert "Good signature" in result.stderr

    sq.run("verify", "--signer-file", cert, "--cleartext", in_release).success()


def test_sign_cleartext_requires_an_explicit_output_path(
    sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """A cleartext document is a signed message, not a detached signature.

    Letting it default to `<input>.asc` would invite publishing it where a
    detached signature is expected, which every verifier rejects.
    """
    payload = work / "Release"
    payload.write_text("Origin: Test\n")

    sqp11.run(
        "sign",
        "--cleartext",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        payload,
    ).failure()
    assert not (work / "Release.asc").exists()

    # And it is not a detached-signature mode.
    sqp11.run(
        "sign",
        "--cleartext",
        "--binary",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        "--output",
        work / "out",
        payload,
    ).failure()


# ---------------------------------------------------------------------------
# Creation time
# ---------------------------------------------------------------------------


def test_sign_requires_a_creation_time_or_an_input_cert(
    sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """The regression guard for the silent Unix-epoch default.

    An OpenPGP fingerprint hashes the creation time along with the key
    material, so a forgotten flag produced well-formed signatures carrying an
    issuer fingerprint that resolved to no published key — and it surfaced only
    at the verifier, after the artefact had shipped.
    """
    payload = work / "p.txt"
    payload.write_bytes(b"no creation time\n")

    result = sqp11.run("sign", "--key-label", pkcs11.rsa, payload).failure()
    stderr = result.stderr
    assert "--creation-time is required" in stderr
    # The value cannot be read off the HSM, so the message has to say where it
    # does come from and offer the shortcut.
    assert "gentime" in stderr, stderr
    assert "--input-cert" in stderr, stderr
    assert "1970-01-01T00:00:00Z" in stderr, stderr
    assert not (work / "p.txt.asc").exists(), "no output when it refuses to run"


def test_creation_time_epoch_still_works_when_asked_for_explicitly(
    sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """The escape hatch that makes the strictness safe.

    A certificate really published under the old default can still be signed
    for — the caller just has to say so in full.
    """
    payload = work / "p.txt"
    payload.write_bytes(b"explicit epoch\n")
    sqp11.run(
        "sign",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        "1970-01-01T00:00:00Z",
        payload,
    ).success()
    assert (work / "p.txt.asc").exists()


@pytest.mark.sq
def test_sign_input_cert_derives_subkey_creation_time(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, sq: Sq, work: Path
):
    """`--input-cert` recovers the published subkey's creation time.

    This is the git-tag-shim bug: without a creation time, `sign` used to
    default to the Unix epoch and produce an issuer fingerprint that resolves
    to no published key.
    """
    cert_path = export_cert("primary", subkey="subkey", userid="InputCert <ic@example.com>")
    payload = work / "p.txt"
    payload.write_bytes(b"input-cert derivation\n")

    sqp11.run(
        "sign", "--key-label", pkcs11.subkey, "--input-cert", cert_path, payload
    ).success()

    subkey_fpr = sq_inspect.only_subkey_fingerprint(cert_path)
    dump = sq_inspect.dump(work / "p.txt.asc")
    issuers = sq_inspect.issuer_fingerprints(dump)
    assert subkey_fpr in issuers, (
        f"issuer must be the published subkey {subkey_fpr}, got {issuers} — "
        "which is only true if the creation time came out of the cert rather "
        "than defaulting"
    )

    sq.run(
        "verify",
        "--signer-file",
        cert_path,
        "--signature-file",
        work / "p.txt.asc",
        payload,
    ).success()


def test_sign_input_cert_rejects_unrelated_cert(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """A cert that does not contain the HSM key must fail, not fall back."""
    cert = export_cert("rsa", userid="Unrelated <un@example.com>")
    payload = work / "p.txt"
    payload.write_bytes(b"unrelated cert\n")

    result = sqp11.run(
        "sign", "--key-label", pkcs11.ec, "--input-cert", cert, payload
    ).failure()
    assert "no key in the input cert matches" in result.stderr


def test_signature_issuer_is_the_subkey_in_two_tier_cert(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    cert_path = export_cert("primary", subkey="subkey", userid="Issuer <iss@example.com>")
    payload = work / "p.txt"
    payload.write_bytes(b"issuer test\n")

    sqp11.run(
        "sign",
        "--key-label",
        pkcs11.subkey,
        "--creation-time",
        STABLE_TIME,
        payload,
    ).success()

    issuers = sq_inspect.issuer_fingerprints(sq_inspect.dump(work / "p.txt.asc"))
    assert sq_inspect.only_subkey_fingerprint(cert_path) in issuers
    assert sq_inspect.primary_fingerprint(cert_path) not in issuers, (
        "release artefacts must be signed by the subkey, never the primary"
    )


@pytest.mark.gpg
def test_wrong_creation_time_invalidates_signature(
    export_cert, sqp11: SqPkcs11, pkcs11: Pkcs11Config, gpg: Gpg, work: Path
):
    """A signature made at the wrong creation time must not verify.

    The negative side of the fingerprint story: if it *did* verify, the
    creation time would not matter and none of the strictness would be needed.
    """
    cert = export_cert("primary", subkey="subkey", userid="WrongTime <wt@example.com>")
    payload = work / "payload.txt"
    payload.write_bytes(b"wrong-time payload\n")
    gpg.import_(cert)

    sqp11.run(
        "sign",
        "--key-label",
        pkcs11.subkey,
        "--creation-time",
        "2027-06-15T00:00:00Z",  # not the cert's time
        payload,
    ).success()

    result = gpg.run("--verify", work / "payload.txt.asc", payload)
    assert result.returncode != 0, (
        "verification must fail when sign --creation-time disagrees with the "
        f"cert:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# Input and output handling
# ---------------------------------------------------------------------------


def test_sign_rejects_nonexistent_input_file(sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path):
    missing = work / "does-not-exist.txt"
    result = sqp11.run(
        "sign",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        missing,
    ).failure()
    assert "does-not-exist" in result.stderr or "No such file" in result.stderr


def test_sign_rejects_directory_as_input(sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path):
    result = sqp11.run(
        "sign",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        work,
    ).failure()
    assert result.stderr.strip(), "expected a diagnostic when the input is a directory"


def test_sign_refuses_to_overwrite_existing_output_without_force(
    sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    payload = work / "p.txt"
    signature = work / "p.txt.asc"
    payload.write_bytes(b"payload\n")
    signature.write_bytes(b"PRECIOUS DO NOT OVERWRITE\n")
    original = signature.read_bytes()

    result = sqp11.run(
        "sign",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        "--output",
        signature,
        payload,
    ).failure()
    assert "refusing to overwrite" in result.stderr
    assert signature.read_bytes() == original, "the existing file must be untouched"

    sqp11.run(
        "sign",
        "--force",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        "--output",
        signature,
        payload,
    ).success()
    assert signature.read_bytes() != original
    assert signature.read_text().startswith("-----BEGIN PGP SIGNATURE-----")


def test_sign_default_output_refuses_overwrite_without_force(
    sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    """The auto-derived `<input>.asc` path is subject to the same guard."""
    payload = work / "p.txt"
    derived = work / "p.txt.asc"
    payload.write_bytes(b"payload\n")
    derived.write_bytes(b"PRECIOUS\n")

    result = sqp11.run(
        "sign",
        "--key-label",
        pkcs11.rsa,
        "--creation-time",
        STABLE_TIME,
        payload,
    ).failure()
    assert "refusing to overwrite" in result.stderr
    assert derived.read_bytes() == b"PRECIOUS\n"


def test_sign_preflights_overwrite_before_hsm_round_trip(sqp11: SqPkcs11, work: Path):
    """The refusal must happen before a signing operation is spent.

    Arrange a key that demonstrably does not exist: without the preflight this
    would fail in the HSM lookup, so seeing the overwrite refusal instead
    proves we never got that far — no wasted operation, no spurious key-usage
    entry in the HSM's audit log.
    """
    payload = work / "p.txt"
    signature = work / "p.txt.asc"
    payload.write_bytes(b"preflight test\n")
    signature.write_bytes(b"DO NOT TOUCH\n")

    result = sqp11.run(
        "sign",
        "--key-label",
        "this-key-does-not-exist-xyz",
        "--creation-time",
        STABLE_TIME,
        "--output",
        signature,
        payload,
    ).failure()
    assert "refusing to overwrite" in result.stderr, (
        f"expected the preflight refusal before the key lookup, got: {result.stderr}"
    )
    assert signature.read_bytes() == b"DO NOT TOUCH\n"
