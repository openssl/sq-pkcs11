"""Key discovery, selector equivalence, and stdout behaviour."""

from __future__ import annotations

from pathlib import Path

import pytest

import _inspect as sq_inspect
from conftest import STABLE_TIME, Pkcs11Config, SqPkcs11

pytestmark = pytest.mark.pkcs11


def _cka_id_for_label(sqp11: SqPkcs11, label: str) -> str | None:
    """Read a key's CKA_ID out of `list-keys`, or None if it has none.

    nShield's `generatekey` does not always populate CKA_ID — an empty one has
    been seen on EC keys — and list-keys prints `<no id>` in that case, which
    must not be passed on as if it were real.
    """
    stdout = sqp11.run("list-keys").success().stdout
    for line in stdout.splitlines():
        if f'label="{label}"' not in line or "id=" not in line:
            continue
        candidate = line.split("id=", 1)[1].split()[0]
        if candidate and all(c in "0123456789abcdefABCDEF" for c in candidate):
            return candidate
    return None


def test_list_keys_shows_test_keys(sqp11: SqPkcs11, pkcs11: Pkcs11Config):
    stdout = sqp11.run("list-keys").success().stdout
    for kind, label in pkcs11.labels.items():
        assert label in stdout, f"expected list-keys to mention {kind} key {label!r}"


def test_each_key_label_resolves_to_exactly_one_object(sqp11: SqPkcs11, pkcs11: Pkcs11Config):
    """A duplicated CKA_LABEL breaks selection by label, confusingly.

    `sign` then fails with `ambiguous slot selection: 2 token slots found`,
    where the count is actually the number of matching *private-key objects* and
    the wording sends the operator looking at slots.  It has happened in
    production; catching it here names the real problem, and the fix is to
    select by `--key-id` instead.
    """
    lines = sqp11.run("list-keys").success().stdout.splitlines()
    for kind, label in pkcs11.labels.items():
        matches = [line for line in lines if f'label="{label}"' in line]
        assert len(matches) == 1, (
            f"the {kind} label {label!r} matches {len(matches)} private-key "
            f"objects; selection by --key-label is not unique, so `sign` will "
            f"report an ambiguous selection. Note the id= values and use "
            f"--key-id:\n" + "\n".join(matches)
        )


def test_key_selector_forms_resolve_same_key(sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path):
    """--key-label, --key-id and --key-uri must reach the same private key."""
    for kind in ("ec", "rsa", "primary"):
        label = pkcs11.labels[kind]
        id_hex = _cka_id_for_label(sqp11, label)
        if id_hex:
            break
    else:
        pytest.skip(
            "no test key has a populated CKA_ID, so the --key-id selector "
            "cannot be exercised; re-generate one with a non-empty id"
        )

    userid = "Selector <sel@example.com>"
    outputs = {}
    for name, selector in (
        ("by-label", ["--key-label", label]),
        ("by-id", ["--key-id", id_hex]),
        ("by-uri", ["--key-uri", f"pkcs11:object={label};type=private"]),
    ):
        dest = work / f"{name}.asc"
        sqp11.run(
            "cert-export",
            *selector,
            "--userid",
            userid,
            "--creation-time",
            STABLE_TIME,
            "--output",
            dest,
        ).success()
        outputs[name] = sq_inspect.primary_fingerprint(dest)

    assert outputs["by-label"] == outputs["by-id"], "label and id must resolve the same key"
    assert outputs["by-label"] == outputs["by-uri"], "label and uri must resolve the same key"


def test_auto_selector_with_multiple_keys_fails(sqp11: SqPkcs11, work: Path):
    """--auto is only for the unambiguous case; several keys must be an error."""
    cert = work / "cert.asc"
    result = sqp11.run(
        "cert-export",
        "--auto",
        "--userid",
        "Ambiguous <amb@example.com>",
        "--creation-time",
        STABLE_TIME,
        "--output",
        cert,
    ).failure()
    assert "ambiguous" in result.stderr.lower()
    assert not cert.exists()


# ---------------------------------------------------------------------------
# stdout
# ---------------------------------------------------------------------------


def test_cert_export_writes_armored_cert_to_stdout(sqp11: SqPkcs11, pkcs11: Pkcs11Config):
    result = sqp11.run(
        "cert-export",
        "--key-label",
        pkcs11.ec,
        "--userid",
        "Stdout <so@example.com>",
        "--creation-time",
        STABLE_TIME,
    ).success()
    assert result.stdout.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    # Diagnostics belong on stderr, but OpenPGP data must not.
    assert not result.stderr.startswith("-----BEGIN")


def test_cert_export_binary_writes_packets_to_stdout(sqp11: SqPkcs11, pkcs11: Pkcs11Config):
    result = sqp11.run(
        "cert-export",
        "--binary",
        "--key-label",
        pkcs11.ec,
        "--userid",
        "Stdout <so@example.com>",
        "--creation-time",
        STABLE_TIME,
    ).success()
    data = result.stdout_bytes
    assert not data.startswith(b"-----BEGIN"), "--binary stdout was armored"
    headers = sq_inspect.packet_headers(sq_inspect.dump(data))
    assert "Public-Key Packet" in headers, (
        f"binary cert-export stdout contained no public-key packet: {headers}"
    )


def test_cert_revoke_writes_one_signature_to_stdout(sqp11: SqPkcs11, pkcs11: Pkcs11Config):
    result = sqp11.run(
        "cert-revoke",
        "--key-label",
        pkcs11.ec,
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "unspecified",
        "--message",
        "stdout test",
    ).success()
    assert result.stdout.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    sq_inspect.assert_one_signature_packet(result.stdout_bytes, "cert-revoke stdout")


def test_subkey_revoke_writes_one_signature_to_stdout(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config
):
    subkey_fpr = sq_inspect.only_subkey_fingerprint(two_tier_cert)
    result = sqp11.run(
        "subkey-revoke",
        "--key-label",
        pkcs11.primary,
        "--input-cert",
        two_tier_cert,
        "--subkey-fingerprint",
        subkey_fpr,
        "--creation-time",
        STABLE_TIME,
        "--reason",
        "unspecified",
        "--message",
        "stdout test",
    ).success()
    sq_inspect.assert_one_signature_packet(result.stdout_bytes, "subkey-revoke stdout")
