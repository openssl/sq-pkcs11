"""verify-signing-key: the pre-flight check before production signing.

Its job is to catch a stale, revoked, expired or simply wrong HSM key *before*
it signs a release artefact, so each test here is a way of being wrong that the
check has to notice.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import _inspect as sq_inspect
from conftest import STABLE_TIME, Pkcs11Config, SqPkcs11, concat

pytestmark = pytest.mark.pkcs11


def test_verify_signing_key_accepts_current_signing_subkey(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config
):
    result = sqp11.run(
        "verify-signing-key",
        "--key-label",
        pkcs11.subkey,
        "--creation-time",
        STABLE_TIME,
        "--input-cert",
        two_tier_cert,
    ).success()
    assert "is a current signing key" in result.stdout


def test_verify_signing_key_rejects_unrelated_hsm_key(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config
):
    """The typo'd-label case: a key that is not in this cert at all."""
    result = sqp11.run(
        "verify-signing-key",
        "--key-label",
        pkcs11.rsa,  # not the key bound in the cert
        "--creation-time",
        STABLE_TIME,
        "--input-cert",
        two_tier_cert,
    ).failure()
    assert "not bound to" in result.stderr


def test_verify_signing_key_rejects_certify_only_primary(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config
):
    """In a two-tier cert the primary cannot sign, so it must not pass.

    Distinguishing "present but not a valid signer" from "not in the cert" is
    the point: they call for different fixes.
    """
    result = sqp11.run(
        "verify-signing-key",
        "--key-label",
        pkcs11.primary,
        "--creation-time",
        STABLE_TIME,
        "--input-cert",
        two_tier_cert,
    ).failure()
    assert "present in" in result.stderr
    assert "not currently a valid signer" in result.stderr


def test_verify_signing_key_rejects_revoked_subkey(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config, work: Path
):
    revocation = work / "rev.asc"
    subkey_fpr = sq_inspect.only_subkey_fingerprint(two_tier_cert)

    sqp11.run(
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
        "compromised",
        "--output",
        revocation,
    ).success()

    merged = concat(work / "cert-with-revocation.asc", two_tier_cert, revocation)
    result = sqp11.run(
        "verify-signing-key",
        "--key-label",
        pkcs11.subkey,
        "--creation-time",
        STABLE_TIME,
        "--input-cert",
        merged,
    ).failure()
    assert "not currently a valid signer" in result.stderr


def test_verify_signing_key_requires_a_creation_time(
    two_tier_cert: Path, sqp11: SqPkcs11, pkcs11: Pkcs11Config
):
    """It will not derive the timestamp from the cert it is checking against.

    Reading the value out of the same certificate would make the check pass by
    construction, which is worse than useless — it would look like a pre-flight
    while asserting nothing.
    """
    result = sqp11.run(
        "verify-signing-key",
        "--key-label",
        pkcs11.subkey,
        "--input-cert",
        two_tier_cert,
    ).failure()
    assert "--creation-time is required" in result.stderr
