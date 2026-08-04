"""Package-repository signing, end to end.

The automated form of the package-signing pass: sign a real
rpm through the gpg shim, and put the artefacts in front of the consumers' own
OpenPGP parsers.

pytest runs on the host and drives target containers over `podman exec`; see
`conftest.py`.  The rpm flow — build, sign, verify — happens inside each rpm
target, with the signing environment bind-mounted in, for two reasons:

* it removes any need for rpm on the host, which the signing host may not have;
* rpm 4.16 and 4.19 expand `%__gpg_sign_cmd` differently — 4.16 passes
  `--digest-algo X` and execve()s directly, 4.19 passes `--digest-algo=X`, adds
  `--` before the operand and probes `--version` first — so only that version's
  own rpmsign exercises its own contract.  A host-side test would cover
  whichever rpm the host happened to have, and no other.

The apt half needs no signing environment in the container: the cleartext
document is signed on the host and only verified on the target.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from conftest import (
    IN_SHIM,
    STABLE_TIME,
    Gpg,
    Pkcs11Config,
    SqPkcs11,
    Target,
    keyring_for,
)

SPEC = """\
Name:      sq-pkcs11-signing-test
Version:   1.0
Release:   1
Summary:   Throwaway package for signing verification
License:   Apache-2.0
BuildArch: noarch
%description
Signed by sq-pkcs11 through the gpg shim.  Not for distribution.
%install
mkdir -p %{buildroot}/usr/share/sq-pkcs11-signing-test
echo ok > %{buildroot}/usr/share/sq-pkcs11-signing-test/ok
%files
/usr/share/sq-pkcs11-signing-test/ok
"""

RELEASE = (
    "Origin: OpenSSL\n"
    "Label: OpenSSL\n"
    "Suite: stable\n"
    "Codename: stable\n"
    "Architectures: amd64\n"
    "Components: main\n"
    "Date: Tue, 26 May 2026 15:08:47 UTC\n"
    "SHA256:\n"
    " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    "                0 main/binary-amd64/Packages\n"
)

# Where the package is built and signed inside a target.
TOPDIR = "/tmp/rpmbuild"
PACKAGE = f"{TOPDIR}/RPMS/noarch/sq-pkcs11-signing-test-1.0-1.noarch.rpm"


# ---------------------------------------------------------------------------
# Shared artefacts
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def published_certs(sqp11: SqPkcs11, pkcs11: Pkcs11Config, artifacts: Path) -> dict[str, Path]:
    """One published certificate per key algorithm, in `artifacts`.

    Both are needed because the algorithms are not interchangeable to every
    consumer — which is the whole point of the matrix below.
    """
    certs = {}
    for kind in ("rsa", "ec"):
        dest = artifacts / f"cert-{kind}.asc"
        sqp11.run(
            "cert-export",
            "--key-label",
            pkcs11.labels[kind],
            "--userid",
            f"Package Signing {kind} <pkg-{kind}@example.com>",
            "--creation-time",
            STABLE_TIME,
            "--output",
            dest,
        ).success()
        certs[kind] = dest
    return certs


@pytest.fixture(scope="session")
def published_cert(sqp11: SqPkcs11, pkcs11: Pkcs11Config, artifacts: Path) -> Path:
    """The certificate consumers verify against, where every target can see it.

    Single-tier on purpose: this has to work on a PIN-protected token too, and
    what matters here is the signing key's own certificate, not the two-tier
    structure (covered in test_cert_export.py).
    """
    dest = artifacts / "cert.asc"
    sqp11.run(
        "cert-export",
        "--key-label",
        pkcs11.rsa,
        "--userid",
        "Package Signing <pkg@example.com>",
        "--creation-time",
        STABLE_TIME,
        "--output",
        dest,
    ).success()
    return dest


# ---------------------------------------------------------------------------
# rpm: build, sign and verify inside the target
# ---------------------------------------------------------------------------


def _build(target: Target) -> None:
    """rpmbuild a throwaway package inside the target."""
    target.run(f"rm -rf {TOPDIR}", check=True)
    target.run(
        f"mkdir -p {TOPDIR}/SPECS && cat > {TOPDIR}/SPECS/t.spec <<'SPEC_EOF'\n{SPEC}SPEC_EOF",
        check=True,
    )
    target.run(f'rpmbuild --define "_topdir {TOPDIR}" -bb {TOPDIR}/SPECS/t.spec', check=True)
    target.run(f"test -f {PACKAGE}", check=True)


def _sign(
    target: Target,
    key_label: str,
    cert_name: str,
    env: dict[str, str] | None = None,
):
    """rpmsign the built package through the shim.

    Overriding %__gpg alone leaves the distro's own %__gpg_sign_cmd in place, so
    whatever contract this rpm version expects is the one exercised.
    """
    signing_env = {"SQ_PKCS11_CERT": f"/artifacts/{cert_name}"}
    signing_env.update(env or {})
    return target.run(
        f'rpmsign --addsign --define "_gpg_name {key_label}" '
        f'--define "__gpg {IN_SHIM}" {PACKAGE}',
        env=signing_env,
    )


def _embedded_signature(target: Target) -> str:
    """What rpm made of the signature in the package header.

    Queried through the header-signature tags rather than scraped out of
    `rpm -qi`, because rpm 4.19 leaves the `Signature` line of `-qi` empty while
    still populating the tag.  Both tags have to be tried: rpm keeps an RSA
    signature in `RSAHEADER` and everything else in `DSAHEADER` — the names
    predate ECDSA and really mean "RSA" and "not RSA".  So a lookup of
    `RSAHEADER` alone reports `(none)` for a perfectly good ECDSA signature.

    Returns a string like

        RSA/SHA512, Tue Aug  4 09:21:56 2026, Key ID f7345b74171c3fa6
        ECDSA/SHA384, Tue Aug  4 11:30:01 2026, Key ID 2a5c43bc457e0635

    or the literal `(none)` when the package carries no signature at all.
    """
    for tag in ("RSAHEADER", "DSAHEADER"):
        value = target.out(f"rpm -q --qf '%{{{tag}:pgpsig}}' -p {PACKAGE}")
        if value and value != "(none)":
            return value
    return "(none)"


@pytest.mark.pkcs11
@pytest.mark.rpm
@pytest.mark.containers
def test_rpmsign_through_the_shim(
    rpm_target: Target, published_cert: Path, pkcs11: Pkcs11Config
):
    _build(rpm_target)
    result = _sign(rpm_target, pkcs11.rsa, published_cert.name)
    assert result.returncode == 0, (
        f"rpmsign on {rpm_target.image} ({rpm_target.note}) failed:{result._detail()}"
    )

    embedded = _embedded_signature(rpm_target)
    assert embedded != "(none)", "rpm rejected the signature it was handed"
    assert "RSA" in embedded, f"expected an RSA signature, got {embedded!r}"
    assert "1970" not in embedded, (
        f"rpm read no creation time from the signature: {embedded!r} — the "
        "creation-time subpacket regressed to being emitted critical, which "
        "rpm's own parser cannot read up to and including 4.16"
    )


@pytest.mark.pkcs11
@pytest.mark.rpm
@pytest.mark.containers
def test_rpm_verifies_the_signature_it_was_given(
    rpm_target: Target, published_cert: Path, pkcs11: Pkcs11Config
):
    """`rpm -K` against a private rpmdb, so no system state is touched.

    An RSA key must pass on both targets.  An ECDSA key fails on almalinux:9 —
    rpm 4.16 has no ECDSA implementation at all — which is why the packaging key
    is RSA.
    """
    _build(rpm_target)
    _sign(rpm_target, pkcs11.rsa, published_cert.name)

    rpm_target.run("rm -rf /tmp/db && mkdir -p /tmp/db", check=True)
    rpm_target.run("rpm --dbpath /tmp/db --initdb", check=True)
    rpm_target.run(
        f"rpm --dbpath /tmp/db --import /artifacts/{published_cert.name}", check=True
    )

    result = rpm_target.run(f"rpm --dbpath /tmp/db -K {PACKAGE}")
    out = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"{rpm_target.image} ({rpm_target.note}) rejected the signature:\n{out}"
    )
    assert "signatures OK" in out, (
        "`digests OK` without `signatures` means the signature was never "
        f"checked, and rpm -K exits 0 for that: {out!r}"
    )


@pytest.mark.pkcs11
@pytest.mark.rpm
@pytest.mark.containers
def test_shim_discards_an_ambient_pin_under_rpmsign(
    rpm_target: Target, published_cert: Path, pkcs11: Pkcs11Config
):
    """A PIN left in a CI environment must not reach sq-pkcs11.

    The hermetic suite proves the variable is stripped from the child
    environment; this proves the whole pipeline still signs with it set, which
    is what an operator actually cares about.
    """
    _build(rpm_target)
    result = _sign(
        rpm_target,
        pkcs11.rsa,
        published_cert.name,
        env={
            "SQ_PKCS11_PIN": "deliberately-wrong",
            "SQ_PKCS11_SUBKEY_PIN": "deliberately-wrong",
        },
    )
    assert result.returncode == 0, (
        "signing must succeed with a bogus ambient PIN, because the shim drops "
        f"it:{result._detail()}"
    )
    assert _embedded_signature(rpm_target) != "(none)"


# ---------------------------------------------------------------------------
# apt: signed on the host, verified on the target
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def published_inrelease(
    sqp11: SqPkcs11,
    pkcs11: Pkcs11Config,
    published_cert: Path,
    artifacts: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    """A cleartext-signed Release, plus the keyring gpgv needs, in `artifacts`."""
    release = tmp_path_factory.mktemp("apt") / "Release"
    release.write_text(RELEASE)
    in_release = artifacts / "InRelease"
    sqp11.run(
        "sign",
        "--cleartext",
        "--key-label",
        pkcs11.rsa,
        "--input-cert",
        published_cert,
        "--output",
        in_release,
        release,
    ).success()

    home = tmp_path_factory.mktemp("gnupg")
    home.chmod(stat.S_IRWXU)
    keyring_for(Gpg(home), published_cert, artifacts / "keyring.gpg")
    return in_release


@pytest.mark.pkcs11
@pytest.mark.containers
@pytest.mark.gpg
def test_inrelease_verifies_on_target(apt_target: Target, published_inrelease: Path):
    """gpgv on the oldest apt releases we target reads the InRelease."""
    assert published_inrelease.is_file(), "the InRelease is produced on the host"
    result = apt_target.run("gpgv --keyring /artifacts/keyring.gpg /artifacts/InRelease")
    out = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"gpgv on {apt_target.image} ({apt_target.note}) rejected it:\n{out}"
    )
    assert "Good signature" in out, out


# ---------------------------------------------------------------------------
# Production topology: sign on Debian, verify on EL
#
# The signing host runs Debian, the packages are consumed on EL9 and EL10.  That
# pairing is not implied by either side working alone: Debian's rpm 4.20 writes
# the signature through rpm-sequoia, and EL9's rpm 4.16 has to read it with its
# own, much older, internal OpenPGP parser.
# ---------------------------------------------------------------------------

# Which (signing algorithm, verifying distribution) pairings can work.
#
# rpm 4.16 has no ECDSA implementation at all — neither `pgpSignatureNew()` nor
# `pgpPubkeyNew()` has a case for it — so an ECDSA-signed package cannot be
# verified on EL9 however it was produced.  That is what makes RSA the only
# viable algorithm for a packaging key serving both.  Asserted in both
# directions so a change either way shows up as a failure rather than a silent
# improvement or regression.
VERIFIES = {
    ("rsa", "almalinux:9"): True,
    ("rsa", "almalinux:10"): True,
    ("ec", "almalinux:9"): False,
    ("ec", "almalinux:10"): True,
}


@pytest.fixture(scope="session", params=["rsa", "ec"], ids=["rsa", "ecdsa"])
def debian_signed_rpm(
    request,
    deb_signer: Target,
    published_certs: dict[str, Path],
    pkcs11: Pkcs11Config,
    artifacts: Path,
) -> tuple[str, Path]:
    """A package built and signed on Debian, copied out for the EL verifiers.

    Signing must succeed for both algorithms: Debian's rpm 4.20 goes through
    rpm-sequoia, which handles ECDSA.  Whether the result is *verifiable*
    elsewhere is the question the tests below ask.
    """
    kind = request.param
    _build(deb_signer)
    result = _sign(deb_signer, pkcs11.labels[kind], published_certs[kind].name)
    assert result.returncode == 0, (
        f"rpmsign on {deb_signer.image} failed for {kind}:{result._detail()}"
    )
    embedded = _embedded_signature(deb_signer)
    assert embedded != "(none)", f"Debian's rpm rejected the {kind} signature"
    assert "1970" not in embedded, (
        f"no creation time read from the {kind} signature: {embedded!r}"
    )
    dest = artifacts / f"debian-signed-{kind}.rpm"
    deb_signer.copy_out(PACKAGE, dest)
    return kind, dest


@pytest.mark.pkcs11
@pytest.mark.rpm
@pytest.mark.containers
def test_debian_signed_rpm_on_el_verifier(
    debian_signed_rpm: tuple[str, Path],
    rpm_target: Target,
    published_certs: dict[str, Path],
):
    """Sign on Debian 13, verify on almalinux:9 and almalinux:10."""
    kind, package = debian_signed_rpm
    expected = VERIFIES[(kind, rpm_target.image)]

    rpm_target.run("rm -rf /tmp/db && mkdir -p /tmp/db", check=True)
    rpm_target.run("rpm --dbpath /tmp/db --initdb", check=True)
    # Not check=True: importing an ECDSA certificate is itself one of the things
    # rpm 4.16 cannot do, and that is a result, not a test error.
    imported = rpm_target.run(
        f"rpm --dbpath /tmp/db --import /artifacts/{published_certs[kind].name}"
    )
    verified = rpm_target.run(f"rpm --dbpath /tmp/db -K /artifacts/{package.name}")
    out = verified.stdout + verified.stderr
    ok = verified.returncode == 0 and "signatures OK" in out

    if expected:
        assert imported.returncode == 0, (
            f"{rpm_target.image} could not import the {kind} certificate:{imported._detail()}"
        )
        assert ok, (
            f"a {kind} package signed by rpm 4.20 on debian:13 must verify on "
            f"{rpm_target.image} ({rpm_target.note}), but did not:\n{out}"
        )
    else:
        assert not ok, (
            f"a {kind} package now verifies on {rpm_target.image} "
            f"({rpm_target.note}) — that is a change from the recorded matrix, "
            "and would mean the packaging key is no longer restricted to RSA:\n"
            f"{out}"
        )
