"""The gpg shim's command-line contract, tested without an HSM.

`contrib/sq-pkcs11-gpg-shim` translates a gpg command line into an
`sq-pkcs11 sign` invocation.  Everything interesting about it is that
translation, and translation can be checked by substituting a stub for
sq-pkcs11 and looking at the argv it was handed.  No token, no keys, no
containers — so these run in CI.

The shapes exercised here were measured from the real thing: rpm 4.16.1.3 on
EL9 and rpm 4.19.1.1 on EL10, expanding their own `%__gpg_sign_cmd`.  Two
details of that contract are the ones a plausible-looking shim gets wrong:
the package arrives on **stdin** with `-` as the operand, and rpm 4.19 probes
`--version` first and gives up if it fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import child_env

pytestmark = pytest.mark.hermetic


class ShimRunner:
    def __init__(self, shim: Path, stub: Path, record: Path, tmpdir: Path):
        self.shim = shim
        self.stub = stub
        self.record = record
        self.tmpdir = tmpdir

    def run(
        self,
        *args: object,
        stdin: bytes | None = None,
        env: dict[str, str] | None = None,
        exit_code: int = 0,
    ) -> subprocess.CompletedProcess:
        # child_env() already drops the suite's own configuration and the PIN
        # variables; clear the rest of the shim's knobs so each test states
        # exactly what the shim is given.
        child = child_env(
            SQ_PKCS11_BIN=str(self.stub),
            STUB_RECORD=str(self.record),
            STUB_EXIT=str(exit_code),
            TMPDIR=str(self.tmpdir),
        )
        for var in ("SQ_PKCS11_CERT", "SQ_PKCS11_CREATION_TIME", "SQ_PKCS11_KEY_LABEL"):
            child.pop(var, None)
        if env:
            child.update(env)
        return subprocess.run(
            [str(self.shim)] + [str(a) for a in args],
            input=stdin if stdin is not None else b"",
            capture_output=True,
            env=child,
        )

    def records(self) -> list[dict]:
        if not self.record.is_file():
            return []
        return [
            json.loads(line) for line in self.record.read_text().splitlines() if line.strip()
        ]

    def only_record(self) -> dict:
        recs = self.records()
        assert len(recs) == 1, f"expected one sq-pkcs11 invocation, got {len(recs)}: {recs}"
        return recs[0]

    def sign_argv(self) -> list[str]:
        return self.only_record()["argv"]


STUB = Path(__file__).with_name("stub_sq_pkcs11.py")


@pytest.fixture
def shim(shim_path: Path, tmp_path: Path) -> ShimRunner:
    assert os.access(STUB, os.X_OK), f"{STUB} must be executable"
    spool = tmp_path / "spool"
    spool.mkdir()
    return ShimRunner(shim_path, STUB, tmp_path / "record.jsonl", spool)


@pytest.fixture
def package(tmp_path: Path) -> bytes:
    """Stand-in for the bytes rpm pipes in: a package header + payload."""
    return b"\xed\xab\xee\xdb" + bytes(range(256)) * 8


def _argv_value(argv: list[str], flag: str) -> str:
    assert flag in argv, f"{flag} missing from {argv}"
    return argv[argv.index(flag) + 1]


# ---------------------------------------------------------------------------
# The two shapes that ship
# ---------------------------------------------------------------------------


def test_rpm_el9_command_line(shim: ShimRunner, package: bytes, tmp_path: Path):
    """rpm 4.16.1.3, EL9: `--digest-algo X` spelling, `-sbo SIG -`, data on stdin."""
    sig = tmp_path / "pkg.rpm.sig"
    proc = shim.run(
        "--no-verbose",
        "--no-armor",
        "--digest-algo",
        "sha256",
        "--no-secmem-warning",
        "-u",
        "ossl-pgp-signing-key-2026",
        "-sbo",
        sig,
        "-",
        stdin=package,
    )
    assert proc.returncode == 0, proc.stderr.decode()

    argv = shim.sign_argv()
    assert argv[0] == "sign"
    assert "--binary" in argv, "rpm asked for --no-armor; sq-pkcs11 must get --binary"
    assert "--force" in argv, (
        "rpm pre-creates the signature file with mkstemp, so without --force "
        "sq-pkcs11's refuse-to-clobber guard rejects every rpmsign run"
    )
    assert _argv_value(argv, "--key-label") == "ossl-pgp-signing-key-2026"
    assert _argv_value(argv, "--output") == str(sig)

    record = shim.only_record()
    assert record["plaintext_sha256"] == hashlib.sha256(package).hexdigest(), (
        "the bytes signed must be exactly the bytes rpm piped in"
    )
    assert record["plaintext_size"] == len(package)


def test_rpm_el10_command_line(shim: ShimRunner, package: bytes, tmp_path: Path):
    """rpm 4.19.1.1, EL10: `--digest-algo=X`, and `--` before the `-` operand."""
    sig = tmp_path / "pkg.rpm.sig"
    proc = shim.run(
        "--no-verbose",
        "--no-armor",
        "--no-secmem-warning",
        "--digest-algo=sha256",
        "-u",
        "ossl-pgp-signing-key-2026",
        "-sbo",
        sig,
        "--",
        "-",
        stdin=package,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    argv = shim.sign_argv()
    assert "--binary" in argv
    assert _argv_value(argv, "--output") == str(sig)
    assert shim.only_record()["plaintext_sha256"] == hashlib.sha256(package).hexdigest()


def test_version_probe_exits_zero_and_identifies_as_gpg(shim: ShimRunner):
    """rpm 4.19 runs the configured gpg with --version and aborts on failure."""
    proc = shim.run("--version")
    assert proc.returncode == 0, proc.stderr.decode()
    first_line = proc.stdout.decode().splitlines()[0]
    assert first_line.startswith("gpg (GnuPG) "), (
        f"a caller sniffing for GnuPG matches on the first line, got {first_line!r}"
    )
    assert "sq-pkcs11" in proc.stdout.decode(), (
        "the banner must also say plainly what this actually is"
    )


# ---------------------------------------------------------------------------
# Credential hygiene
# ---------------------------------------------------------------------------


def test_ambient_pin_variables_are_removed(shim: ShimRunner, package: bytes, tmp_path: Path):
    """A PIN left in the environment must not reach sq-pkcs11.

    Those variables switch sq-pkcs11 into PKCS#11 login mode.  The signing
    subkey is module-protected and needs login mode None, so an inherited
    value changes which slot is selected — a failure that looks like a key
    lookup problem and has nothing to do with the key.
    """
    proc = shim.run(
        "--no-armor",
        "-u",
        "lbl",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
        env={"SQ_PKCS11_PIN": "leaked", "SQ_PKCS11_SUBKEY_PIN": "leaked-too"},
    )
    assert proc.returncode == 0, proc.stderr.decode()
    record = shim.only_record()
    assert not record["pin_in_env"], "SQ_PKCS11_PIN reached sq-pkcs11"
    assert not record["subkey_pin_in_env"], "SQ_PKCS11_SUBKEY_PIN reached sq-pkcs11"
    assert not any("leaked" in a for a in record["argv"])


def test_pin_file_is_forwarded_when_explicitly_configured(
    shim: ShimRunner, package: bytes, tmp_path: Path
):
    """The explicit opt-in is the only way a credential gets through."""
    pin = tmp_path / "pin"
    pin.write_text("1234")
    proc = shim.run(
        "--no-armor",
        "-u",
        "lbl",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
        env={"SQ_PKCS11_PIN_FILE": str(pin)},
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert _argv_value(shim.sign_argv(), "--pin-file") == str(pin)


# ---------------------------------------------------------------------------
# Environment-supplied configuration
# ---------------------------------------------------------------------------


def test_cert_and_creation_time_are_forwarded(shim: ShimRunner, package: bytes, tmp_path: Path):
    cert = tmp_path / "release.asc"
    cert.write_text("(not parsed by the stub)")
    proc = shim.run(
        "--no-armor",
        "-u",
        "lbl",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
        env={
            "SQ_PKCS11_CERT": str(cert),
            "SQ_PKCS11_CREATION_TIME": "2026-05-26T15:08:47Z",
        },
    )
    assert proc.returncode == 0, proc.stderr.decode()
    argv = shim.sign_argv()
    assert _argv_value(argv, "--input-cert") == str(cert)
    assert _argv_value(argv, "--creation-time") == "2026-05-26T15:08:47Z"


def test_key_label_env_substitutes_for_missing_dash_u(
    shim: ShimRunner, package: bytes, tmp_path: Path
):
    """rpm 4.19 omits -u entirely when %_gpg_name is unset."""
    proc = shim.run(
        "--no-armor",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
        env={"SQ_PKCS11_KEY_LABEL": "from-env"},
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert _argv_value(shim.sign_argv(), "--key-label") == "from-env"


def test_explicit_dash_u_wins_over_the_env_default(
    shim: ShimRunner, package: bytes, tmp_path: Path
):
    """SQ_PKCS11_KEY_LABEL is a default, not an override.

    The conventional precedence — an explicit command-line value beats the
    environment — matters here because the command line is what rpm generated
    from `%_gpg_name`, and that is the setting an operator reaches for first.
    """
    proc = shim.run(
        "--no-armor",
        "-u",
        "from-cli",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
        env={"SQ_PKCS11_KEY_LABEL": "from-env"},
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert _argv_value(shim.sign_argv(), "--key-label") == "from-cli"


# ---------------------------------------------------------------------------
# Option-syntax coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "expect_label"),
    [
        pytest.param(["-u", "lbl", "-sbo", "OUT", "-"], "lbl", id="separate--sbo-cluster"),
        pytest.param(["-ulbl", "-sb", "-o", "OUT", "-"], "lbl", id="-uNAME--o"),
        pytest.param(["--local-user=lbl", "-b", "--output=OUT", "-"], "lbl", id="long-equals"),
        pytest.param(
            ["--default-key", "lbl", "-s", "-b", "-o", "OUT", "-"], "lbl", id="default-key"
        ),
        pytest.param(["-bsulbl", "-o", "OUT", "-"], "lbl", id="cluster-ending-in-u"),
    ],
)
def test_option_spellings(
    shim: ShimRunner, package: bytes, tmp_path: Path, args: list[str], expect_label: str
):
    out = tmp_path / "s.sig"
    argv = [a.replace("OUT", str(out)) for a in args]
    proc = shim.run("--no-armor", *argv, stdin=package)
    assert proc.returncode == 0, proc.stderr.decode()
    got = shim.sign_argv()
    assert _argv_value(got, "--key-label") == expect_label
    assert _argv_value(got, "--output") == str(out)


def test_armor_requests_armored_output(shim: ShimRunner, package: bytes, tmp_path: Path):
    proc = shim.run(
        "--armor",
        "--detach-sign",
        "-u",
        "lbl",
        "-o",
        tmp_path / "s.asc",
        "-",
        stdin=package,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    argv = shim.sign_argv()
    assert "--binary" not in argv, "--armor must not become --binary"
    assert "--cleartext" not in argv


def test_clearsign_maps_to_cleartext(shim: ShimRunner, tmp_path: Path):
    """Repository tooling that builds InRelease calls gpg --clearsign."""
    release = tmp_path / "Release"
    release.write_text("Origin: Test\n")
    proc = shim.run("--clearsign", "-u", "lbl", "-o", tmp_path / "InRelease", release)
    assert proc.returncode == 0, proc.stderr.decode()
    argv = shim.sign_argv()
    assert "--cleartext" in argv
    assert "--binary" not in argv


@pytest.mark.parametrize("spelling", ["--digest-algo sha256", "--digest-algo=sha256"])
def test_digest_algo_is_ignored_but_reported(
    shim: ShimRunner, package: bytes, tmp_path: Path, spelling: str
):
    """sq-pkcs11 picks the digest from the key; say so rather than pretend."""
    proc = shim.run(
        "--no-armor",
        *spelling.split(),
        "-u",
        "lbl",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert "ignoring --digest-algo" in proc.stderr.decode()
    assert not any(a.startswith("--digest-algo") for a in shim.sign_argv()), (
        "sq-pkcs11 has no --digest-algo; forwarding it would abort the signing"
    )


@pytest.mark.parametrize(
    "option",
    [
        "--homedir",
        "--keyring",
        "--secret-keyring",
        "--passphrase-fd",
        "--pinentry-mode",
        "--trust-model",
        "--compress-algo",
    ],
)
def test_ignored_options_do_not_swallow_the_operand(
    shim: ShimRunner, package: bytes, tmp_path: Path, option: str
):
    """Regression: an option whose value is not consumed becomes an operand.

    The value would then be mistaken for a second file to sign, and the shim
    would refuse the whole invocation with "expected exactly one input file".
    """
    proc = shim.run(
        option,
        "some-value",
        "--no-armor",
        "-u",
        "lbl",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
    )
    assert proc.returncode == 0, (
        f"{option} leaked its value into the operand list:\n{proc.stderr.decode()}"
    )
    record = shim.only_record()
    assert "some-value" not in record["argv"]


def test_unknown_option_is_reported_and_ignored(
    shim: ShimRunner, package: bytes, tmp_path: Path
):
    proc = shim.run(
        "--no-armor",
        "--some-future-gpg-flag",
        "-u",
        "lbl",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert "ignoring unrecognised option --some-future-gpg-flag" in proc.stderr.decode()


def test_literal_gpg_operand_is_dropped(shim: ShimRunner, package: bytes, tmp_path: Path):
    """rpm's macro text begins `<path-to-gpg> gpg …`.

    rpm execve()s the path with "gpg" as argv[0], so the word never reaches
    us — but a caller routing the same macro text through a shell leaves it
    behind as an operand.
    """
    proc = shim.run(
        "gpg",
        "--no-verbose",
        "--no-armor",
        "-u",
        "lbl",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert shim.only_record()["plaintext_size"] == len(package)


# ---------------------------------------------------------------------------
# Refusals: things it must not quietly pretend to do
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "operation",
    [
        "--verify",
        "--decrypt",
        "--encrypt",
        "--import",
        "--export",
        "--list-keys",
        "--gen-key",
        "--edit-key",
        "--delete-key",
        "--card-status",
    ],
)
def test_unsupported_operations_fail_loudly(shim: ShimRunner, tmp_path: Path, operation: str):
    proc = shim.run(operation, tmp_path / "whatever")
    assert proc.returncode != 0, f"{operation} must not be silently ignored"
    assert "not supported" in proc.stderr.decode()
    assert shim.records() == [], "nothing may be signed for an unsupported operation"


def test_missing_output_path_streams_to_stdout(shim: ShimRunner, tmp_path: Path):
    """gpg writes to stdout with no -o, and it is how git receives a signature."""
    payload = tmp_path / "f"
    payload.write_text("x")
    proc = shim.run("--no-armor", "-u", "lbl", payload)
    assert proc.returncode == 0, proc.stderr.decode()
    assert _argv_value(shim.sign_argv(), "--output") == "-"


def test_missing_key_fails_with_the_macro_hint(
    shim: ShimRunner, package: bytes, tmp_path: Path
):
    proc = shim.run("--no-armor", "-sbo", tmp_path / "s.sig", "-", stdin=package)
    assert proc.returncode != 0
    stderr = proc.stderr.decode()
    assert "no signing key given" in stderr
    assert "_gpg_name" in stderr, "the error should name the rpm macro to set"


def test_several_operands_fail(shim: ShimRunner, tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_text("a")
    b.write_text("b")
    proc = shim.run("--no-armor", "-u", "lbl", "-o", tmp_path / "s.sig", a, b)
    assert proc.returncode != 0
    assert "exactly one input file" in proc.stderr.decode()


def test_missing_sq_pkcs11_binary_fails_clearly(
    shim: ShimRunner, package: bytes, tmp_path: Path
):
    proc = shim.run(
        "--no-armor",
        "-u",
        "lbl",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
        env={"SQ_PKCS11_BIN": "/nonexistent/sq-pkcs11"},
    )
    assert proc.returncode != 0
    assert "sq-pkcs11 not found" in proc.stderr.decode()


# ---------------------------------------------------------------------------
# Process behaviour
# ---------------------------------------------------------------------------


def test_exit_status_is_forwarded(shim: ShimRunner, package: bytes, tmp_path: Path):
    """rpm decides the signing failed from the exit status alone."""
    proc = shim.run(
        "--no-armor",
        "-u",
        "lbl",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
        exit_code=3,
    )
    assert proc.returncode == 3, (
        "a non-zero exit from sq-pkcs11 must reach rpm unchanged, or a failed "
        "signature would be reported as a success"
    )


def test_stdin_spool_directory_is_cleaned_up(shim: ShimRunner, package: bytes, tmp_path: Path):
    proc = shim.run("--no-armor", "-u", "lbl", "-sbo", tmp_path / "s.sig", "-", stdin=package)
    assert proc.returncode == 0, proc.stderr.decode()
    spooled = Path(shim.only_record()["plaintext"])
    assert not spooled.exists(), "the spooled copy of the package must be removed"
    leftovers = list(shim.tmpdir.iterdir())
    assert leftovers == [], f"spool directory left behind: {leftovers}"


def test_spool_is_cleaned_up_even_when_signing_fails(
    shim: ShimRunner, package: bytes, tmp_path: Path
):
    proc = shim.run(
        "--no-armor",
        "-u",
        "lbl",
        "-sbo",
        tmp_path / "s.sig",
        "-",
        stdin=package,
        exit_code=1,
    )
    assert proc.returncode == 1
    assert list(shim.tmpdir.iterdir()) == [], "spool must be removed on the failure path too"


def test_plaintext_operand_is_guarded_by_double_dash(
    shim: ShimRunner, package: bytes, tmp_path: Path
):
    """So a path beginning with a dash cannot be read as a flag."""
    proc = shim.run("--no-armor", "-u", "lbl", "-sbo", tmp_path / "s.sig", "-", stdin=package)
    assert proc.returncode == 0, proc.stderr.decode()
    argv = shim.sign_argv()
    assert "--" in argv, f"expected `--` before the input path in {argv}"
    assert argv.index("--") == len(argv) - 2, "`--` must immediately precede the operand"


def test_no_operand_at_all_reads_stdin(shim: ShimRunner, package: bytes, tmp_path: Path):
    """gpg's own behaviour: no file operand means read standard input."""
    proc = shim.run("--no-armor", "-u", "lbl", "-o", tmp_path / "s.sig", stdin=package)
    assert proc.returncode == 0, proc.stderr.decode()
    assert shim.only_record()["plaintext_sha256"] == hashlib.sha256(package).hexdigest()
