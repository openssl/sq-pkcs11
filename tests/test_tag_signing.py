"""Signing git tags through the gpg shim.

git is the shim's second caller, and its contract differs from rpm's in two
ways that no argv assertion can prove on its own:

    gpg --status-fd=2 -bsau <keyid> < payload > armored_detached_signature

The signature goes to **stdout** — there is no -o path — and the `SIG_CREATED`
status line is mandatory: git scans for it and fails the signing without it,
however good the signature.  So the tests that matter here let real git emit
the command line and judge the answer.

Verification is deliberately *not* served: `--verify` stays an error, because
gpg and sq already do it and an HSM adds nothing.  That makes `gpg.program` a
per-command setting, which the last test pins down.

Layers: `hermetic` for the translation, `git` for real `git tag -s` with a stub
sq-pkcs11, `pkcs11` for a tag signed on the token and verified with gpg.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from conftest import STABLE_TIME, Gpg, Pkcs11Config, child_env, keyring_for

STUB = Path(__file__).with_name("stub_sq_pkcs11.py")

# What git pipes in: a tag object without its signature.
PAYLOAD = b"object 1e8b2f4c\ntype commit\ntag v1.2.3\ntagger T <t@example.com> 0 +0000\n\nmsg\n"


class ShimRunner:
    def __init__(self, shim: Path, record: Path, tmpdir: Path):
        self.shim = shim
        self.record = record
        self.tmpdir = tmpdir

    def run(self, *args: object, stdin: bytes = PAYLOAD) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.shim)] + [str(a) for a in args],
            input=stdin,
            capture_output=True,
            env=self.env(),
        )

    def env(self) -> dict[str, str]:
        # child_env() drops the suite's own config and the PIN variables; clear
        # the rest so each test states exactly what the shim is given.
        child = child_env(
            SQ_PKCS11_BIN=str(STUB),
            STUB_RECORD=str(self.record),
            TMPDIR=str(self.tmpdir),
        )
        for var in ("SQ_PKCS11_CERT", "SQ_PKCS11_CREATION_TIME", "SQ_PKCS11_KEY_LABEL"):
            child.pop(var, None)
        return child

    def records(self) -> list[dict]:
        if not self.record.is_file():
            return []
        return [
            json.loads(line) for line in self.record.read_text().splitlines() if line.strip()
        ]

    def sign_argv(self) -> list[str]:
        recs = self.records()
        assert len(recs) == 1, f"expected one sq-pkcs11 invocation, got {len(recs)}: {recs}"
        return recs[0]["argv"]


@pytest.fixture
def shim(shim_path: Path, tmp_path: Path) -> ShimRunner:
    assert os.access(STUB, os.X_OK), f"{STUB} must be executable"
    spool = tmp_path / "spool"
    spool.mkdir()
    return ShimRunner(shim_path, tmp_path / "record.jsonl", spool)


def _argv_value(argv: list[str], flag: str) -> str:
    assert flag in argv, f"{flag} missing from {argv}"
    return argv[argv.index(flag) + 1]


# ---------------------------------------------------------------------------
# The command line git emits
# ---------------------------------------------------------------------------


@pytest.mark.hermetic
def test_git_signing_command_line(shim: ShimRunner):
    """git 2.x, verbatim: `--status-fd=2 -bsau <keyid>`, payload on stdin."""
    proc = shim.run("--status-fd=2", "-bsau", "ossl-pgp-signing-key-2026")
    assert proc.returncode == 0, proc.stderr.decode()

    argv = shim.sign_argv()
    assert _argv_value(argv, "--key-label") == "ossl-pgp-signing-key-2026"
    assert _argv_value(argv, "--output") == "-", "git has no -o; it reads stdout"
    assert "--binary" not in argv, "the -a in git's cluster means armored output"
    assert shim.records()[0]["plaintext_sha256"] == hashlib.sha256(PAYLOAD).hexdigest(), (
        "the bytes signed must be exactly the bytes git piped in"
    )


@pytest.mark.hermetic
def test_signature_is_streamed_to_stdout(shim: ShimRunner):
    proc = shim.run("--status-fd=2", "-bsau", "lbl")
    assert proc.returncode == 0, proc.stderr.decode()
    assert b"-----BEGIN PGP SIGNATURE-----" in proc.stdout, (
        f"nothing usable on stdout: {proc.stdout!r}"
    )


@pytest.mark.hermetic
def test_status_fd_gets_a_sig_created_line(shim: ShimRunner):
    """Required, not cosmetic: without it git fails the signing outright."""
    proc = shim.run("--status-fd=2", "-bsau", "lbl")
    assert proc.returncode == 0, proc.stderr.decode()
    assert re.search(rb"^\[GNUPG:\] SIG_CREATED ", proc.stderr, re.MULTILINE), (
        f"git needs this line at a line boundary; got {proc.stderr!r}"
    )


@pytest.mark.hermetic
def test_status_line_is_not_written_onto_the_signature_fd(shim: ShimRunner):
    """On fd 1 the status line would land inside the armor git is reading."""
    proc = shim.run("--status-fd=1", "-bsau", "lbl")
    assert proc.returncode == 0, proc.stderr.decode()
    assert b"SIG_CREATED" not in proc.stdout, f"signature stream corrupted: {proc.stdout!r}"


@pytest.mark.hermetic
def test_no_status_fd_means_no_status_line(shim: ShimRunner):
    """rpm never asks for one, and must not start seeing GnuPG chatter."""
    proc = shim.run("-bsau", "lbl")
    assert proc.returncode == 0, proc.stderr.decode()
    assert b"SIG_CREATED" not in proc.stderr


@pytest.mark.hermetic
@pytest.mark.parametrize(
    ("args", "expect_label"),
    [
        pytest.param(["-bsau", "lbl"], "lbl", id="git-cluster"),
        pytest.param(["-bsa", "-u", "lbl"], "lbl", id="cluster-then--u"),
        pytest.param(["-bsulbl"], "lbl", id="attached-name"),
        pytest.param(["-uossl-pub-2026", "-bsa"], "ossl-pub-2026", id="name-containing-u"),
    ],
)
def test_key_id_spellings(shim: ShimRunner, args: list[str], expect_label: str):
    proc = shim.run("--status-fd=2", *args)
    assert proc.returncode == 0, proc.stderr.decode()
    assert _argv_value(shim.sign_argv(), "--key-label") == expect_label


@pytest.mark.hermetic
def test_missing_key_names_the_git_setting(shim: ShimRunner):
    proc = shim.run("--status-fd=2", "-bsa")
    assert proc.returncode != 0
    stderr = proc.stderr.decode()
    assert "no signing key given" in stderr
    assert "user.signingkey" in stderr, "the error should name the git setting to fix"
    assert shim.records() == []


# ---------------------------------------------------------------------------
# Driven by real git
# ---------------------------------------------------------------------------


class GitRepo:
    """A throwaway repository, insulated from the developer's own git config."""

    def __init__(self, git: str, path: Path):
        self.git = git
        self.path = path

    def run(
        self, *args: object, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess:
        # GIT_CONFIG_GLOBAL/NOSYSTEM: a gpg.program, user.signingkey or
        # tag.gpgSign in the developer's config would decide what these test.
        base = {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
        return subprocess.run(
            [self.git, "-C", str(self.path)] + [str(a) for a in args],
            capture_output=True,
            env={**(env or child_env()), **base},
        )

    def out(self, *args: object, env: dict[str, str] | None = None) -> str:
        proc = self.run(*args, env=env)
        assert proc.returncode == 0, f"git {args}: {proc.stderr.decode()}"
        return proc.stdout.decode()

    def tag_payload(self, tag: str) -> bytes:
        """The tag object without its signature: the bytes git asked us to sign."""
        body = self.out("cat-file", "tag", tag).encode()
        return body.split(b"-----BEGIN PGP SIGNATURE-----")[0]


@pytest.fixture
def repo(git_bin: str, tmp_path: Path) -> GitRepo:
    path = tmp_path / "repo"
    path.mkdir()
    git = GitRepo(git_bin, path)
    git.out("init", "-q", "--initial-branch=main")
    (path / "file").write_text("content\n")
    git.out("add", "file")
    git.out("-c", "commit.gpgsign=false", "commit", "-qm", "initial")
    return git


@pytest.mark.git
def test_real_git_accepts_what_the_shim_produces(
    repo: GitRepo, shim: ShimRunner, shim_path: Path
):
    """The contract end to end, with the stub still standing in for the HSM.

    Everything above asserts against the command line git is *believed* to
    emit.  This lets git emit it and lets git judge the answer, which is the
    only way the SIG_CREATED requirement is actually covered.
    """
    proc = repo.run(
        "-c",
        f"gpg.program={shim_path}",
        "tag",
        "-s",
        "-u",
        "ossl-pgp-signing-key-2026",
        "v1.0.0",
        "-m",
        "release tag",
        env=shim.env(),
    )
    assert proc.returncode == 0, "git rejected the shim's output:\n" + proc.stderr.decode()

    tag = repo.out("cat-file", "tag", "v1.0.0")
    assert "-----BEGIN PGP SIGNATURE-----" in tag, f"tag carries no signature:\n{tag}"
    # And the bytes signed were the tag object git built.
    assert (
        shim.records()[0]["plaintext_sha256"]
        == hashlib.sha256(repo.tag_payload("v1.0.0")).hexdigest()
    )


@pytest.mark.git
def test_verification_through_the_shim_fails_loudly(
    repo: GitRepo, shim: ShimRunner, shim_path: Path
):
    """`git tag -v` must not be answered by a signing shim.

    git runs `gpg.program` for both directions, so a persistent gpg.program
    would route verification here too.  The shim refuses rather than pretend,
    which fails closed — git reports the tag as unverified and can never call a
    bad signature good.  Hence gpg.program is a per-command setting.
    """
    env = shim.env()
    repo.out(
        "-c", f"gpg.program={shim_path}", "tag", "-s", "-u", "lbl", "v1.0.0", "-m", "t", env=env
    )
    signed = len(shim.records())

    proc = repo.run("-c", f"gpg.program={shim_path}", "tag", "-v", "v1.0.0", env=env)
    assert proc.returncode != 0, "verification must not report success"
    assert "not supported" in proc.stderr.decode()
    assert len(shim.records()) == signed, "verification must not sign anything"


# ---------------------------------------------------------------------------
# The whole path: token, tag, and gpg
# ---------------------------------------------------------------------------


@pytest.mark.pkcs11
@pytest.mark.gpg
@pytest.mark.git
def test_tag_signed_on_the_token_verifies_with_gpg(
    repo: GitRepo,
    shim_path: Path,
    sq_pkcs11_bin: Path,
    pkcs11: Pkcs11Config,
    export_cert,
    gpg: Gpg,
    tmp_path: Path,
):
    """A tag signed on the token verifies against the published certificate.

    The point of the round trip is the fingerprint.  `--input-cert` derives the
    key-creation time by matching the HSM key's public material, so the
    signature's issuer fingerprint equals the published key's by construction.
    Get that wrong and everything works right up to a "No public key" verdict.
    """
    cert = export_cert("rsa", userid="Tagger <tag@example.com>", creation_time=STABLE_TIME)

    env = child_env(SQ_PKCS11_BIN=str(sq_pkcs11_bin), SQ_PKCS11_CERT=str(cert))
    if pkcs11.pin_file is not None:
        env["SQ_PKCS11_PIN_FILE"] = str(pkcs11.pin_file)

    signed = repo.run(
        "-c",
        f"gpg.program={shim_path}",
        "tag",
        "-s",
        "-u",
        pkcs11.rsa,
        "v1.0.0",
        "-m",
        "release tag",
        env=env,
    )
    assert signed.returncode == 0, "signing the tag failed:\n" + signed.stderr.decode()

    # Verification is gpg's job, so check it the way an operator would: split
    # the tag object into payload and signature and hand both to gpg.
    tag = repo.out("cat-file", "tag", "v1.0.0").encode()
    marker = b"-----BEGIN PGP SIGNATURE-----"
    payload, _, signature = tag.partition(marker)
    (tmp_path / "payload").write_bytes(payload)
    (tmp_path / "tag.asc").write_bytes(marker + signature)

    keyring_for(gpg, cert, tmp_path / "keyring.gpg")
    result = gpg.run("--verify", tmp_path / "tag.asc", tmp_path / "payload")
    assert result.returncode == 0, f"gpg could not verify the tag:\n{result.stderr}"
    assert "Good signature" in result.stderr, result.stderr
