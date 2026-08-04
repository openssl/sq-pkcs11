"""Shared fixtures for the sq-pkcs11 integration suite.

Every test here drives the compiled binary (and the `contrib/` gpg shim) as a
subprocess.  Nothing imports sq-pkcs11 internals, because there is nothing to
import: the contract under test is the command line.

Layers, selected with `-m`:

    hermetic    nothing external.  A stub stands in for sq-pkcs11, so the
                shim's argument handling is tested with no HSM at all.
    pkcs11      needs a PKCS#11 module plus the configured test keys.  Works
                against SoftHSM2 for development and CI, and against a real
                nShield for the release-signing pass.
    gpg / sq    needs those verifiers on PATH.
    rpm         needs rpmbuild and rpmsign.
    containers  needs podman or docker, to run the consumers' own parsers.

Configuration lives in `tests/test.env` (see `test.env.example`); with no such
file the environment supplies it.  The file wins over the environment, and the
resolved configuration is printed in pytest's header — see the Configuration
section below for why.  The variable names are the ones the previous Rust suite
used, so an existing test.env keeps working.
"""

from __future__ import annotations

import atexit
import os
import re
import shlex
import shutil
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

import pytest

import _inspect
import _softhsm

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_ENV_FILE = REPO_ROOT / "tests" / "test.env"

# Fixed key-creation time, so fingerprints are reproducible from one test
# session to the next.
STABLE_TIME = "2026-01-01T00:00:00Z"

# The five keys the suite expects, and the variable each is read from.
KEY_VARS = {
    "rsa": "SQ_PKCS11_NSHIELD_TEST_RSA",
    "ec": "SQ_PKCS11_NSHIELD_TEST_EC",
    "primary": "SQ_PKCS11_NSHIELD_TEST_PRIMARY",
    "subkey": "SQ_PKCS11_NSHIELD_TEST_SUBKEY",
    "subkey2": "SQ_PKCS11_NSHIELD_TEST_SUBKEY2",
}

# Variables that must never reach sq-pkcs11 from the test runner's own
# environment: they switch it into PKCS#11 login mode, which changes slot
# selection.  A test that wants a PIN says so through SQ_PKCS11_TEST_PIN_FILE.
AMBIENT_PIN_VARS = ("SQ_PKCS11_PIN", "SQ_PKCS11_SUBKEY_PIN")

# Everything the suite treats as its own configuration.  These are resolved once
# below and are *not* read from os.environ again, so a value left over in the
# developer's shell cannot change what the tests exercise.
CONFIG_KEYS = (
    "PKCS11_MODULE_PATH",
    "SQ_PKCS11_MODULE",
    "SOFTHSM2_CONF",
    "SQ_PKCS11_BIN",
    "SQ_PKCS11_GPG_SHIM",
    "SQ_PKCS11_TEST_PIN_FILE",
    "SQ_PKCS11_TEST_CONTAINER_MOUNTS",
    "SQ_PKCS11_TEST_CONTAINER_ARGS",
    *KEY_VARS.values(),
)


# ---------------------------------------------------------------------------
# Configuration
#
# `tests/test.env`, when it exists, *is* the configuration: it decides every key
# in CONFIG_KEYS, and the process environment is not consulted for them.  That
# is deliberate.  With the previous `setdefault` precedence an exported variable
# won, so switching between a real HSM and SoftHSM2 meant remembering to unset
# half a dozen names first — and forgetting to unset SQ_PKCS11_TEST_PIN_FILE
# sent a module-protected key down the login path, which surfaces as the
# thoroughly misleading "ambiguous slot selection".  Configuration a test suite
# depends on should not be something you can be holding by accident.
#
# With no test.env, the environment supplies the config, which is how CI and
# one-off runs work.  Set SQ_PKCS11_TEST_ENV to choose a different file, or to
# `none` to ignore any file and use the environment.
#
# Nothing here mutates os.environ.  Every subprocess is handed an explicitly
# built environment (see `child_env`), so what a command sees is visible at the
# call site rather than inherited from session-wide state.
# ---------------------------------------------------------------------------


# Keys whose value names a file.  A relative one is resolved against the repo
# root, because a committed config cannot know where it was checked out and
# because SOFTHSM2_CONF is read by a child process whose cwd is not ours.
PATH_KEYS = frozenset(
    {
        "PKCS11_MODULE_PATH",
        "SQ_PKCS11_MODULE",
        "SOFTHSM2_CONF",
        "SQ_PKCS11_BIN",
        "SQ_PKCS11_GPG_SHIM",
        "SQ_PKCS11_TEST_PIN_FILE",
    }
)

# `${NAME}` or `${NAME:-fallback}`.  Enough for a committed config to carry a
# sensible default for something that moves between distributions — the SoftHSM
# module lives in a different place on Debian and on Fedora — without turning
# into a set of exports again.
_VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        name, fallback = match.group(1), match.group(2)
        return os.environ.get(name) or (fallback or "")

    return _VAR_REF.sub(replace, value)


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = name.strip()
        value = _expand(value.strip().strip('"').strip("'"))
        if value and name in PATH_KEYS and not Path(value).is_absolute():
            value = str((REPO_ROOT / value).resolve())
        values[name] = value
    return values


def _resolve_config() -> tuple[dict[str, str], Path | None, list[str]]:
    """Return (config, file used, notes about anything overridden or ignored)."""
    selected = os.environ.get("SQ_PKCS11_TEST_ENV")
    if selected == "none":
        source: Path | None = None
    elif selected:
        source = Path(selected)
        if not source.is_file():
            raise RuntimeError(f"SQ_PKCS11_TEST_ENV={selected} does not exist")
        # Resolved, because SQ_PKCS11_TEST_ENV is usually given relative to the
        # working directory and the header below reports the path.
        source = source.resolve()
    else:
        source = TEST_ENV_FILE if TEST_ENV_FILE.is_file() else None

    notes: list[str] = []
    if source is None:
        config = {k: v for k in CONFIG_KEYS if (v := os.environ.get(k))}
        return config, None, notes

    from_file = _read_env_file(source)
    config = {}
    for key in CONFIG_KEYS:
        # An empty value in the file means "explicitly unset", which is how a
        # config can neutralise something rather than only add to it.
        if key in from_file:
            if from_file[key]:
                config[key] = from_file[key]
            if os.environ.get(key) not in (None, from_file[key]):
                notes.append(f"{key}: using {source.name}, ignoring the exported value")
        elif key in os.environ:
            notes.append(f"{key}: exported but not in {source.name}, so ignored")
    return config, source, notes


CONFIG, CONFIG_SOURCE, CONFIG_NOTES = _resolve_config()


def _locate_softhsm_module() -> None:
    """Point a SoftHSM2 module path at wherever this distribution keeps it.

    Only when the configured path names libsofthsm2.so and is not there: any
    other module is a vendor library whose absence is a real problem, and must
    keep skipping with the path the config asked for.  Done at import so the
    header reports the module the run will actually load.
    """
    configured = CONFIG.get("PKCS11_MODULE_PATH", "")
    if not configured.endswith("libsofthsm2.so") or Path(configured).exists():
        return
    found = _softhsm.find_module()
    if found is not None:
        CONFIG["PKCS11_MODULE_PATH"] = found
        CONFIG_NOTES.append(f"PKCS11_MODULE_PATH: {configured} is absent, using {found}")


_locate_softhsm_module()


def pytest_report_header() -> list[str]:
    """Show what the run actually resolved, so it is never a guess."""
    # relpath rather than relative_to: a config file need not live under the
    # repository, and relative_to would raise if it does not.
    where = os.path.relpath(CONFIG_SOURCE, REPO_ROOT) if CONFIG_SOURCE else "the environment"
    lines = [f"sq-pkcs11 config: {where}"]
    module = CONFIG.get("PKCS11_MODULE_PATH") or CONFIG.get("SQ_PKCS11_MODULE")
    lines.append(f"  module:   {module or '<unset — pkcs11 tests will skip>'}")
    labels = [CONFIG.get(var, "?") for var in KEY_VARS.values()]
    lines.append(f"  keys:     {', '.join(labels)}")
    lines.append(
        f"  pin file: {CONFIG.get('SQ_PKCS11_TEST_PIN_FILE') or '<none — module-protected>'}"
    )
    lines += [f"  note:     {note}" for note in CONFIG_NOTES]
    lines += _stray_container_note()
    return lines


def _stray_container_note() -> list[str]:
    """Mention containers a previous session left behind.

    Not removed automatically: another session may be running them right now,
    and yanking its targets mid-test would be worse than the leak.
    """
    runtime = shutil.which("podman") or shutil.which("docker")
    if runtime is None:
        return []
    try:
        found = subprocess.run(
            [runtime, "ps", "-aq", "--filter", f"label={CONTAINER_LABEL_KEY}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    count = len(found.stdout.split())
    if not count:
        return []
    return [
        f"  strays:   {count} container(s) from an earlier run; if no other "
        f"session is active, remove with",
        f"            {runtime} rm -f $({runtime} ps -aq --filter label={CONTAINER_LABEL_KEY})",
    ]


def child_env(**extra: str) -> dict[str, str]:
    """The environment a subprocess gets: the host's, minus what we own.

    Config keys are replaced by the resolved configuration and the PIN variables
    are dropped, so neither can leak in from the shell that started pytest.
    """
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in CONFIG_KEYS and k not in AMBIENT_PIN_VARS
    }
    env.update(CONFIG)
    env.update(extra)
    return env


def _discover_binary() -> Path | None:
    explicit = CONFIG.get("SQ_PKCS11_BIN")
    if explicit:
        path = Path(explicit)
        return path if path.is_file() else None
    for candidate in ("target/release/sq-pkcs11", "target/debug/sq-pkcs11"):
        path = REPO_ROOT / candidate
        if path.is_file():
            return path
    found = shutil.which("sq-pkcs11")
    return Path(found) if found else None


def _discover_shim() -> Path | None:
    explicit = CONFIG.get("SQ_PKCS11_GPG_SHIM")
    if explicit:
        path = Path(explicit)
        return path if path.is_file() else None
    path = REPO_ROOT / "contrib" / "sq-pkcs11-gpg-shim"
    return path if path.is_file() else None


# ---------------------------------------------------------------------------
# Session-scoped configuration fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def sq_pkcs11_bin() -> Path:
    binary = _discover_binary()
    if binary is None:
        pytest.skip(
            "sq-pkcs11 binary not found — run `cargo build --release`, or set "
            "SQ_PKCS11_BIN to its path"
        )
    return binary


@pytest.fixture(scope="session")
def shim_path() -> Path:
    shim = _discover_shim()
    if shim is None:
        pytest.skip("contrib/sq-pkcs11-gpg-shim not found; set SQ_PKCS11_GPG_SHIM")
    return shim


class Pkcs11Config:
    """Validated PKCS#11 test configuration."""

    def __init__(self, module: Path, labels: dict[str, str], pin_file: Path | None):
        self.module = module
        self.labels = labels
        self.pin_file = pin_file

    def __getattr__(self, name: str) -> str:
        # Lets tests say `pkcs11.rsa` instead of `pkcs11.labels["rsa"]`.
        if name in KEY_VARS:
            return self.labels[name]
        raise AttributeError(name)


@pytest.fixture(scope="session")
def softhsm_token(request: pytest.FixtureRequest) -> None:
    """Provision the SoftHSM2 token, when SoftHSM2 is what the config names.

    SOFTHSM2_CONF is that signal: a real HSM's configuration has no such key and
    this does nothing.  Provisioning belongs here rather than in a script the
    developer and CI both have to remember to run first — the token, its PIN file
    and its five keys are all named by the config, so deriving them from it
    keeps one source of truth for the paths and labels.

    Session-scoped and idempotent, so the cost on a run whose token already
    exists is one `softhsm2-util --show-slots`.
    """
    conf = CONFIG.get("SOFTHSM2_CONF")
    if not conf:
        return
    pin_file = CONFIG.get("SQ_PKCS11_TEST_PIN_FILE")
    if not pin_file:
        pytest.skip(
            "SOFTHSM2_CONF is set but SQ_PKCS11_TEST_PIN_FILE is not, so there is no PIN"
        )
    labels = {kind: CONFIG.get(var, "") for kind, var in KEY_VARS.items()}
    if not all(labels.values()):
        return  # `pkcs11` reports which ones are missing.
    module = CONFIG.get("PKCS11_MODULE_PATH") or CONFIG.get("SQ_PKCS11_MODULE", "")
    try:
        created = _softhsm.provision(Path(conf), Path(module), labels, Path(pin_file))
    except _softhsm.Unavailable as exc:
        pytest.skip(f"SoftHSM2: {exc}")
    if created:
        # Through the terminal reporter, not print: creating a token and five
        # keypairs is worth seeing, and fixture output is otherwise captured and
        # shown only if something fails.
        reporter = request.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(f"provisioned SoftHSM2: {', '.join(created)}")


@pytest.fixture(scope="session")
def pkcs11(sq_pkcs11_bin: Path, softhsm_token: None) -> Pkcs11Config:
    """PKCS#11 module + test key labels, verified to actually be present.

    Skips — with the reason, not silently — when the module is absent or a
    configured label is missing from the token.  A stale test.env that names
    keys nobody provisioned used to let every test run and fail deep inside a
    key lookup; catching it once here is both faster and clearer.
    """
    module = CONFIG.get("PKCS11_MODULE_PATH") or CONFIG.get("SQ_PKCS11_MODULE", "")
    if not module:
        pytest.skip("PKCS11_MODULE_PATH is not set (tests/test.env missing or incomplete?)")
    module_path = Path(module)
    if not module_path.exists():
        pytest.skip(f"PKCS#11 module {module} does not exist (vendor client not installed?)")

    missing = [var for var in KEY_VARS.values() if not CONFIG.get(var)]
    if missing:
        pytest.skip(f"not set in tests/test.env: {', '.join(missing)}")
    labels = {kind: CONFIG[var] for kind, var in KEY_VARS.items()}

    pin_file_env = CONFIG.get("SQ_PKCS11_TEST_PIN_FILE")
    pin_file = Path(pin_file_env) if pin_file_env else None
    if pin_file is not None and not pin_file.is_file():
        pytest.skip(f"SQ_PKCS11_TEST_PIN_FILE={pin_file} does not exist")

    config = Pkcs11Config(module_path, labels, pin_file)

    # Probe the token once: the module loads, and every configured label
    # really is there.
    argv = [str(sq_pkcs11_bin), "list-keys"]
    if pin_file is not None:
        argv += ["--pin-file", str(pin_file)]
    proc = subprocess.run(argv, capture_output=True, text=True, env=child_env())
    if proc.returncode != 0:
        pytest.skip("sq-pkcs11 list-keys failed (HSM unreachable?):\n" + proc.stderr.strip())
    for kind, label in labels.items():
        # list-keys prints `  label="<value>"  id=<hex>  type=<...>`; match the
        # quoted form so one label cannot pass as a substring of another.
        if f'label="{label}"' not in proc.stdout:
            pytest.skip(
                f"{KEY_VARS[kind]}={label} is not present in the token; check "
                "tests/test.env and run `sq-pkcs11 list-keys`"
            )
    return config


# ---------------------------------------------------------------------------
# Command runners
# ---------------------------------------------------------------------------


class Result:
    """A finished subprocess, with assertion helpers that print diagnostics."""

    def __init__(self, proc: subprocess.CompletedProcess, argv: Sequence[str]):
        self.proc = proc
        self.argv = list(argv)

    @property
    def returncode(self) -> int:
        return self.proc.returncode

    @property
    def stdout(self) -> str:
        return self.proc.stdout.decode("utf-8", "replace")

    @property
    def stderr(self) -> str:
        return self.proc.stderr.decode("utf-8", "replace")

    @property
    def stdout_bytes(self) -> bytes:
        return self.proc.stdout

    def _detail(self) -> str:
        return (
            f"\ncommand: {' '.join(self.argv)}"
            f"\nexit: {self.returncode}"
            f"\nstdout: {self.stdout}"
            f"\nstderr: {self.stderr}"
        )

    def success(self) -> Result:
        assert self.returncode == 0, "expected success" + self._detail()
        return self

    def failure(self) -> Result:
        assert self.returncode != 0, "expected failure" + self._detail()
        return self


class SqPkcs11:
    """Runs the sq-pkcs11 binary against the configured token.

    Two conveniences, both of which matter for running the same tests against
    SoftHSM2 and against a module-protected nShield key:

    * ambient `SQ_PKCS11_PIN` / `SQ_PKCS11_SUBKEY_PIN` are stripped from the
      child environment, so a value in the developer's shell cannot change
      which slot gets selected;
    * `--pin-file` (and `--subkey-pin-file`, when a subkey selector is
      present) are appended when `SQ_PKCS11_TEST_PIN_FILE` is configured.
      SoftHSM tokens always require a C_Login; a module-protected nShield key
      must not get one.  Tests that exercise authentication itself pass
      `auth=False` and supply their own flags.
    """

    def __init__(self, binary: Path, config: Pkcs11Config | None):
        self.binary = binary
        self.config = config

    def run(
        self,
        *args: object,
        auth: bool = True,
        stdin: bytes | None = None,
        env: dict[str, str] | None = None,
    ) -> Result:
        argv: list[str] = [str(self.binary)] + [str(a) for a in args]
        pin_file = self.config.pin_file if (self.config and auth) else None
        if pin_file is not None:
            if "--pin-file" not in argv:
                argv += ["--pin-file", str(pin_file)]
            if (
                any(
                    a.startswith("--subkey-")
                    and a in ("--subkey-label", "--subkey-id", "--subkey-uri", "--subkey-auto")
                    for a in argv
                )
                and "--subkey-pin-file" not in argv
            ):
                argv += ["--subkey-pin-file", str(pin_file)]
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            env=env if env is not None else child_env(),
        )
        return Result(proc, argv)


@pytest.fixture(scope="session")
def sqp11(sq_pkcs11_bin: Path, pkcs11: Pkcs11Config) -> SqPkcs11:
    # Session-scoped: the runner holds no per-test state, and the
    # session-scoped artefact fixtures in test_package_signing.py need it.
    return SqPkcs11(sq_pkcs11_bin, pkcs11)


# ---------------------------------------------------------------------------
# External verifiers
# ---------------------------------------------------------------------------


def _require(tool: str) -> str:
    found = shutil.which(tool)
    if not found:
        pytest.skip(f"{tool} is not installed")
    return found


class Gpg:
    """gpg bound to a throwaway keyring directory."""

    def __init__(self, home: Path):
        self.home = home

    def run(self, *args: object, check: bool = False) -> Result:
        argv = [_require("gpg"), "--batch", "--no-tty"] + [str(a) for a in args]
        env = dict(os.environ, GNUPGHOME=str(self.home), GPG_TTY="")
        proc = subprocess.run(argv, capture_output=True, env=env)
        result = Result(proc, argv)
        if check:
            result.success()
        return result

    def import_(self, *paths: object) -> Gpg:
        self.run("--import", *paths, check=True)
        return self

    def export_keyring(self, dest: Path) -> Path:
        """gpgv wants an exported keyring, not armor."""
        result = self.run("--export", check=True)
        dest.write_bytes(result.stdout_bytes)
        assert dest.stat().st_size > 0, "exported keyring is empty"
        return dest

    def colons(self, *args: object) -> list[str]:
        result = self.run("--with-colons", *args, check=True)
        return result.stdout.splitlines()

    def list_keys(self) -> list[str]:
        return self.colons("--list-keys")

    def field(self, lines: Sequence[str], prefix: str, index: int) -> str:
        """Column `index` (0-based) of the first `prefix:` line."""
        for line in lines:
            if line.startswith(prefix + ":"):
                return line.split(":")[index]
        raise AssertionError(f"no {prefix}: line in:\n" + "\n".join(lines))


@pytest.fixture
def gpg_home(tmp_path: Path):
    home = tmp_path / "gnupg"
    home.mkdir()
    home.chmod(stat.S_IRWXU)  # gpg insists on 0700
    yield home
    # Importing a key starts a gpg-agent (and scdaemon) that daemonises and
    # outlives pytest, one pair per test, each holding sockets in a directory
    # we are about to forget about.  Ask them to stop.
    gpgconf = shutil.which("gpgconf")
    if gpgconf is not None:
        subprocess.run(
            [gpgconf, "--homedir", str(home), "--kill", "all"],
            capture_output=True,
            timeout=30,
        )


@pytest.fixture
def gpg(gpg_home: Path) -> Gpg:
    _require("gpg")
    return Gpg(gpg_home)


@pytest.fixture
def gpgv():
    """Detached/cleartext verification the way apt does it."""
    binary = _require("gpgv")

    def _verify(keyring: Path, *args: object) -> Result:
        argv = [binary, "--keyring", str(keyring)] + [str(a) for a in args]
        proc = subprocess.run(argv, capture_output=True)
        return Result(proc, argv)

    return _verify


class Sq:
    """Stock Sequoia sq — a second, independent OpenPGP implementation."""

    def __init__(self, home: Path):
        self.home = home

    def run(self, *args: object, check: bool = False) -> Result:
        argv = [_usable_sq(), "--home", str(self.home), "--batch"] + [str(a) for a in args]
        proc = subprocess.run(argv, capture_output=True)
        result = Result(proc, argv)
        if check:
            result.success()
        return result


def _usable_sq() -> str:
    """sq, checked for version — shared with _inspect so there is one rule.

    An old sq is worse than none: it is found on PATH and then parses arguments
    differently, so a test fails confusingly instead of skipping.
    """
    binary, reason = _inspect._sq_probe()
    if binary is None:
        pytest.skip(reason or "sq is unusable")
    return binary


@pytest.fixture
def sq(tmp_path: Path) -> Sq:
    home = tmp_path / "sq"
    home.mkdir()
    home.chmod(stat.S_IRWXU)
    _usable_sq()
    return Sq(home)


@pytest.fixture(scope="session")
def container_runtime() -> str:
    for candidate in ("podman", "docker"):
        found = shutil.which(candidate)
        if found:
            return found
    pytest.skip("neither podman nor docker is available")


# ---------------------------------------------------------------------------
# Target containers
#
# pytest always runs on the host.  It is never installed into, or executed
# inside, a target image — otherwise the suite would have to cope with whatever
# Python each distribution ships, which is the thing this arrangement avoids.
# A target is a long-lived container driven over `podman exec`, the same shape
# the openssl-packages suite uses: started detached, prerequisites installed
# once, removed on teardown.  Not one container per test.
#
# rpm targets get the signing environment bind-mounted as well, so `rpmsign`
# runs against the token from inside the container.  That is worth the extra
# wiring: rpm 4.16 and 4.19 expand %__gpg_sign_cmd differently, and only real
# rpmsign of that version exercises its own contract.
# ---------------------------------------------------------------------------

# Every container this session starts carries this label, so teardown can find
# one whose id we lost — and so a container that escapes a hard kill can still
# be identified afterwards.
CONTAINER_LABEL_KEY = "sq-pkcs11-tests"
CONTAINER_LABEL = f"{CONTAINER_LABEL_KEY}={uuid4().hex[:12]}"

# (runtime, container id) for everything still running.
_STARTED: set[tuple[str, str]] = set()


def _sweep_containers() -> None:
    """Remove every container this session started.  Idempotent.

    Called from the fixture's own teardown, from pytest_sessionfinish, and from
    atexit, because a Ctrl-C can land in any of several places — including
    inside the subprocess call that creates a container, before the fixture has
    a finaliser to run.  The label pass catches ids that never made it into the
    registry.
    """
    for runtime, cid in sorted(_STARTED):
        subprocess.run([runtime, "rm", "-f", cid], capture_output=True, timeout=120)
    _STARTED.clear()
    for runtime in ("podman", "docker"):
        if not shutil.which(runtime):
            continue
        found = subprocess.run(
            [runtime, "ps", "-aq", "--filter", f"label={CONTAINER_LABEL}"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        for cid in found.stdout.split():
            subprocess.run([runtime, "rm", "-f", cid], capture_output=True, timeout=120)


atexit.register(_sweep_containers)


def pytest_sessionfinish() -> None:
    _sweep_containers()


# Fixed paths the signing environment is mounted at inside a target.
IN_BINARY = "/opt/sq-pkcs11/sq-pkcs11"
IN_SHIM = "/opt/sq-pkcs11/sq-pkcs11-gpg-shim"
IN_PIN = "/opt/sq-pkcs11/pin"

# Ceilings for a command in a target.  Generous, because signing waits on an HSM
# and installing a package waits on a mirror; the point is only that neither can
# wait forever.
EXEC_TIMEOUT = 300.0
SETUP_TIMEOUT = 600.0


class Target:
    """A target distribution's own tooling, reachable over `podman exec`."""

    def __init__(self, runtime: str, family: str, image: str, note: str, cid: str):
        self.runtime = runtime
        self.family = family
        self.image = image
        self.note = note
        self.cid = cid
        # Environment every command in this target gets; populated for rpm
        # targets, which need to reach the token.
        self.env: dict[str, str] = {}

    def run(
        self,
        command: str,
        check: bool = False,
        env: dict[str, str] | None = None,
        timeout: float = EXEC_TIMEOUT,
    ) -> Result:
        argv = [self.runtime, "exec"]
        for name, value in {**self.env, **(env or {})}.items():
            argv += ["--env", f"{name}={value}"]
        argv += [self.cid, "bash", "-c", command]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as expired:
            # Bounded, because a container command can wait forever: a package
            # manager whose mirror accepts the connection and then stalls, or
            # anything that turns out to want input.  A test that reports a
            # timeout can be diagnosed; a session that hangs cannot.
            proc = subprocess.CompletedProcess(
                argv,
                124,  # what `timeout(1)` reports, for the same reason
                expired.stdout or b"",
                (expired.stderr or b"") + f"timed out after {timeout:g}s".encode(),
            )
        result = Result(proc, argv)
        if check:
            assert result.returncode == 0, f"on {self.image}:{result._detail()}"
        return result

    def out(self, command: str, env: dict[str, str] | None = None) -> str:
        return (self.run(command, check=True, env=env).stdout).strip()

    def copy_out(self, src: str, dest: Path) -> Path:
        """Copy a file out of the container, so another target can read it.

        Used to hand a package signed in one target to the targets that verify
        it, which is the production topology: the signing host and the consumer
        are different machines running different distributions.
        """
        proc = subprocess.run(
            [self.runtime, "cp", f"{self.cid}:{src}", str(dest)],
            capture_output=True,
            timeout=EXEC_TIMEOUT,
        )
        assert proc.returncode == 0, (
            f"copying {src} out of {self.image}: {proc.stderr.decode()}"
        )
        return dest

    def __repr__(self) -> str:
        return f"<Target {self.image}>"


def _apt_install(package: str) -> str:
    """Install one package, without waiting on a mirror that never answers.

    The Acquire options matter on a restricted network: apt's default is a long
    timeout and several retries per URI, so an unreachable archive costs minutes
    per index file before failing.
    """
    return (
        "{ export DEBIAN_FRONTEND=noninteractive; "
        "apt-get update -qq -o Acquire::Retries=1 -o Acquire::http::Timeout=20 "
        "-o Acquire::https::Timeout=20 && "
        f"apt-get install -y -qq --no-install-recommends {package}; }}"
    )


# Prerequisites each family needs, each guarded on what it installs: a base
# image that already has the tool must not reach for the network, because
# `apt-get update` against an archived release is exactly where a run on a
# restricted network stalls.  Output is left alone rather than redirected to
# /dev/null — it is captured either way, and it is what the skip message says.
_TARGET_SETUP = {
    "rpm": "command -v rpmbuild >/dev/null || dnf install -y -q rpm-build rpm-sign",
    # The deb images ship gpgv already: apt depends on it to verify a Release
    # file, which is the very thing being tested here.
    "deb": "command -v gpgv >/dev/null || " + _apt_install("gpgv"),
    # Debian's `rpm` package carries rpmbuild and rpmsign.  This is what the
    # signing host runs, so it is the signer in the production-topology test.
    "deb-rpm": "command -v rpmsign >/dev/null || " + _apt_install("rpm"),
}


@pytest.fixture(scope="session")
def artifacts(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Host directory every target sees, read-only, at /artifacts.

    Bind-mounted when the container starts but written to as tests run — a bind
    mount shows the host's writes live, so artefacts can be produced later in
    the session and still be visible.
    """
    path = tmp_path_factory.mktemp("artifacts")
    path.chmod(0o755)
    return path


def _softhsm_token_dir(config: Path) -> Path | None:
    """`directories.tokendir` out of a softhsm2.conf, if that is what we have.

    The only vendor-specific knowledge here, and it exists so the common
    development setup needs no extra configuration.  Anything else — /opt/nfast,
    say — is listed in SQ_PKCS11_TEST_CONTAINER_MOUNTS.
    """
    try:
        for line in config.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() == "directories.tokendir":
                return Path(value.strip())
    except OSError:
        return None
    return None


def _signing_mounts(
    binary: Path, shim: Path, pkcs11: Pkcs11Config
) -> tuple[list[str], dict[str, str]]:
    """Bind-mount arguments and environment that let a target reach the token."""
    mounts = [
        f"{binary}:{IN_BINARY}:ro",
        f"{shim}:{IN_SHIM}:ro",
        # The module has to keep its host path, because that is what
        # PKCS11_MODULE_PATH names.
        f"{pkcs11.module}:{pkcs11.module}:ro",
    ]
    env = {"PKCS11_MODULE_PATH": str(pkcs11.module), "SQ_PKCS11_BIN": IN_BINARY}

    if pkcs11.pin_file is not None:
        mounts.append(f"{pkcs11.pin_file}:{IN_PIN}:ro")
        env["SQ_PKCS11_PIN_FILE"] = IN_PIN

    softhsm_conf = CONFIG.get("SOFTHSM2_CONF")
    if softhsm_conf:
        conf = Path(softhsm_conf)
        mounts.append(f"{conf}:{conf}:ro")
        env["SOFTHSM2_CONF"] = str(conf)
        tokens = _softhsm_token_dir(conf)
        if tokens is not None and tokens.is_dir():
            # Read-write: the store is opened for update even when only signing.
            mounts.append(f"{tokens}:{tokens}:rw")

    # Comma-separated, each optionally suffixed `:ro` (the default) or `:rw`.
    # /opt/nfast wants `:rw`: the module reaches the hardserver over a unix
    # socket under it, and connecting to a socket needs write permission on the
    # socket inode, so a read-only bind fails with EACCES.
    for extra in CONFIG.get("SQ_PKCS11_TEST_CONTAINER_MOUNTS", "").split(","):
        extra = extra.strip()
        if not extra:
            continue
        path, _, mode = extra.rpartition(":")
        if mode not in ("ro", "rw"):
            path, mode = extra, "ro"
        mounts.append(f"{path}:{path}:{mode}")

    # Vendor knobs the module itself reads (nShield's CKNFAST_*, for instance).
    for name, value in os.environ.items():
        if name.startswith("CKNFAST_"):
            env[name] = value
    return mounts, env


def _start_target(
    runtime: str,
    family: str,
    image: str,
    note: str,
    artifacts: Path,
    extra_mounts: Sequence[str] = (),
) -> Target:
    argv = [
        runtime,
        "run",
        "-d",
        "--label",
        CONTAINER_LABEL,
        "-v",
        f"{artifacts}:/artifacts:ro",
    ]
    for mount in extra_mounts:
        argv += ["-v", mount]
    # Whatever else the token needs from the runtime.  Under rootless podman an
    # nShield wants `--group-add keep-groups`, which carries the host's
    # supplementary groups in so the hardserver socket's `nfast` group applies.
    # Note what NOT to use: `--userns=keep-id` runs the container as your own
    # user rather than root, and the targets install their own tooling, so
    # package installation then fails.
    if extra_mounts:
        argv += shlex.split(CONFIG.get("SQ_PKCS11_TEST_CONTAINER_ARGS", ""))
    argv += [image, "sleep", "infinity"]
    try:
        # Bounded: this pulls the image when it is not local yet.
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=SETUP_TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.skip(f"starting {image} timed out after {SETUP_TIMEOUT:g}s (slow image pull?)")
    if proc.returncode != 0:
        pytest.skip(f"could not start {image}: {proc.stderr.strip()}")
    target = Target(runtime, family, image, note, proc.stdout.strip())
    _STARTED.add((runtime, target.cid))
    setup = target.run(_TARGET_SETUP[family], timeout=SETUP_TIMEOUT)
    if setup.returncode != 0:
        # Preparing a target is environment, not product: a container that
        # cannot install its own tooling — no network, or not running as root
        # because SQ_PKCS11_TEST_CONTAINER_ARGS made it someone else — is a
        # reason to skip with the message, not to fail.  Remove the container
        # first; the fixture's cleanup has not been armed yet.
        _remove_container(runtime, target.cid)
        detail = (setup.stderr or setup.stdout).strip().splitlines()
        pytest.skip(f"could not prepare {image}: {detail[-1] if detail else 'no output'}")
    return target


def _remove_container(runtime: str, cid: str) -> None:
    subprocess.run([runtime, "rm", "-f", cid], capture_output=True, timeout=120)
    _STARTED.discard((runtime, cid))


def _target_fixture(targets: Sequence[tuple[str, str, str]], signing: bool = False):
    """A session-scoped fixture parametrized over `targets`."""

    @pytest.fixture(scope="session", params=targets, ids=[image for _, image, _ in targets])
    def _fixture(request, container_runtime: str, artifacts: Path):
        family, image, note = request.param
        mounts: list[str] = []
        env: dict[str, str] = {}
        if signing:
            binary = request.getfixturevalue("sq_pkcs11_bin")
            shim = request.getfixturevalue("shim_path")
            config = request.getfixturevalue("pkcs11")
            mounts, env = _signing_mounts(binary, shim, config)

        target = _start_target(container_runtime, family, image, note, artifacts, mounts)
        target.env = env
        try:
            if signing:
                # The binary is built on the host, so it may not run here at
                # all, and the module may not load.  Find out once, with a
                # reason, rather than failing inside every test.
                pin = f" --pin-file {IN_PIN}" if "SQ_PKCS11_PIN_FILE" in env else ""
                probe = target.run(f"{IN_BINARY} list-keys{pin}")
                if probe.returncode != 0:
                    pytest.skip(
                        f"the token is not reachable from {image}: "
                        f"{(probe.stderr or probe.stdout).strip().splitlines()[-1:]}"
                        " — a host-built binary need not run on the target, and "
                        "the module has to be mountable (see "
                        "SQ_PKCS11_TEST_CONTAINER_MOUNTS)"
                    )
            yield target
        finally:
            _remove_container(container_runtime, target.cid)

    return _fixture


# The two rpm OpenPGP implementations that matter: EL9 uses rpm's own parser,
# EL10 delegates to rpm-sequoia.  They disagree about ECDSA, which is what
# decides the packaging key's algorithm — and they drive the gpg shim with
# different command lines, so each signs for itself here.
rpm_target = _target_fixture(
    [
        ("rpm", "almalinux:9", "rpm 4.16, internal OpenPGP parser"),
        ("rpm", "almalinux:10", "rpm 4.19, rpm-sequoia"),
    ],
    signing=True,
)

# The production topology: the signing host is Debian, the consumers are EL.
# Signing there and verifying on EL is the pairing the pipeline actually uses,
# and nothing about it is implied by either side working in isolation — Debian's
# rpm 4.20 writes the signature, EL9's rpm 4.16 has to read it.
deb_signer = _target_fixture(
    [("deb-rpm", "debian:13", "rpm 4.20 — the signing host's own rpmsign")],
    signing=True,
)

# The oldest apt verifiers we target.  A newer gpgv accepting an InRelease says
# little; these are where a marginal encoding shows up.
apt_target = _target_fixture(
    [
        ("deb", "debian:11", "gpgv 2.2.27"),
        ("deb", "ubuntu:20.04", "gpgv 2.2.19"),
    ]
)


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def work(tmp_path: Path) -> Path:
    """Per-test scratch directory (pytest keeps the last few runs on disk)."""
    return tmp_path


@pytest.fixture
def export_cert(sqp11: SqPkcs11, pkcs11: Pkcs11Config, tmp_path: Path):
    """Export a certificate, single-tier or two-tier.

    Most tests need a cert only as a starting point, and spelling out the same
    eight flags each time buries what the test is actually about.
    """

    def _export(
        key: str = "rsa",
        *,
        userid: str = "Test <test@example.com>",
        creation_time: str = STABLE_TIME,
        subkey: str | None = None,
        subkey_creation_time: str = STABLE_TIME,
        name: str = "cert.asc",
        extra: Sequence[object] = (),
        merge: Path | None = None,
        expect_success: bool = True,
    ) -> Path:
        if subkey is not None and pkcs11.pin_file is not None:
            # A two-tier export authenticates each tier independently, so it
            # opens two sessions and logs into both.  On a module whose login
            # state is token-wide rather than per-session — SoftHSM2, and any
            # token where both tiers share one softcard — the second C_Login
            # returns CKR_USER_ALREADY_LOGGED_IN and the export fails.
            #
            # The deployment this is built for does not hit that: the primary is
            # OCS-quorum (authenticated out of band by `preload`, so login mode
            # None) and the signing subkey is module-protected (login mode None
            # too), and no C_Login happens at all.  So these tests do run on the
            # real HSM; they just cannot run against a PIN-protected token.
            pytest.skip(
                "two-tier cert-export needs two logins on one token, which a "
                "login-required module refuses (CKR_USER_ALREADY_LOGGED_IN); "
                "run this against module-protected keys"
            )

        dest = tmp_path / name
        args: list[object] = ["cert-export", "--key-label", pkcs11.labels[key]]
        if merge is not None:
            args += ["--merge-cert", merge]
        if subkey is not None:
            args += [
                "--subkey-label",
                pkcs11.labels[subkey],
                "--subkey-creation-time",
                subkey_creation_time,
            ]
        if userid:
            args += ["--userid", userid]
        args += ["--creation-time", creation_time, "--output", dest]
        args += list(extra)
        result = sqp11.run(*args)
        if expect_success:
            result.success()
        return dest

    return _export


@pytest.fixture
def two_tier_cert(export_cert):
    """A Certify-only primary plus a signing subkey, both at STABLE_TIME.

    The structure this repo recommends for release signing, and the input most
    of the revocation and verify-signing-key tests need.
    """
    return export_cert("primary", subkey="subkey", userid="Two Tier <2t@example.com>")


def keyring_for(gpg: Gpg, cert: Path, dest: Path) -> Path:
    """Import `cert` and export a binary keyring `gpgv` can use."""
    gpg.import_(cert)
    return gpg.export_keyring(dest)


def concat(dest: Path, *sources: Path) -> Path:
    """Concatenate OpenPGP files.

    GnuPG silently drops a standalone subkey revocation imported on its own,
    and only attaches it when it arrives in the same stream as the cert — the
    same workaround real consumers have to apply.
    """
    dest.write_bytes(b"".join(p.read_bytes() for p in sources))
    return dest
