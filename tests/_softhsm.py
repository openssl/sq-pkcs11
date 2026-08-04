"""Provisioning for a SoftHSM2 token, so a development run needs no setup step.

Everything here is `softhsm2-util` and `pkcs11-tool` in a subprocess, and every
step is idempotent: an existing token and its keys are left alone, so this costs
one `--show-slots` on a run that has nothing to do.

Nothing here can touch a real HSM.  It only ever writes inside the directory
holding the SOFTHSM2_CONF the configuration names, and it is called only when
the configuration names one at all.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

# The token the suite creates.  The PIN is only meaningful to a software token
# in a gitignored directory; a real HSM's PIN comes from a file the operator
# writes and is never generated here.
TOKEN_LABEL = "sqp11-test"
SO_PIN = "12345678"
DEFAULT_PIN = "1234"

# Key type per kind in KEY_VARS.  RSA-4096 and P-384 mirror the nShield test
# keys; the three P-256 keys stand in for the tiers of a two-tier cert, where
# the algorithm does not matter and generation time does.
KEY_TYPES = {
    "rsa": "rsa:4096",
    "ec": "EC:secp384r1",
    "primary": "EC:prime256v1",
    "subkey": "EC:prime256v1",
    "subkey2": "EC:prime256v1",
}

# libsofthsm2.so moves between distributions.
MODULE_CANDIDATES = (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
)

_LABEL_LINE = re.compile(r"^\s*label:\s*(\S.*?)\s*$", re.MULTILINE)


class Unavailable(Exception):
    """SoftHSM2 cannot be provisioned here.  The message says why."""


def find_module() -> str | None:
    """Where this distribution keeps libsofthsm2.so, if it has it."""
    for candidate in MODULE_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def _run(argv: list[str], env: dict[str, str], what: str) -> str:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=600)
    except FileNotFoundError:
        raise Unavailable(
            f"{argv[0]} not found, so {what} is not possible.  "
            "Debian/Ubuntu: apt install softhsm2 opensc.  Fedora/EL: dnf install softhsm opensc"
        ) from None
    except subprocess.SubprocessError as exc:
        raise Unavailable(f"{what} failed: {exc}") from None
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        raise Unavailable(f"{what} failed: {detail[-1] if detail else 'no output'}")
    return proc.stdout


def provision(conf: Path, module: Path, labels: dict[str, str], pin_file: Path) -> list[str]:
    """Make the token and keys the configuration names exist.

    `conf` is the SOFTHSM2_CONF path; its parent directory holds the token
    store.  Returns a description of what had to be created, empty when
    everything was already there.
    """
    if not module.exists():
        raise Unavailable(f"{module} does not exist; install softhsm2 or set SOFTHSM_MODULE")

    state = conf.parent
    (state / "tokens").mkdir(parents=True, exist_ok=True)
    if not conf.exists():
        conf.write_text(
            "# Written by the test suite; edit tests/softhsm.env instead.\n"
            f"directories.tokendir = {state / 'tokens'}\n"
            "objectstore.backend = file\n"
            "log.level = ERROR\n"
        )
    if not pin_file.exists():
        pin_file.parent.mkdir(parents=True, exist_ok=True)
        pin_file.write_text(DEFAULT_PIN)
        pin_file.chmod(0o600)
    pin = pin_file.read_text().strip()

    # softhsm2-util and the module both find the token store this way.  PATH is
    # the caller's, so a softhsm2 installed somewhere unusual still resolves.
    env = {"SOFTHSM2_CONF": str(conf), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    created = []

    if TOKEN_LABEL not in _run(
        ["softhsm2-util", "--show-slots"], env, "listing SoftHSM2 slots"
    ):
        _run(
            # --free: whichever uninitialised slot is available.
            [
                "softhsm2-util",
                "--init-token",
                "--free",
                "--label",
                TOKEN_LABEL,
                "--so-pin",
                SO_PIN,
                "--pin",
                pin,
            ],
            env,
            f"initialising token {TOKEN_LABEL}",
        )
        created.append(f"token {TOKEN_LABEL}")

    pkcs11_tool = ["pkcs11-tool", "--module", str(module), "--login", "--pin", pin]
    listing = _run([*pkcs11_tool, "--list-objects"], env, "listing token objects")
    present = set(_LABEL_LINE.findall(listing))
    for index, (kind, key_type) in enumerate(KEY_TYPES.items(), start=1):
        label = labels[kind]
        if label in present:
            continue
        _run(
            [
                *pkcs11_tool,
                "--keypairgen",
                "--key-type",
                key_type,
                "--label",
                label,
                "--id",
                f"{index:02}",
            ],
            env,
            f"generating {label} ({key_type})",
        )
        created.append(f"{label} ({key_type})")
    return created
