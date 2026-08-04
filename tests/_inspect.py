"""Structural assertions about OpenPGP artefacts, delegated to `sq`.

The tests need to see inside what sq-pkcs11 produces: which signature type a
revocation carries, whether a subpacket is marked critical, which key issued a
signature, what capabilities a subkey was granted.

Everything below is either a subprocess call or the grouping of labelled lines.
No protocol knowledge.
"""

from __future__ import annotations

import functools
import re
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple, Union

import pytest

Source = Union[str, Path, bytes, bytearray]

# How `sq packet dump` renders each --reason value.
REASON_TEXT = {
    "unspecified": "No reason specified",
    "superseded": "Key is superseded",
    "compromised": "Key material has been compromised",
    "retired": "Key is retired and no longer used",
}


# These assertions use the sq 1.x command line — `sq packet dump`, `sq inspect
# FILE`, `--cert-store=none`.  Older sq is not merely missing features, it parses
# arguments differently, so finding one on PATH and using it anyway produces
# confusing failures instead of an honest skip.  Debian trixie (1.2) and EL10
# (1.3) are fine; Ubuntu 24.04 ships 0.33.
SQ_MIN_MAJOR = 1


@functools.lru_cache(maxsize=1)
def _sq_probe() -> tuple[str | None, str | None]:
    """Locate a usable sq.  Returns (binary, reason it cannot be used)."""
    found = shutil.which("sq")
    if found is None:
        return None, "stock Sequoia sq is not installed"
    # `sq version` works on both old and new; `sq --version` only on old.
    proc = subprocess.run([found, "version"], capture_output=True)
    text = (proc.stdout + proc.stderr).decode("utf-8", "replace").strip()
    match = re.search(r"\bsq (\d+)\.(\d+)", text)
    if match is None:
        return None, f"could not read a version from `{found} version`: {text!r}"
    if int(match.group(1)) < SQ_MIN_MAJOR:
        return None, (
            f"{found} is sq {match.group(1)}.{match.group(2)}; these assertions "
            f"need the sq {SQ_MIN_MAJOR}.x command line"
        )
    return found, None


def _sq(*args: object, stdin: bytes | None = None) -> str:
    binary, reason = _sq_probe()
    if binary is None:
        pytest.skip(reason or "sq is unusable")
    argv = [binary, "--home=none", "--cert-store=none", "--batch"] + [str(a) for a in args]
    proc = subprocess.run(argv, input=stdin, capture_output=True)
    assert proc.returncode == 0, (
        f"command: {' '.join(argv)}\n"
        f"exit: {proc.returncode}\n"
        f"stderr: {proc.stderr.decode('utf-8', 'replace')}"
    )
    return proc.stdout.decode("utf-8", "replace")


def dump(source: Source) -> str:
    """`sq packet dump` output — the strict parser's view of a packet stream.

    Accepts a path or raw bytes; `sq packet dump` reads stdin when given no
    file, so a command's stdout can be piped straight in.  Raises if the stream
    does not parse, which is the assertion for packet framing: a signature
    serialized without its packet header does not get this far.
    """
    if isinstance(source, (bytes, bytearray)):
        return _sq("packet", "dump", stdin=bytes(source))
    return _sq("packet", "dump", source)


def inspect(source: str | Path) -> str:
    """`sq inspect` output — the certificate-level view."""
    return _sq("inspect", source)


# ---------------------------------------------------------------------------
# Grouping `sq inspect` output
# ---------------------------------------------------------------------------


class InspectedKey(NamedTuple):
    """One key from `sq inspect`, with its labelled fields."""

    fingerprint: str
    is_subkey: bool
    fields: dict[str, str]

    @property
    def key_flags(self) -> list[str]:
        """e.g. `["certification"]`, or `["certification", "signing"]`."""
        raw = self.fields.get("Key flags", "")
        return [flag.strip() for flag in raw.split(",") if flag.strip()]

    @property
    def creation_time(self) -> str:
        return self.fields.get("Creation time", "")

    @property
    def expiration_time(self) -> str:
        return self.fields.get("Expiration time", "")


def inspected_keys(source: str | Path) -> list[InspectedKey]:
    """The keys in a certificate, primary first.

    `sq inspect` prints a run of `Label: value` lines per key, introduced by
    `Fingerprint:` for the primary and `Subkey:` for each subkey.
    """
    found: list[InspectedKey] = []
    for line in inspect(source).splitlines():
        label, sep, value = line.strip().partition(": ")
        if not sep:
            continue
        if label == "Fingerprint":
            found.append(InspectedKey(value.strip(), False, {}))
        elif label == "Subkey":
            found.append(InspectedKey(value.strip(), True, {}))
        elif found:
            found[-1].fields.setdefault(label, value.strip())
    assert found, f"sq inspect reported no keys for {source}"
    return found


def primary_fingerprint(source: str | Path) -> str:
    keys = inspected_keys(source)
    assert not keys[0].is_subkey, "expected sq inspect to report the primary first"
    return keys[0].fingerprint


def subkey_fingerprints(source: str | Path) -> list[str]:
    return [key.fingerprint for key in inspected_keys(source) if key.is_subkey]


def only_subkey_fingerprint(source: str | Path) -> str:
    """The single subkey's fingerprint; fails if there is not exactly one."""
    subkeys = subkey_fingerprints(source)
    assert len(subkeys) == 1, f"expected exactly one subkey, found {len(subkeys)}"
    return subkeys[0]


# ---------------------------------------------------------------------------
# Reading `sq packet dump` output
# ---------------------------------------------------------------------------


def packet_headers(dump_text: str) -> list[str]:
    """Packet-boundary lines, e.g. `["Signature Packet"]`.

    `sq packet dump` introduces each packet with a line like
    `Signature Packet, new CTB, 635 bytes`.
    """
    return [line.split(",")[0].strip() for line in dump_text.splitlines() if " CTB, " in line]


def field_lines(dump_text: str, label: str) -> list[str]:
    """Every `label: …` line, stripped, in order."""
    prefix = label + ":"
    return [line.strip() for line in dump_text.splitlines() if line.strip().startswith(prefix)]


def field(dump_text: str, label: str) -> str:
    """The single `label: value` line's value; fails on zero or several."""
    lines = field_lines(dump_text, label)
    assert len(lines) == 1, f"expected one {label!r} line, got {lines}"
    return lines[0].split(":", 1)[1].strip()


def assert_one_signature_packet(source: Source, what: str) -> str:
    """Assert `source` is exactly one signature packet; return its dump.

    Regression guard for the "Malformed CTB: MSB of ptag not set" class of bug,
    where a signature was serialized as its bare body.  GnuPG imports that
    happily; Sequoia does not, which is the point of asking Sequoia.
    """
    text = dump(source)
    headers = packet_headers(text)
    assert headers == ["Signature Packet"], (
        f"{what}: expected exactly one Signature Packet, got {headers}"
    )
    return text


def signature_creation_time_line(dump_text: str) -> str:
    """The `Signature creation time:` line, which carries `(critical)` or not."""
    lines = field_lines(dump_text, "Signature creation time")
    assert len(lines) == 1, f"expected one creation-time line, got {lines}"
    return lines[0]


def issuer_fingerprints(dump_text: str) -> Sequence[str]:
    return [
        line.split(":", 1)[1].strip() for line in field_lines(dump_text, "Issuer Fingerprint")
    ]
