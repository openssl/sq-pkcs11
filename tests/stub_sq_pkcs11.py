#!/usr/bin/env python3
"""A stand-in for sq-pkcs11, used to test the gpg shim without an HSM.

`contrib/sq-pkcs11-gpg-shim` translates a gpg command line into an
`sq-pkcs11 sign` invocation.  Checking that translation needs to see the argv
the shim produced, not a signature — so `SQ_PKCS11_BIN` points here instead,
and this records the call.

Appends one JSON record per invocation to `$STUB_RECORD`, so a test can see
both the shim's own `--version` probe and the signing call that follows.
Exits with `$STUB_EXIT` (default 0), which is how the tests check that a
failure reaches rpm unchanged.

Not a test module: pytest does not collect it, and it is never imported.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys


def main() -> int:
    argv = sys.argv[1:]
    record = {
        "argv": argv,
        # The shim is expected to strip these before running us.
        "pin_in_env": "SQ_PKCS11_PIN" in os.environ,
        "subkey_pin_in_env": "SQ_PKCS11_SUBKEY_PIN" in os.environ,
        "plaintext": None,
        "plaintext_sha256": None,
        "plaintext_size": None,
    }

    # The shim always passes the file to sign as the operand after `--`, so a
    # test can confirm the bytes that arrived on stdin are the bytes we were
    # asked to sign.
    if "--" in argv:
        path = argv[argv.index("--") + 1]
        record["plaintext"] = path
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            record["plaintext_error"] = str(exc)
        else:
            record["plaintext_sha256"] = hashlib.sha256(data).hexdigest()
            record["plaintext_size"] = len(data)

    # Write something to --output, so a caller that checks for a file is happy.
    if "--output" in argv:
        out = argv[argv.index("--output") + 1]
        if out != "-":
            try:
                with open(out, "wb") as handle:
                    handle.write(b"STUB SIGNATURE\n")
            except OSError:
                pass

    with open(os.environ["STUB_RECORD"], "a") as handle:
        handle.write(json.dumps(record) + "\n")

    return int(os.environ.get("STUB_EXIT", "0"))


if __name__ == "__main__":
    sys.exit(main())
