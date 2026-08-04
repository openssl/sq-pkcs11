# Integration test suite

Drives the compiled `sq-pkcs11` binary and `contrib/sq-pkcs11-gpg-shim` as
subprocesses, and puts what they produce in front of independent verifiers —
GnuPG, Sequoia, rpm, apt.

## Running

```sh
cargo build --release          # the suite tests the binary, so build it first

uv run pytest                  # everything the host can support — CI runs this
uv run pytest -m hermetic      # no token, no containers
uv run pytest -m "pkcs11 and not containers"
```

## Layers

| Marker | Needs | Covers |
|---|---|---|
| `hermetic` | nothing | the gpg shim's argument handling, against a stub sq-pkcs11 |
| `pkcs11` | a PKCS#11 module and the configured keys | sign, cert-export, revocation, verify-signing-key |
| `gpg` / `sq` | `gpg`+`gpgv` / `sq` on PATH | verification by the two implementations that matter |
| `rpm` | `podman`, plus a token the container can reach | `rpmsign --addsign` through the shim, on rpm 4.16 *and* 4.19 |
| `containers` | `podman` or `docker` | the consumers' own parsers: EL9/EL10 rpm, debian:11 and ubuntu:20.04 gpgv |

## Configuration

Read from `tests/test.env` (copy `test.env.example`), which **wins over the
environment** for every key below; with no such file the environment supplies
them. pytest's header prints what was resolved and what was ignored.

| Variable | Meaning |
|---|---|
| `PKCS11_MODULE_PATH` | vendor PKCS#11 library. Required for `pkcs11` tests |
| `SQ_PKCS11_NSHIELD_TEST_RSA` | RSA key `CKA_LABEL` |
| `SQ_PKCS11_NSHIELD_TEST_EC` | NIST-curve ECDSA key `CKA_LABEL` |
| `SQ_PKCS11_NSHIELD_TEST_PRIMARY` | Certify-only primary `CKA_LABEL` |
| `SQ_PKCS11_NSHIELD_TEST_SUBKEY` | signing subkey `CKA_LABEL` |
| `SQ_PKCS11_NSHIELD_TEST_SUBKEY2` | second signing subkey, for the rotation test |
| `SQ_PKCS11_BIN` | binary to test. Default: `target/release`, then `target/debug`, then `PATH` |
| `SQ_PKCS11_GPG_SHIM` | shim to test. Default: `contrib/sq-pkcs11-gpg-shim` |
| `SQ_PKCS11_TEST_PIN_FILE` | file holding the token PIN. Set this for SoftHSM2; leave unset for module-protected keys |
| `SQ_PKCS11_TEST_CONTAINER_MOUNTS` | comma-separated host paths to bind into rpm targets at the same location, each optionally `:ro` (default) or `:rw` — for a module needing more than SoftHSM2 does. nShield wants `/opt/nfast:rw` |
| `SQ_PKCS11_TEST_CONTAINER_ARGS` | extra arguments for `podman run`, for what a bind mount cannot express. Under rootless podman an nShield wants `--group-add keep-groups`, so the hardserver socket's `nfast` group applies. Not `--userns=keep-id`: that runs the container as your user, and the targets install their own tooling as root |
| `SQ_PKCS11_TEST_ENV` | a different config file, or `none` to use the environment. Read from the environment itself, since it selects the file |

### Provisioning the nShield test keys

`generatekey` in FIPS 140-3 mode is **not** unattended: each generation needs
Administrator Card Set authorisation. Run these once per Security World,
interactively, presenting ACS cards when prompted:

```sh
generatekey pkcs11 protect=module type=RSA   size=4096 plainname=sq-pkcs11-nshield-test-rsa4096
generatekey pkcs11 protect=module type=ECDSA size=384  plainname=sq-pkcs11-nshield-test-p384
generatekey pkcs11 protect=module type=ECDSA size=384  plainname=sq-pkcs11-nshield-test-primary
generatekey pkcs11 protect=module type=ECDSA size=384  plainname=sq-pkcs11-nshield-test-subkey
generatekey pkcs11 protect=module type=ECDSA size=384  plainname=sq-pkcs11-nshield-test-subkey2
```

All five must be **module-protected** — the suite is unattended and cannot
present cards or PINs. Confirm they are visible, then configure:

```sh
nfkminfo -k pkcs11 | grep sq-pkcs11-nshield
cp tests/test.env.example tests/test.env      # test.env is gitignored
uv run pytest -m pkcs11
```

### Developing against SoftHSM2

`tests/softhsm.env` is committed, so the development and CI setup is the same
for everyone. Provision the token once, then select that config:

```sh
sudo apt install softhsm2 opensc          # or: dnf install softhsm opensc
tests/provision-softhsm.sh                # writes tests/softhsm/, gitignored
cargo build --release

SQ_PKCS11_TEST_ENV=tests/softhsm.env uv run pytest
```

Two limitations to expect against SoftHSM2:

- The tests that build a **two-tier** cert skip. Such an export authenticates
  each tier independently, so it opens two sessions and logs into both, and a
  module whose login state is token-wide rather than per-session rejects the
  second `C_Login` with `CKR_USER_ALREADY_LOGGED_IN`. The deployment this tool is
  built for never reaches that code — the primary is authenticated out of band by
  nShield's `preload` and the signing subkey is module-protected, so no
  `C_Login` happens at all — which is why those tests do run on real hardware.

## What is not covered

- **OCS / K-of-N quorum login** — needs physical card insertion.
- **Two-tier `cert-export` against a PIN-protected token** — see the note under
  the SoftHSM2 recipe above; unaffected on module-protected keys.
