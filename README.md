# sq-pkcs11

Sign OpenPGP release artifacts using a private key held on a PKCS#11 HSM.
The signatures are standard OpenPGP and verify with both GnuPG and Sequoia.

Built primarily for the OpenSSL release-signing workflow on Entrust nShield
HSMs in FIPS 140-3 mode, but the standard subcommands work with any
PKCS#11 v2.40+ module that supports the algorithms listed below.

## Features

- Detached OpenPGP signatures (ASCII-armored or binary)
- OpenPGP certificate construction from an HSM-backed public key
- PKCS#11 key selection by URI (RFC 7512), `CKA_LABEL`, `CKA_ID`, or auto
- Three authentication modes: module-protected (no login), softcard /
  single-card OCS (PIN), and nShield K/N quorum OCS (`C_LoginBegin` /
  `C_LoginNext` / `C_LoginEnd`)
- Stable fingerprints across separate `cert-export` and `sign` invocations
- Multi-HSM aware: handles two or more nShield modules in one Security
  World transparently for module-protected keys

## Requirements

- Rust 1.75 or newer
- A C toolchain and OpenSSL development headers (`libssl-dev` /
  `openssl-devel`) for building Sequoia's OpenSSL crypto backend
- A PKCS#11 v2.40+ module from your HSM vendor at runtime
- For the `--ocs` quorum login path: an nShield PKCS#11 module that
  exports `C_LoginBegin`, `C_LoginNext`, `C_LoginEnd`

## Building

```sh
cargo build --release
```

The resulting binary is at `target/release/sq-pkcs11`.

## Configuring the PKCS#11 module

The PKCS#11 vendor library path is required for every command. It can be
supplied three ways, in priority order:

```sh
# 1. command-line flag
./sq-pkcs11 -m /opt/nfast/toolkits/pkcs11/libcknfast.so list-keys

# 2. standard env var (used by pkcs11-tool, p11-kit, GnuTLS)
export PKCS11_MODULE_PATH=/opt/nfast/toolkits/pkcs11/libcknfast.so
./sq-pkcs11 list-keys

# 3. tool-specific fallback env var
export SQ_PKCS11_MODULE=/opt/nfast/toolkits/pkcs11/libcknfast.so
./sq-pkcs11 list-keys
```

## Usage

### Discovering keys

```sh
./sq-pkcs11 list-keys
```

Shows each visible PKCS#11 token slot with its protection mode, then the
signing keys on each slot with `CKA_LABEL`, `CKA_ID`, and key type.

### Selecting a key

Every signing-related command accepts one of:

| Flag | Example |
|---|---|
| `--key-uri <URI>` | `pkcs11:token=release;object=signing-key;type=private` |
| `--key-label <LABEL>` | matches `CKA_LABEL` |
| `--key-id <HEX>` | matches `CKA_ID`, e.g. `8d2c17c0...` |
| `--auto` | only when exactly one usable key is visible |

Use `--key-uri` with a `token=` component to disambiguate softcard or
OCS slots. For module-protected keys, any of the three forms works.

### Authentication

| Mode | How |
|---|---|
| Module-protected | no auth flag — login is not required |
| Softcard / single-card OCS | `--pin <pass>` or `SQ_PKCS11_PIN` env var |
| nShield K/N quorum OCS | `--ocs` — the tool prompts per card via `rpassword` |

For OCS quorum login, the operator(s) must insert their cards into
readers connected to the nShield host before running the command. The
`--ocs` path uses nShield's vendor extension functions and is not
available in load-sharing or HSM Pool mode (use `preload` for those).

### Exporting an OpenPGP certificate

```sh
./sq-pkcs11 cert-export \
  --key-label my-signing-key \
  --uid "OpenSSL Release Key <openssl-security@openssl.org>" \
  --creation-time 2026-05-01T00:00:00Z \
  --output release.asc
```

Produces an OpenPGP public key block ready for distribution to keyservers
and your project website. The `--uid` may be repeated.

### Signing a file

```sh
./sq-pkcs11 sign \
  --key-label my-signing-key \
  --creation-time 2026-05-01T00:00:00Z \
  openssl-3.6.0.tar.gz
# writes openssl-3.6.0.tar.gz.asc

./sq-pkcs11 sign --no-armor --output release.tar.gz.sig --key-label ... release.tar.gz
```

Verify with GnuPG:

```sh
gpg --import release.asc
gpg --verify openssl-3.6.0.tar.gz.asc openssl-3.6.0.tar.gz
```

## Stable fingerprints: `--creation-time`

The OpenPGP fingerprint is derived from key material **and** the key's
embedded creation time. When `--creation-time` is omitted, the tool
defaults to Unix epoch (`1970-01-01T00:00:00Z`) — a stable value that
guarantees `cert-export` and `sign` agree on the fingerprint without any
coordination.

For a published certificate the epoch default is functional but
unprofessional. Pick a meaningful timestamp **once** when you commit to
the key, document it, and pass the same value to every subsequent
invocation:

```sh
KEY_TIME=2026-05-01T00:00:00Z

./sq-pkcs11 cert-export --creation-time "$KEY_TIME" ...    # once
./sq-pkcs11 sign        --creation-time "$KEY_TIME" ...    # every time
```

Once the certificate is uploaded to keyservers, the timestamp is
permanent — never change it. A different value gives a different
fingerprint, which from a verifier's perspective is a different key.

## Supported algorithms

Aligned with FIPS 140-3 approved algorithms supported by nShield in
strict mode:

| Algorithm | PKCS#11 mechanism | Hashes |
|---|---|---|
| RSA (≥ 2048) | `CKM_RSA_PKCS` | SHA-256, SHA-384, SHA-512 |
| ECDSA P-256 / P-384 / P-521 | `CKM_ECDSA` | matching curve hash |

The tool drives these as pre-hashed, single-part operations: Sequoia
hashes the OpenPGP-formatted data, the digest is wrapped in a DER
`DigestInfo` for RSA, and the HSM signs the prepared input.

## Limitations

- **Out of scope**: key generation, key import/export, key deletion,
  certificate revocation. Use your HSM's own tooling (`generatekey`,
  `createocs`, `ppmk` on nShield).
- **No Ed25519 / EdDSA**: nShield's FIPS 140-3 mode does not approve
  Ed25519 in releases before V13.7, and many other HSMs don't expose it.
  For broad portability the tool sticks to NIST-curve ECDSA and RSA.
- **No RSA-PSS**: only `CKM_RSA_PKCS` (PKCS#1 v1.5). PSS support would
  require additional DigestInfo handling and isn't needed for OpenPGP
  release-signing today.
- **No SHA-1 or MD5**: rejected by design.
- **Sequoia experimental warnings**: the tool uses Sequoia's
  `crypto-openssl` backend, which is the production-recommended one. The
  RustCrypto backend is gated behind `allow-experimental-crypto` upstream
  and is not used here.
- **No keyserver upload**: the certificate is printed to stdout or
  written to a file; uploading it is left to your existing tooling
  (`gpg --send-keys`, `hkp-tool`, `sq keyring publish`, ...).
- **OCS quorum is nShield-specific**: `C_LoginBegin`/`C_LoginNext`/
  `C_LoginEnd` are vendor extensions. On non-nShield HSMs use
  `--pin` (single-card OCS works that way) or your vendor's preload
  equivalent.
- **HSM-dependent code is not unit-tested**: the actual signing path,
  slot/login logic, and certificate assembly require a real HSM. They
  are exercised by manual integration tests against an nShield 5c. The
  pure-function code (URI parsing, OID/MPI handling, DigestInfo prefix,
  timestamp parsing) has unit-test coverage — `cargo test`.

## License

Apache-2.0
