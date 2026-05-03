# nShield integration tests

These tests exercise the full sign / verify round-trip against an
**Entrust nShield** HSM in a FIPS 140-3 Security World. They are
vendor-specific by design: the file layout, env vars, and key
provisioning instructions all assume an nShield environment with
`/opt/nfast/` tooling available (`generatekey`, `nfkminfo`, `gpg`).

The test suite is gated on the presence of `tests/nshield/test.env`.
If that file is missing, every test in `tests/nshield_integration.rs`
skips silently. So the suite is safe to leave in the repository even
on developer machines that have no HSM.

## Prerequisites

1. An initialised Security World, FIPS 140-3 mode, with `nfkminfo` showing
   `Initialised Usable`.
2. The nShield client tooling (`/opt/nfast/bin/` on `PATH`) and a working
   `libcknfast.so`.
3. `gpg` available — the round-trip tests use it as the independent
   verifier.

## Provisioning the test keys

`generatekey` in FIPS 140-3 mode is **not unattended**: each generation
requires Administrator Card Set (ACS) authorisation. Run these four
commands once per Security World, in interactive mode, presenting ACS
cards when prompted:

```sh
generatekey pkcs11 protect=module type=RSA   size=4096 plainname=sq-pkcs11-nshield-test-rsa4096
generatekey pkcs11 protect=module type=ECDSA size=384  plainname=sq-pkcs11-nshield-test-p384
generatekey pkcs11 protect=module type=ECDSA size=384  plainname=sq-pkcs11-nshield-test-primary
generatekey pkcs11 protect=module type=ECDSA size=384  plainname=sq-pkcs11-nshield-test-subkey
generatekey pkcs11 protect=module type=ECDSA size=384  plainname=sq-pkcs11-nshield-test-subkey2
```

All four keys must be **module-protected**. The integration suite cannot
prompt for OCS cards or softcard PINs.

Verify the keys are visible to `nfkminfo`:

```sh
nfkminfo -k pkcs11 | grep sq-pkcs11-nshield
```

## Configuring the suite

```sh
cp tests/nshield/test.env.example tests/nshield/test.env
```

Edit `test.env` if any of the labels or the module path differ from the
defaults. `tests/nshield/test.env` is in `.gitignore`.

## Running

```sh
cargo test --test nshield_integration
```

To see test output (including the names of skipped tests):

```sh
cargo test --test nshield_integration -- --nocapture
```

## What the suite does **not** cover

- **OCS / quorum login** — needs physical card insertion, can't be automated.
- **Softcard-protected keys** — would need a stored passphrase, which
  defeats the protection.
- **Two-HSM Security Worlds** — module-protected keys appear identically
  on every accelerator slot, so the suite implicitly works across modules
  without testing it explicitly.
- **`generatekey` itself** — bootstrap is manual because of ACS.

These gaps are exercised by manual integration testing during release
ceremonies.
