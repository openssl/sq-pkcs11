# `sq-pkcs11-gpg-shim`

A gpg(1)-compatible front end for `sq-pkcs11 sign`, for tools that sign by
exec'ing a `gpg` command line rather than by linking a library. It lets them
sign against a PKCS#11 HSM with no private key on disk and no gpg-agent.

Two callers are covered — `rpmsign` and `git` — and their command lines differ
in ways that matter. Shipped in the release tarball beside the binary, so the
two cannot skew.

## rpmsign

rpm expands `%__gpg_sign_cmd` to roughly

```
gpg --no-verbose --no-armor [--digest-algo=X] -u "<_gpg_name>" -sbo <sigfile> -
```

and expects a binary detached signature at the `-o` path and exit 0. The data
arrives on **stdin**: both rpm 4.16 (EL9) and 4.19 (EL10) pass `-` and pipe the
package in. rpm 4.19 also probes `--version` first and gives up if it exits
non-zero.

```sh
rpmsign --addsign \
    --define "_gpg_name <CKA_LABEL>" \
    --define "__gpg /usr/local/bin/sq-pkcs11-gpg-shim" \
    package.rpm
```

Overriding `%__gpg` alone leaves the distro's own `%__gpg_sign_cmd` in place, so
the contract stays whatever that rpm version expects. Override the whole
`%__gpg_sign_cmd` only to inject extra arguments. Either macro works from the
command line, `~/.rpmmacros`, or `/etc/rpm/macros.d/`.

## git

git runs the program named by `gpg.program` as

```
gpg --status-fd=2 -bsau <keyid> < payload > armored_signature
```

There is no `-o` anywhere: the signature is read from **stdout**. A
`SIG_CREATED` status line is also mandatory — git scans for it and fails the
signing without it, however good the signature.

```sh
git -c gpg.program=/usr/local/bin/sq-pkcs11-gpg-shim \
    tag -s -u <CKA_LABEL> v1.0.0 -m "release tag"
```

Pass `gpg.program` per command as above rather than setting it in git config.
git runs the same program to *verify* — `git tag -v`, `git log
--show-signature` — and the shim only signs, so it refuses those. Verification
needs real `gpg` or `sq` with the published certificate in a keyring; an HSM
contributes nothing to it. The refusal fails closed: git reports the tag as
unverified and can never call a bad signature good.

```sh
gpg --import release.asc
git tag -v v1.0.0                # plain gpg, no gpg.program
```

## Naming the key

`%_gpg_name` and `-u` are both the HSM object's `CKA_LABEL`: it becomes
`--key-label`, not a search over user IDs, so an email address or a fingerprint
will not resolve. Note that git falls back to the committer identity when
`user.signingkey` is unset, which is such an address.

## Configuration

Everything `sq-pkcs11` needs that gpg has no flag for comes from the
environment:

| Variable | Effect |
|---|---|
| `PKCS11_MODULE_PATH` | vendor PKCS#11 library (required) |
| `SQ_PKCS11_CERT` | published cert, passed as `--input-cert`; the preferred way to fix the creation time |
| `SQ_PKCS11_CREATION_TIME` | RFC 3339 creation time, passed as `--creation-time` |
| `SQ_PKCS11_KEY_LABEL` | supplies the label when the caller passes no `-u`; an explicit `-u` wins |
| `SQ_PKCS11_PIN_FILE` | passed as `--pin-file`, for a softcard or single-card OCS key |
| `SQ_PKCS11_BIN` | path to `sq-pkcs11` (default: found on `PATH`) |

One of `SQ_PKCS11_CERT` or `SQ_PKCS11_CREATION_TIME` is required, for the
reasons in [Stable
fingerprints](../README.md#stable-fingerprints---creation-time). For a git tag
the consequence of getting it wrong is a signature that verifies as `No public
key`.

`SQ_PKCS11_PIN` and `SQ_PKCS11_SUBKEY_PIN` are removed from the environment
before `sq-pkcs11` runs. They switch it into PKCS#11 login mode, and a
module-protected key — the unattended case — needs login mode `None`, so an
inherited value would change which slot is selected. `SQ_PKCS11_PIN_FILE` above
is the only way in.

## Option handling

- With no `-o` the signature goes to stdout, as gpg does.
- `--clearsign` maps to `sign --cleartext`, for repository tooling that
  generates `InRelease` through gpg.
- `--digest-algo` is accepted and ignored: `sq-pkcs11` picks the digest to match
  the signing key's strength and records it in the signature, where verifiers
  read it from. The shim says so on stderr when a caller asks.
- Unrecognised options are reported and skipped, so a new distro macro or git
  release cannot turn into a refusal to sign.
- Options that would change what the command *does* — `--verify`, `--encrypt`,
  key management — are refused rather than quietly ignored.

## rpm parser compatibility

Two rpm OpenPGP implementations are in play, and they do not agree:

| | rpm 4.16 (EL9, internal parser) | rpm 4.19 (EL10, rpm-sequoia) |
|---|---|---|
| RSA | works | works |
| ECDSA P-256 / P-384 | **rejected** | works |

On EL9, `rpmsign` refuses an ECDSA signature outright (`error: Unsupported PGP
signature`) and `rpm --import` cannot read an ECDSA certificate (`key 1 import
failed`). **A packaging key that has to serve both EL9 and EL10 must therefore
be RSA**, even though `sq-pkcs11` signs happily with either and both verify
under GnuPG and Sequoia.

One further quirk of rpm 4.16 shapes the `--binary` output. Its subpacket parser
dispatches on the raw type byte without masking the critical bit
(`rpmio/rpmpgp.c`), so it cannot read a *critical* signature-creation-time
subpacket and reports `Signature : RSA/SHA512, Thu Jan  1 00:00:00 1970` for
every package — verification is unaffected, only the displayed date. `--binary`
therefore emits that subpacket non-critical, as GnuPG always has. It stays in
the hashed area, so it is still covered by the signature. The armored and
cleartext forms are left as Sequoia produces them, since nothing that consumes
those reads the field through that parser.
