# sq-pkcs11

Sign OpenPGP release artifacts using a private key held on a PKCS#11 HSM.
The signatures are standard OpenPGP and verify with both GnuPG and Sequoia.

Built primarily for the OpenSSL release-signing workflow on Entrust nShield
HSMs in FIPS 140-3 mode, but the standard subcommands work with any
PKCS#11 v2.40+ module that supports the algorithms listed below.

For nShield-specific operational notes — running K/N OCS quorum ceremonies
under `preload`, vendor `CKA_NFKM_*` attributes, recipes for reading the
Security World key-generation timestamp, and FIPS 140-3 algorithm
constraints — see [`NSHIELD.md`](NSHIELD.md).

## Features

- Detached OpenPGP signatures (ASCII-armored or binary)
- Cleartext-signed documents (RFC 9580 Cleartext Signature Framework), the
  form apt wants for a repository `InRelease`
- A gpg-CLI-compatible shim so tools that shell out to `gpg` — `rpmsign
  --addsign` in particular — can sign against the HSM unchanged
- OpenPGP certificate construction from an HSM-backed public key
- Two-tier certificates (long-term Certify-only primary + signing subkey)
- Subkey rotation: re-export with `--merge-cert` to add a new subkey
  while preserving every existing subkey, UID, and historical signature
- Standalone primary-key and subkey revocation certificates
- PKCS#11 key selection by URI (RFC 7512), `CKA_LABEL`, `CKA_ID`, or auto
- Two authentication modes: module-protected (no login) and softcard /
  single-card OCS (PIN).  K>1 OCS quorums are handled by wrapping the
  invocation in nShield's `preload` utility, which feeds an
  already-authenticated PKCS#11 session into `sq-pkcs11`.
- Stable fingerprints across separate `cert-export` and `sign` invocations
- Multi-HSM aware: handles two or more nShield modules in one Security
  World transparently for module-protected keys

## Requirements

- Rust 1.86 or newer (set by `rust-version` in `Cargo.toml`; the floor
  is driven by transitive deps from `sequoia-openpgp` and moves with
  upstream releases). On Debian/Ubuntu, the distro-packaged `rustc` is
  often older than this — install a current toolchain via
  [rustup](https://rustup.rs/) instead.
- A C toolchain and OpenSSL development headers (`libssl-dev` /
  `openssl-devel`) for building Sequoia's OpenSSL crypto backend
- A PKCS#11 v2.40+ module from your HSM vendor at runtime
- For K/N OCS quorum logins on nShield: the `preload` utility (shipped
  with the nShield Security World software) — see
  [`NSHIELD.md`](NSHIELD.md) for the wrapper recipe

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
| Softcard / single-card OCS | `--pin-file <path>` or `SQ_PKCS11_PIN` env var |
| nShield K/N quorum OCS | wrap the invocation in `preload` — see [`NSHIELD.md`](NSHIELD.md) |

For K/N OCS quorum logins on nShield, the quorum ceremony runs in
`preload` (which already has a mature interactive UI for it), and
`sq-pkcs11` inherits the preloaded OCS via the PKCS#11 module — no
`--pin-file` is needed in that mode.  `preload` also handles HSM Pool
mode and load-sharing topologies that the standalone PKCS#11 `C_Login`
flow doesn't.

### Exporting an OpenPGP certificate (single-key)

```sh
./sq-pkcs11 cert-export \
  --key-label my-signing-key \
  --userid "OpenSSL Release Key <openssl-security@openssl.org>" \
  --creation-time 2026-05-01T00:00:00Z \
  --validity-period 5y \
  --output release.asc
```

Produces an OpenPGP public key block ready for distribution to keyservers
and your project website. The `--userid` may be repeated. The primary key
carries both `Certify` and `Sign` capabilities; subsequent `sign`
invocations use it directly.

### Exporting a two-tier certificate (long-term primary + signing subkey)

The recommended structure for release-signing infrastructure: a
long-lived `Certify`-only primary key kept under strong protection
(e.g. OCS quorum), and a shorter-lived `Sign` subkey under module
protection for unattended use:

```sh
preload -c openssl-release-primary -- \
  ./sq-pkcs11 cert-export \
    --key-label  "openssl-release-primary" \
    --subkey-label "openssl-release-sign-2026"  \
    --userid "OpenSSL Release Key <openssl-security@openssl.org>" \
    --creation-time         2026-05-01T00:00:00Z --validity-period         10y \
    --subkey-creation-time  2026-05-01T00:00:00Z --subkey-validity-period  2y  \
    --output release.asc
```

This is a one-off ceremony performed annually (or whenever the subkey
is rotated). `preload` runs the OCS quorum interactively (`-c <cardset>`
takes the operators through inserting their cards and entering each
passphrase), then `sq-pkcs11` runs against the preloaded session and
emits a single cert containing primary + subkey with the proper
subkey-binding signature and cross-signature.

Each tier authenticates independently:

| Flag | Tier |
|---|---|
| `--pin-file` (or `preload` wrapper) | primary |
| `--subkey-pin-file` (or `preload` wrapper) | subkey |

(Passphrases are read from a file or the `SQ_PKCS11_PIN` /
`SQ_PKCS11_SUBKEY_PIN` env vars; there is no `--pin <PASS>` value
flag — that would expose secrets through `ps` and shell history.)

Omitting both auth flags on a tier means the corresponding key is
module-protected (no login required).

For day-to-day signing, only the subkey is used and no auth is needed.  Point
`sign` at the published certificate and it takes the subkey's creation time
from there:

```sh
./sq-pkcs11 sign --key-label "openssl-release-sign-2026" \
  --input-cert release.asc openssl-3.6.0.tar.gz
```

`gpg --verify` walks the cert from the signature's issuer (the subkey)
through the subkey-binding to the primary, and reports both
fingerprints. `gpg -k` after import shows:

```
pub   rsa4096 2026-05-01 [C] [expires: 2036-05-01]
      <PRIMARY FINGERPRINT>
uid           [ unknown] OpenSSL Release Key <...>
sub   rsa4096 2026-05-01 [S] [expires: 2028-05-01]
      <SUBKEY FINGERPRINT>
```

`--validity-period` defaults to **5 years**. Format: integer + unit
(`y` years, `w` weeks, `d` days, `h` hours). `Ny` is **calendar-aware**:
`--validity-period 5y --creation-time 2026-05-10T19:53:26Z` expires at
`2031-05-10T19:53:26Z` exactly, regardless of how many leap years fall
in between (Feb 29 falls back to Feb 28 in non-leap target years).
Other units are exact fixed durations.

To issue a non-expiring certificate, pass `--no-expiration` instead —
but prefer a finite period as defence in depth: an expired key cannot
make new signatures, but old signatures made while the key was valid
keep verifying indefinitely.

To extend a key beyond its expiry, re-run `cert-export` with the same
`--creation-time` and a longer `--validity-period`, then redistribute
the cert.

### Rotating the signing subkey (`--merge-cert`)

When a signing subkey reaches end-of-life or you want to introduce a
fresh one without retiring the old one immediately, run `cert-export`
in **merge mode**.  This preserves every existing subkey, UID, and
revocation in the input cert and adds the new subkey-binding signature
on top:

```sh
./sq-pkcs11 cert-export \
  --merge-cert      release.asc \
  --key-label       openssl-release-primary \
  --subkey-label    openssl-release-sign-2027 \
  --creation-time           2026-05-01T00:00:00Z \
  --subkey-creation-time    2027-05-01T00:00:00Z \
  --subkey-validity-period  2y \
  --output          release-v2.asc
```

#### Which timestamps are fixed and which are free

The two creation-time flags behave very differently in merge mode:

| Flag | Refers to | In merge mode |
|---|---|---|
| `--creation-time` | the **primary** key | **Must** match the value used when the cert was first published. The primary fingerprint is the cert's identity; if your timestamp produces a different fingerprint, the tool refuses to merge with a hard error. |
| `--subkey-creation-time` | the **new** subkey being added | Free choice — typically the date you're cutting over to the new subkey. |

You do **not** supply (or need to remember) the *old* subkey's
creation time.  The old subkey, its binding signature, and its embedded
creation time are already in the input cert and are preserved as-is.

After rotation, when signing with the new subkey, pass *its* creation
time (not the primary's) on `sign`:

```sh
./sq-pkcs11 sign \
  --key-label      openssl-release-sign-2027 \
  --creation-time  2027-05-01T00:00:00Z \    # the NEW subkey's creation time
  release.tar.gz
```

Old signatures made with the old subkey keep verifying because the old
subkey is still in the merged cert.

#### Why preserve old subkeys

Signatures made by an old subkey remain verifiable forever as long as
the cert advertises that subkey, so retiring an old subkey by
*deleting* it from the cert would invalidate every release signature
ever made with it.  The right pattern is to **expire** an old subkey
(its `--subkey-validity-period` lapses, so it can't make new
signatures) but **leave it in the published certificate** so historical
signatures keep verifying.  When the key is genuinely compromised, also
issue a subkey revocation (below).

The tool refuses to merge if the input cert's primary fingerprint
doesn't match the HSM-derived primary — i.e. you cannot accidentally
merge a new subkey into the wrong cert.

### Signing a file

```sh
./sq-pkcs11 sign \
  --key-label my-signing-key \
  --creation-time 2026-05-01T00:00:00Z \
  openssl-3.6.0.tar.gz
# writes openssl-3.6.0.tar.gz.asc
```

Instead of remembering and passing `--creation-time`, point `sign` at the
published certificate and let it derive the value:

```sh
./sq-pkcs11 sign \
  --key-label my-signing-key \
  --input-cert release.asc \
  openssl-3.6.0.tar.gz
```

`--input-cert` locates the signing (sub)key in the cert by matching the HSM
key's public material (RSA modulus+exponent / EC curve+point) and signs with
**that key's** embedded creation time, so the signature's issuer fingerprint
equals the published key's by construction. This is the robust choice for
release signing and git tags: no timestamp to track, rotation-safe, and it
cannot select the wrong subkey. If no key in the cert matches the HSM key, it
errors rather than silently falling back to the epoch default. An explicit
`--creation-time` still wins (and warns if it disagrees with the cert).

Verify with GnuPG:

```sh
gpg --import release.asc
gpg --verify openssl-3.6.0.tar.gz.asc openssl-3.6.0.tar.gz
```

### Output forms

`sign` emits one of three things.  All three verify with both GnuPG and
Sequoia:

| Flag | Output | Used by |
|---|---|---|
| *(none)* | armored detached signature, `-----BEGIN PGP SIGNATURE-----` | release tarballs, `Release.gpg`, `repomd.xml.asc` |
| `--binary` | detached signature as raw OpenPGP packets | `rpmsign`, which embeds the packets in the package header |
| `--cleartext` | the text plus a signature over it, in one document | apt's `InRelease` |

The default is armored, so existing callers are unaffected by the other two.

```sh
# binary detached — byte-for-byte what `gpg --no-armor -sbo` writes
./sq-pkcs11 sign --binary \
  --key-label my-signing-key --input-cert release.asc \
  --output release.tar.gz.sig release.tar.gz
```

### Cleartext signing (`InRelease`)

apt accepts a repository `Release` file signed two ways, and normally both are
published: a detached armored `Release.gpg` (the default output above) and a
cleartext-signed `InRelease`, which apt prefers because it fetches the metadata
and its signature in one request.

```sh
./sq-pkcs11 sign --cleartext \
  --key-label my-signing-key --input-cert release.asc \
  --output InRelease Release

gpgv --keyring /etc/apt/trusted.gpg.d/mine.gpg InRelease
```

`--output` is required with `--cleartext`, and there is no default: a cleartext
document is a *signed message*, not a detached signature, and letting it land
on the usual `<input>.asc` path would invite publishing it where a detached
signature is expected — where every verifier rejects it.

Two properties of the Cleartext Signature Framework are worth knowing before
publishing one:

- It does not sign trailing whitespace and requires a trailing newline, so
  line-ending whitespace is trimmed and a missing final newline is added in
  the emitted copy of the text.  The text in the document is always exactly
  the text that was signed.  A `Release` file is unaffected by this — its
  fields carry no trailing whitespace — but a generic input might be.
- The signature covers the text only.  A verifier must read the message *out of
  the signed document*, never trust a separate copy of it.

### Revoking a primary key or subkey

Use `cert-revoke` to retire the entire certificate, or `subkey-revoke`
to retire just one subkey.  Both produce a standalone OpenPGP
revocation signature that any verifier can import alongside the cert
to mark the key as revoked.

Primary-key revocation (entire cert is dead):

```sh
preload -c openssl-release-primary -- \
  ./sq-pkcs11 cert-revoke \
    --key-label     openssl-release-primary \
    --creation-time 2026-05-01T00:00:00Z \
    --reason        compromised \
    --message       "primary HSM was decommissioned" \
    --output        release-revocation.asc
```

Subkey revocation (cert remains valid; one subkey is retired).
The subkey is identified by full 40-hex fingerprint inside the
published cert, **not** by HSM CKA_LABEL — so this works even when
the subkey's private material has been deleted, lost, or compromised:

```sh
# Look up the subkey fingerprint in the published cert first:
sq inspect release.asc                 # or
gpg --list-keys --with-subkey-fingerprint

preload -c openssl-release-primary -- \
  ./sq-pkcs11 subkey-revoke \
    --key-label              openssl-release-primary \
    --creation-time          2026-05-01T00:00:00Z \
    --input-cert             release.asc \
    --subkey-fingerprint     70F222DB97E8304B93112F1B998B87DB3AFDA5A8 \
    --reason                 superseded \
    --message                "rotated to openssl-release-sign-2027" \
    --output                 sign-2026-revocation.asc
```

`subkey-revoke` exercises only the primary's private key in the HSM.
The subkey's public material is read from `--input-cert`; the subkey
itself is never opened.  This is deliberate: the typical reason to
revoke a signing subkey is that its secret has been compromised or
lost, in which case a tool that demanded HSM access to that secret
would be useless.

`sq-pkcs11` also verifies that the `--input-cert`'s primary
fingerprint matches the HSM-derived primary fingerprint before
signing, so an operator who picks the wrong `--key-label` /
`--creation-time` cannot accidentally produce a revocation signed by
the wrong primary key.

Short 16-hex key IDs are not accepted for `--subkey-fingerprint`;
they are not collision-resistant and a malformed cert could carry an
ambiguous alias.  The full 40-hex fingerprint is required.

`--reason` accepts:

| Value | OpenPGP code | Use when |
|---|---|---|
| `compromised` | 0x02 | secret material is known or believed leaked |
| `superseded`  | 0x01 | a new key is taking the place of the old one |
| `retired`     | 0x03 | the key is being permanently retired and not replaced |
| `unspecified` | 0x00 | none of the above applies |

The choice affects how verifiers treat past signatures: `compromised`
implies signatures made by the key may have been forged and should be
treated with suspicion; `superseded`/`retired` mean past signatures
remain trustworthy.  Pick `compromised` only when warranted.

`--revocation-time` (RFC 3339) defaults to the current time.  Setting
it explicitly is rare but useful when reissuing a previously-prepared
revocation certificate.

The output is the **revocation only** — a standalone signature packet
in `PUBLIC KEY BLOCK` armor.  Distribution is the same as for the
public certificate: publish to keyservers and your project website,
where verifiers fetch and import it:

```sh
gpg --import release.asc
gpg --import release-revocation.asc
gpg -k     # primary now shown as [revoked]
```

### Caveat: GnuPG ignores standalone subkey-revocation files

The two-step `gpg --import cert.asc; gpg --import revocation.asc` flow
shown above works as expected for **primary-key** revocations, but
GnuPG (tested through 2.4.x) **silently drops a standalone subkey
revocation imported on its own**.  Its `--import` reports
`Total number processed: 0` and the subkey is never marked revoked
in the keyring.  This is a long-standing GnuPG behaviour — the packet
emitted by `subkey-revoke` is structurally correct (Sequoia's `sq`
applies it without complaint), GnuPG just doesn't pair an orphan
SubkeyRevocation packet with an existing subkey in its database.

When publishing a subkey revocation for GnuPG-using consumers,
distribute it **bundled with the cert** as a single file:

```sh
# Producer side (after subkey-revoke produced sign-2026-revocation.asc):
cat release.asc sign-2026-revocation.asc > release-with-subkey-revoked.asc

# Consumer side:
gpg --import release-with-subkey-revoked.asc
gpg -k   # subkey now shown as [revoked]
```

Keyservers that serve the merged cert (e.g. keys.openpgp.org after the
revocation has been uploaded as part of the cert) sidestep this for
fetch-based consumers; the caveat applies primarily to operators
publishing revocation-only files on a website for manual import.

### Keep old subkeys around

For day-to-day operations, **keep old expired and superseded subkeys
in the published certificate**.  Removing a subkey from the cert
invalidates every signature ever made with it; expiring or revoking it
prevents future use without touching the historical record.

## Stable fingerprints: `--creation-time`

The OpenPGP fingerprint is derived from key material **and** the key's
embedded creation time. A PKCS#11 token has no notion of an OpenPGP creation
time, so the value cannot be read off the HSM — it has to be supplied, and it
has to be the same value every time.

**There is no default.** Omitting `--creation-time` is an error on every
command that needs one. Earlier versions defaulted to Unix epoch, on the
theory that a fixed placeholder at least kept `cert-export` and `sign` in
agreement. In practice a caller that passed the flag to `cert-export` and
forgot it on `sign` got well-formed signatures carrying an issuer fingerprint
that resolved to no published key — and the failure only surfaced at the
verifier, as `gpg: Can't check signature: No public key`, after the artifact
had shipped. Silence is not worth that.

The two ways to supply it:

```sh
# 1. Let sign read it out of the published certificate.  Preferred: there is
#    no timestamp to keep in sync, and it cannot pick the wrong subkey.
./sq-pkcs11 sign --input-cert release.asc --key-label ... file

# 2. State it.  Required for cert-export, cert-revoke, subkey-revoke and
#    verify-signing-key, which have no cert to derive it from (or, for
#    verify-signing-key, deliberately do not derive it).
KEY_TIME=2026-05-01T00:00:00Z
./sq-pkcs11 cert-export --creation-time "$KEY_TIME" ...
```

Pick the timestamp **once**, when you commit to the key, and document it. The
natural choice is the moment the HSM generated the key; on nShield that is the
Security World `gentime`, and [`NSHIELD.md`](NSHIELD.md) has a recipe for
turning a `CKA_LABEL` into an RFC 3339 timestamp. Once the certificate is
published the value is permanent — a different one gives a different
fingerprint, which from a verifier's perspective is a different key.

If a certificate really was published under the old epoch default, nothing is
lost: ask for it explicitly and the tool obliges.

```sh
./sq-pkcs11 sign --creation-time 1970-01-01T00:00:00Z ...
```

## Signing through a gpg-compatible shim (`rpmsign` and friends)

Some signing tools cannot be pointed at a library; they shell out to a `gpg`
command line. `rpmsign --addsign` is the common case: it expands rpm's
`%__gpg_sign_cmd` macro to roughly

```
gpg --no-verbose --no-armor [--digest-algo=X] -u "<_gpg_name>" -sbo <sigfile> -
```

and expects the binary to write a binary detached signature to the `-o` path
and exit 0. [`contrib/sq-pkcs11-gpg-shim`](contrib/sq-pkcs11-gpg-shim) accepts
that command line and turns it into `sq-pkcs11 sign --binary`.

Point rpm's gpg at the shim and name the HSM key:

```sh
rpmsign --addsign \
    --define "_gpg_name <CKA_LABEL>" \
    --define "__gpg /usr/local/bin/sq-pkcs11-gpg-shim" \
    package.rpm
```

Overriding `%__gpg` alone leaves the distro's own `%__gpg_sign_cmd` in place,
so the contract stays whatever that rpm version expects. Override the whole
`%__gpg_sign_cmd` only if you need to inject extra arguments. Either macro
works from the command line, `~/.rpmmacros`, or `/etc/rpm/macros.d/`.

`%_gpg_name` must be the HSM object's `CKA_LABEL` — it becomes `--key-label`,
not a search over user IDs, so an email address or a fingerprint will not
resolve.

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
reasons in [Stable fingerprints](#stable-fingerprints---creation-time).

The shim removes `SQ_PKCS11_PIN` and `SQ_PKCS11_SUBKEY_PIN` from the
environment before running `sq-pkcs11`. Those variables switch `sq-pkcs11`
into PKCS#11 login mode, and a module-protected key — the unattended case —
needs login mode `None`. A value that merely happens to be exported in a CI
environment would flip the mode and send key lookup down the
login-required-token path. Ambient credentials must not steer key selection,
so `SQ_PKCS11_PIN_FILE` above is the only way in.

`--digest-algo` is accepted and ignored: `sq-pkcs11` picks the digest to match
the signing key's strength, and the choice is recorded in the signature itself,
where verifiers read it from. The shim says so on stderr when a caller asks for
one. Unrecognised options are reported and skipped; options that would change
what the command *does* (`--verify`, `--encrypt`, key management, …) are
refused rather than quietly ignored.

`gpg --clearsign` is also supported, and maps to `sign --cleartext` — useful
for repository tooling that generates `InRelease` through gpg.

### rpm parser compatibility

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

One further quirk of rpm 4.16 shapes the `--binary` output. Its subpacket
parser dispatches on the raw type byte without masking the critical bit
(`rpmio/rpmpgp.c`), so it cannot read a *critical* signature-creation-time
subpacket and reports `Signature : RSA/SHA512, Thu Jan  1 00:00:00 1970` for
every package — verification is unaffected, only the displayed date. `--binary`
therefore emits that subpacket non-critical, as GnuPG always has. It stays in
the hashed area, so it is still covered by the signature. The armored and
cleartext forms are left as Sequoia produces them, since nothing that consumes
those reads the field through that parser.

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

- **Out of scope**: key generation, key import/export, key deletion.
  Use your HSM's own tooling (`generatekey`, `createocs`, `ppmk` on
  nShield).  Certificate-level revocation (cert and subkey) **is** in
  scope — see `cert-revoke` / `subkey-revoke`.
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
- **The gpg shim only signs**: `contrib/sq-pkcs11-gpg-shim` covers detached
  and cleartext signing and nothing else.  Verification, encryption, and
  keyring or key management all need real GnuPG.  It is a compatibility
  front end for tools that exec `gpg`, not a drop-in replacement.
- **No signature streaming**: `sign` reads the whole input into memory.  An
  OpenPGP signature is over a hash of the entire input, so nothing can be
  emitted before the last byte is read regardless; this only bounds the
  input size by available memory.
- **OCS K/N quorum logins are nShield-specific**: handled by wrapping
  the invocation in `preload`, which is part of the nShield Security
  World software and not portable.  On non-nShield HSMs that support
  K=1 OCS or softcards, `--pin-file` works.  Other vendor quorum
  schemes (Thales/Luna MofN, AWS CloudHSM quorum) need their own
  preload-equivalent or out-of-band auth.
- **HSM-dependent code is not unit-tested**: the actual signing path,
  slot/login logic, and certificate assembly need a PKCS#11 token, so they
  are covered by the integration suite in
  [`tests/`](tests/README.md) rather than by unit
  tests — run with `pytest` against SoftHSM2 for development and against an
  nShield for the release-signing pass.  The pure-function code (URI parsing,
  OID/MPI handling, DigestInfo prefix, timestamp parsing) has unit-test
  coverage in Rust: `cargo test --bins`.

## License

Apache-2.0
