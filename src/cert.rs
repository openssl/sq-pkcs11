use sequoia_openpgp::{
    armor,
    cert::{CertRevocationBuilder, SubkeyRevocationBuilder},
    crypto::mpi,
    packet::{
        key::{Key4, PrimaryRole, PublicParts, SubordinateRole, UnspecifiedRole},
        signature::SignatureBuilder,
        Key, Signature, UserID,
    },
    parse::Parse,
    serialize::Marshal,
    types::{
        Curve, HashAlgorithm, KeyFlags, ReasonForRevocation, SignatureType, SymmetricAlgorithm,
    },
    Cert, Packet,
};

use crate::error::{Error, Result};
use crate::signer::Pkcs11Signer;

/// Per-key inputs to the certificate builder.
pub struct KeySpec<'a> {
    pub signer: &'a mut Pkcs11Signer,
    pub creation_time: std::time::SystemTime,
    pub validity_period: Option<std::time::Duration>,
}

/// Full certificate description.
///
/// When `subkey` is `None`, the resulting cert has a single primary key with
/// both `Certify` and `Sign` capabilities.  When `subkey` is `Some`, the
/// primary becomes `Certify`-only and the subkey carries the `Sign` flag.
///
/// When `merge_into` is `Some`, the new packets (UID bindings + subkey)
/// are inserted into the existing cert rather than seeding a fresh one.
/// In merge mode we never re-issue the primary's direct-key signature and
/// new UIDs are not marked as primary.
pub struct CertSpec<'a> {
    pub primary: KeySpec<'a>,
    pub subkey: Option<KeySpec<'a>>,
    pub user_ids: &'a [String],
    pub merge_into: Option<&'a Cert>,
}

/// Build (or extend) an OpenPGP certificate around HSM-backed signer(s).
///
/// Fresh cert (merge_into = None):
/// 1. Direct-key self-sig over primary
///    (flags = Certify+Sign without subkey, Certify-only with subkey)
/// 2. Positive-certification self-sig per User ID
/// 3. Subkey + cross-sig + binding-sig if a subkey is supplied
///
/// Merge cert (merge_into = Some):
/// 1. Verify the existing cert's primary fingerprint matches what we
///    would generate from the HSM key + creation time.  Refuse on mismatch.
/// 2. Skip the direct-key signature — the existing one stays.
/// 3. Add UID + binding-sig per `user_ids` (may be empty in merge mode).
/// 4. Add subkey + cross-sig + binding-sig if a subkey is supplied.
///
/// All historical packets in `merge_into` (old subkeys, prior UIDs,
/// existing revocations, etc.) are preserved.
pub fn build_cert(spec: CertSpec<'_>) -> Result<Cert> {
    let CertSpec {
        primary,
        mut subkey,
        user_ids,
        merge_into,
    } = spec;

    if merge_into.is_none() {
        assert!(
            !user_ids.is_empty(),
            "fresh cert requires at least one User ID"
        );
    }

    // Stamp creation times on the cached public keys so signature issuer
    // fingerprints match the cert key fingerprints.
    primary.signer.set_creation_time(primary.creation_time)?;
    if let Some(sk) = subkey.as_mut() {
        sk.signer.set_creation_time(sk.creation_time)?;
    }

    let primary_hash = preferred_hash_for(primary.signer.public_key());

    // Build the primary public-key packet pinned to the requested creation time.
    let primary_key = sequoia_openpgp::packet::Key::V4(Key4::<PublicParts, PrimaryRole>::new(
        primary.creation_time,
        primary.signer.public_key().pk_algo(),
        primary.signer.public_key().mpis().clone(),
    )?);

    let cert = match merge_into {
        Some(existing) => {
            // Refuse to merge if fingerprints disagree — would silently
            // produce an inconsistent cert.
            let existing_fpr = existing.primary_key().key().fingerprint();
            let new_fpr = primary_key.fingerprint();
            if existing_fpr != new_fpr {
                return Err(Error::Other(anyhow::anyhow!(
                    "primary fingerprint mismatch: existing cert has {existing_fpr}, \
                     HSM-derived primary is {new_fpr} \
                     (check --creation-time matches the existing cert)"
                )));
            }
            existing.clone()
        }
        None => {
            // Seed Cert with the primary; canonicalisation tolerates the missing
            // self-signature until we add it on the next step.
            let cert = Cert::try_from(vec![Packet::PublicKey(primary_key)])?;

            // -------- Direct-key self-signature on the primary --------
            let primary_flags = if subkey.is_some() {
                KeyFlags::empty().set_certification()
            } else {
                KeyFlags::empty().set_certification().set_signing()
            };
            let direct_sig = SignatureBuilder::new(SignatureType::DirectKey)
                .set_hash_algo(primary_hash)
                .set_key_flags(primary_flags)?
                .set_preferred_hash_algorithms(preferred_hashes())?
                .set_preferred_symmetric_algorithms(preferred_symmetric())?
                .set_key_validity_period(primary.validity_period)?
                .sign_direct_key(primary.signer, cert.primary_key().key())?;

            let (cert, _) = cert.insert_packets([Packet::from(direct_sig)])?;
            cert
        }
    };

    // -------- User ID binding signatures --------
    // In merge mode we do not mark new UIDs as primary, since the existing
    // cert already designates one and Sequoia warns about ambiguous primary.
    let mark_primary_uid = merge_into.is_none();
    let mut uid_packets: Vec<Packet> = Vec::with_capacity(user_ids.len() * 2);
    let mut first_uid = true;
    for raw_uid in user_ids {
        let uid = UserID::from(raw_uid.as_str());
        let mut builder =
            SignatureBuilder::new(SignatureType::PositiveCertification).set_hash_algo(primary_hash);
        if mark_primary_uid && first_uid {
            builder = builder.set_primary_userid(true)?;
            first_uid = false;
        }
        let uid_sig =
            builder.sign_userid_binding(primary.signer, cert.primary_key().key(), &uid)?;
        uid_packets.push(uid.into());
        uid_packets.push(uid_sig.into());
    }
    let (cert, _) = cert.insert_packets(uid_packets)?;

    // -------- Subkey, if any --------
    let cert = if let Some(sk) = subkey {
        let subkey_hash = preferred_hash_for(sk.signer.public_key());

        let subkey_key =
            sequoia_openpgp::packet::Key::V4(Key4::<PublicParts, SubordinateRole>::new(
                sk.creation_time,
                sk.signer.public_key().pk_algo(),
                sk.signer.public_key().mpis().clone(),
            )?);

        // In merge mode, refuse to bind a subkey whose fingerprint is
        // already present in the existing cert.  Re-running cert-export
        // --merge-cert with the SAME --subkey-* and --subkey-creation-time
        // is almost certainly an operator mistake (a real rotation
        // requires a different subkey, hence different key material or
        // a different creation time).  Silently piling on a second
        // binding signature would canonicalise to the same packet but
        // bloat the cert and obscure operator intent; allowing it as
        // "idempotent" requires Sequoia's deduplication, which we
        // shouldn't lean on for correctness.
        if let Some(existing) = merge_into {
            let new_fpr = subkey_key.fingerprint();
            for existing_sub in existing.keys().subkeys() {
                if existing_sub.key().fingerprint() == new_fpr {
                    return Err(Error::Other(anyhow::anyhow!(
                        "subkey {new_fpr} is already bound in the input cert; \
                         re-running cert-export --merge-cert with the same subkey \
                         is a no-op and almost certainly a mistake. \
                         To rotate, supply a different --subkey-creation-time \
                         (or a different subkey entirely) so the new subkey gets \
                         a distinct fingerprint."
                    )));
                }
            }
        }

        // Cross-sig — subkey signer attests it consents to being bound.
        // Required for any signing-capable subkey to prevent subkey hijacking.
        let cross_sig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
            .set_hash_algo(subkey_hash)
            .sign_primary_key_binding(sk.signer, cert.primary_key().key(), &subkey_key)?;

        // Subkey binding — primary signs (primary, subkey), embedding cross-sig.
        let binding_sig = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_hash_algo(primary_hash)
            .set_key_flags(KeyFlags::empty().set_signing())?
            .set_key_validity_period(sk.validity_period)?
            .set_embedded_signature(cross_sig)?
            .sign_subkey_binding(primary.signer, cert.primary_key().key(), &subkey_key)?;

        let (cert, _) =
            cert.insert_packets([Packet::PublicSubkey(subkey_key), Packet::from(binding_sig)])?;
        cert
    } else {
        cert
    };

    Ok(cert)
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// Inputs for primary-key revocation.
pub struct CertRevocationSpec<'a> {
    pub primary: KeySpec<'a>,
    pub reason: ReasonForRevocation,
    pub message: &'a [u8],
    pub revocation_time: std::time::SystemTime,
}

/// Inputs for subkey revocation.  Only the primary's *private* key is
/// needed to sign — the subkey is identified by its public material,
/// which can come from the published certificate without HSM access to
/// the subkey itself.  This is critical for the compromise-response
/// path: a lost or compromised subkey can still be revoked as long as
/// the primary signing key is reachable.
pub struct SubkeyRevocationSpec<'a> {
    pub primary: KeySpec<'a>,
    /// Public material of the subkey being revoked.  Its embedded
    /// creation time is used as-is (no `set_creation_time` rewrite).
    pub subkey_public: Key<PublicParts, SubordinateRole>,
    pub reason: ReasonForRevocation,
    pub message: &'a [u8],
    pub revocation_time: std::time::SystemTime,
}

/// Build a standalone primary-key revocation signature.
pub fn build_cert_revocation(spec: CertRevocationSpec<'_>) -> Result<Signature> {
    spec.primary
        .signer
        .set_creation_time(spec.primary.creation_time)?;

    let primary_key = sequoia_openpgp::packet::Key::V4(Key4::<PublicParts, PrimaryRole>::new(
        spec.primary.creation_time,
        spec.primary.signer.public_key().pk_algo(),
        spec.primary.signer.public_key().mpis().clone(),
    )?);
    // Sequoia's revocation builder needs a Cert just for hashing context.
    // A primary-only Cert canonicalises fine here.
    let cert = Cert::try_from(vec![Packet::PublicKey(primary_key)])?;

    let primary_hash = preferred_hash_for(spec.primary.signer.public_key());

    let sig = CertRevocationBuilder::new()
        .set_signature_creation_time(spec.revocation_time)?
        .set_reason_for_revocation(spec.reason, spec.message)?
        .build(spec.primary.signer, &cert, primary_hash)?;

    Ok(sig)
}

/// Build a standalone subkey revocation signature.
///
/// Only the primary's private key is exercised — `spec.subkey_public`
/// carries enough information to hash over the right subkey.  The subkey
/// itself does not need to be reachable on the HSM; the public material
/// can come from the published certificate.
pub fn build_subkey_revocation(spec: SubkeyRevocationSpec<'_>) -> Result<Signature> {
    spec.primary
        .signer
        .set_creation_time(spec.primary.creation_time)?;

    let primary_key = sequoia_openpgp::packet::Key::V4(Key4::<PublicParts, PrimaryRole>::new(
        spec.primary.creation_time,
        spec.primary.signer.public_key().pk_algo(),
        spec.primary.signer.public_key().mpis().clone(),
    )?);
    let cert = Cert::try_from(vec![Packet::PublicKey(primary_key)])?;

    let primary_hash = preferred_hash_for(spec.primary.signer.public_key());

    let sig = SubkeyRevocationBuilder::new()
        .set_signature_creation_time(spec.revocation_time)?
        .set_reason_for_revocation(spec.reason, spec.message)?
        .build(
            spec.primary.signer,
            &cert,
            &spec.subkey_public,
            primary_hash,
        )?;

    Ok(sig)
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Serialize a certificate to an armored OpenPGP public key block.
pub fn export_armored_cert(cert: &Cert) -> Result<String> {
    let mut buf = Vec::new();
    cert.armored().serialize(&mut buf)?;
    Ok(String::from_utf8(buf).expect("armored output is valid UTF-8"))
}

/// Serialize a certificate as raw OpenPGP packets (no armor).
pub fn export_binary_cert(cert: &Cert) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    cert.serialize(&mut buf)?;
    Ok(buf)
}

/// Wrap a single signature packet (typically a revocation) in OpenPGP armor.
///
/// Uses `PUBLIC KEY BLOCK` armor and a `Comment` header matching the GnuPG
/// `--gen-revoke` convention so importers display a clear hint.
pub fn export_armored_signature(sig: &Signature) -> Result<String> {
    let packet = Packet::from(sig.clone());
    let mut buf = Vec::new();
    {
        let mut writer = armor::Writer::with_headers(
            &mut buf,
            armor::Kind::PublicKey,
            vec![("Comment", "This is a revocation certificate")],
        )
        .map_err(|e| Error::Other(anyhow::anyhow!("armor writer init: {e}")))?;
        packet.serialize(&mut writer)?;
        writer
            .finalize()
            .map_err(|e| Error::Other(anyhow::anyhow!("armor finalize: {e}")))?;
    }
    Ok(String::from_utf8(buf).expect("armored output is valid UTF-8"))
}

/// Serialize a single signature packet without armor.
pub fn export_binary_signature(sig: &Signature) -> Result<Vec<u8>> {
    let packet = Packet::from(sig.clone());
    let mut buf = Vec::new();
    packet.serialize(&mut buf)?;
    Ok(buf)
}

/// Parse a public OpenPGP certificate from a buffer (armored or binary).
pub fn parse_cert(bytes: &[u8]) -> Result<Cert> {
    Cert::from_bytes(bytes).map_err(|e| Error::Other(anyhow::anyhow!("parsing cert: {e}")))
}

// ---------------------------------------------------------------------------
// Hash algorithm helpers
// ---------------------------------------------------------------------------

/// Pick a hash algorithm whose strength matches the signing key.
///
/// For ECDSA the choice follows NIST SP 800-57: pair each curve with a hash
/// of the corresponding security level (P-256↔SHA-256, P-384↔SHA-384,
/// P-521↔SHA-512).  Strict FIPS-mode HSMs may reject mismatched pairs, and
/// matched pairs avoid wasted hash work for shorter curves.
///
/// For RSA we default to SHA-512 — both well-supported and stronger than
/// any RSA key size we accept.
pub fn preferred_hash_for(public: &Key<PublicParts, UnspecifiedRole>) -> HashAlgorithm {
    if let mpi::PublicKey::ECDSA { curve, .. } = public.mpis() {
        match curve {
            Curve::NistP256 => HashAlgorithm::SHA256,
            Curve::NistP384 => HashAlgorithm::SHA384,
            Curve::NistP521 => HashAlgorithm::SHA512,
            _ => HashAlgorithm::SHA384, // any other curve we accept goes through P-384 hash
        }
    } else {
        HashAlgorithm::SHA512
    }
}

fn preferred_hashes() -> Vec<HashAlgorithm> {
    vec![
        HashAlgorithm::SHA512,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA256,
    ]
}

fn preferred_symmetric() -> Vec<SymmetricAlgorithm> {
    vec![SymmetricAlgorithm::AES256, SymmetricAlgorithm::AES128]
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::cert::{CertBuilder, CipherSuite};
    use sequoia_openpgp::parse::PacketParser;
    use sequoia_openpgp::parse::PacketParserResult;

    /// Generate a software cert with a free revocation signature, without
    /// touching any HSM. Used to exercise the export helpers in isolation.
    fn software_revocation() -> Signature {
        let (_cert, revocation) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::P256)
            .add_userid("Export Test <export@example.com>")
            .generate()
            .expect("software cert generation");
        revocation
    }

    /// Sequoia's PacketParser is what `sq inspect` uses; if the stream is not
    /// a properly framed OpenPGP packet (i.e. the CTB byte is missing) it
    /// fails with the same "MSB of ptag not set" error a user would see.
    fn assert_parses_as_single_signature(bytes: &[u8]) {
        let mut ppr = PacketParser::from_bytes(bytes).expect("PacketParser init");
        let mut count = 0;
        while let PacketParserResult::Some(pp) = ppr {
            let (packet, next) = pp.recurse().expect("packet recurse");
            assert!(
                matches!(packet, Packet::Signature(_)),
                "expected Signature packet, got {packet:?}"
            );
            count += 1;
            ppr = next;
        }
        assert_eq!(count, 1, "expected exactly one packet, got {count}");
    }

    #[test]
    fn export_binary_signature_is_a_framed_packet() {
        let sig = software_revocation();
        let bytes = export_binary_signature(&sig).expect("export_binary_signature");

        // The first byte of any OpenPGP packet is a CTB whose MSB must be set.
        // The original bug serialised the signature *body* (starting with the
        // v4 version byte 0x04, MSB clear), tripping `sq inspect`.
        assert!(
            !bytes.is_empty() && bytes[0] & 0x80 != 0,
            "first byte must have MSB set (CTB framing); got 0x{:02x}",
            bytes.first().copied().unwrap_or(0)
        );

        assert_parses_as_single_signature(&bytes);
    }

    #[test]
    fn export_armored_signature_dearmors_to_a_framed_packet() {
        let sig = software_revocation();
        let armored = export_armored_signature(&sig).expect("export_armored_signature");

        // Armor framing is GnuPG-compatible (PUBLIC KEY BLOCK + comment).
        assert!(
            armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
            "missing armor BEGIN line"
        );
        assert!(
            armored.contains("Comment: This is a revocation certificate"),
            "missing revocation Comment header"
        );

        // The dearmored body must itself be a properly framed packet stream.
        let mut ppr = PacketParser::from_bytes(armored.as_bytes()).expect("PacketParser dearmor");
        let mut count = 0;
        while let PacketParserResult::Some(pp) = ppr {
            let (packet, next) = pp.recurse().expect("packet recurse");
            assert!(
                matches!(packet, Packet::Signature(_)),
                "expected Signature packet, got {packet:?}"
            );
            count += 1;
            ppr = next;
        }
        assert_eq!(count, 1, "expected exactly one packet, got {count}");
    }
}
