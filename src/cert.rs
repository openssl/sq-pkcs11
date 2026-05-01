use sequoia_openpgp::{
    Cert, Packet,
    crypto::mpi,
    packet::{
        Key, UserID,
        key::{Key4, PrimaryRole, PublicParts, SubordinateRole, UnspecifiedRole},
        signature::SignatureBuilder,
    },
    serialize::Serialize,
    types::{Curve, HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm},
};

use crate::error::Result;
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
pub struct CertSpec<'a> {
    pub primary: KeySpec<'a>,
    pub subkey: Option<KeySpec<'a>>,
    pub user_ids: &'a [String],
}

/// Build an OpenPGP certificate around HSM-backed signer(s).
///
/// Single-key cert (no subkey):
/// 1. Direct-key self-sig over primary (flags = Certify + Sign)
/// 2. Positive-certification self-sig per User ID
///
/// Two-tier cert (subkey present):
/// 1. Direct-key self-sig over primary (flags = Certify only)
/// 2. Positive-certification self-sig per User ID
/// 3. Cross-sig: subkey signs (primary, subkey) as PrimaryKeyBinding
/// 4. Subkey-binding: primary signs (primary, subkey) as SubkeyBinding,
///    with the cross-sig embedded in the hashed area.
pub fn build_cert(spec: CertSpec<'_>) -> Result<Cert> {
    let CertSpec {
        primary,
        mut subkey,
        user_ids,
    } = spec;

    assert!(!user_ids.is_empty(), "at least one User ID is required");

    // Stamp creation times on the cached public keys so signature issuer
    // fingerprints match the cert key fingerprints.
    primary.signer.set_creation_time(primary.creation_time)?;
    if let Some(sk) = subkey.as_mut() {
        sk.signer.set_creation_time(sk.creation_time)?;
    }

    let primary_hash = preferred_hash_for(primary.signer.public_key());

    // Build the primary public-key packet pinned to the requested creation time.
    let primary_key = sequoia_openpgp::packet::Key::V4(
        Key4::<PublicParts, PrimaryRole>::new(
            primary.creation_time,
            primary.signer.public_key().pk_algo(),
            primary.signer.public_key().mpis().clone(),
        )?,
    );

    // Seed Cert with the primary; canonicalisation tolerates the missing
    // self-signature until we add it on the next step.
    let cert = Cert::try_from(vec![Packet::PublicKey(primary_key.into())])?;

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

    // -------- User ID binding signatures --------
    let mut uid_packets: Vec<Packet> = Vec::with_capacity(user_ids.len() * 2);
    let mut first_uid = true;
    for raw_uid in user_ids {
        let uid = UserID::from(raw_uid.as_str());
        let mut builder = SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_hash_algo(primary_hash);
        // Mark exactly the first UID as primary; Sequoia will warn if more
        // than one UID claims primary status.
        if first_uid {
            builder = builder.set_primary_userid(true)?;
            first_uid = false;
        }
        let uid_sig = builder.sign_userid_binding(
            primary.signer,
            cert.primary_key().key(),
            &uid,
        )?;
        uid_packets.push(uid.into());
        uid_packets.push(uid_sig.into());
    }
    let (cert, _) = cert.insert_packets(uid_packets)?;

    // -------- Subkey, if any --------
    let cert = if let Some(sk) = subkey {
        let subkey_hash = preferred_hash_for(sk.signer.public_key());

        let subkey_key = sequoia_openpgp::packet::Key::V4(
            Key4::<PublicParts, SubordinateRole>::new(
                sk.creation_time,
                sk.signer.public_key().pk_algo(),
                sk.signer.public_key().mpis().clone(),
            )?,
        );

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

        let (cert, _) = cert.insert_packets([
            Packet::PublicSubkey(subkey_key.into()),
            Packet::from(binding_sig),
        ])?;
        cert
    } else {
        cert
    };

    Ok(cert)
}

/// Pick a hash algorithm whose strength matches the signing key.
///
/// For ECDSA the choice follows NIST SP 800-57: pair each curve with a hash
/// of the corresponding security level (P-256↔SHA-256, P-384↔SHA-384,
/// P-521↔SHA-512).  Strict FIPS-mode HSMs may reject mismatched pairs, and
/// matched pairs avoid wasted hash work for shorter curves.
///
/// For RSA we default to SHA-512 — both well-supported and stronger than
/// any RSA key size we accept.
fn preferred_hash_for(public: &Key<PublicParts, UnspecifiedRole>) -> HashAlgorithm {
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

/// Serialize a certificate to an armored OpenPGP public key block.
pub fn export_armored_cert(cert: &Cert) -> Result<String> {
    let mut buf = Vec::new();
    cert.armored().serialize(&mut buf)?;
    Ok(String::from_utf8(buf).expect("armored output is valid UTF-8"))
}
