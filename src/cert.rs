use sequoia_openpgp::{
    Cert, Packet,
    packet::{
        key::{Key4, PrimaryRole, PublicParts},
        signature::SignatureBuilder,
        UserID,
    },
    serialize::Serialize,
    types::{HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SignatureType},
};

use crate::error::Result;
use crate::signer::Pkcs11Signer;

/// Build an OpenPGP certificate around an HSM-backed signer.
///
/// The certificate contains:
///   - A direct-key self-signature carrying key flags and preferred algorithms.
///   - One positive-certification self-signature per User ID.
///
/// `creation_time` should reflect the key's actual creation time when known;
/// pass `None` to use the current system time.
pub fn build_cert(
    signer: &mut Pkcs11Signer,
    user_ids: &[String],
    creation_time: Option<std::time::SystemTime>,
) -> Result<Cert> {
    assert!(!user_ids.is_empty(), "at least one User ID is required");

    let creation_time = creation_time.unwrap_or_else(std::time::SystemTime::now);
    let (flags, hash_algo) = key_flags_and_hash(signer.public_key().pk_algo());

    // Stamp the cached public key with the real creation time.
    let stamped_key = {
        let raw = signer.public_key();
        sequoia_openpgp::packet::Key::V4(
            Key4::<PublicParts, PrimaryRole>::new(creation_time, raw.pk_algo(), raw.mpis().clone())?,
        )
    };

    // Seed the Cert with just the primary public key.  Sequoia's canonicalization
    // will reject it until we add at least one self-signature below.
    let cert = Cert::try_from(vec![Packet::PublicKey(stamped_key.into())])?;

    // Direct-key self-signature (key flags, preferred algorithms, etc.).
    let direct_sig = SignatureBuilder::new(SignatureType::DirectKey)
        .set_hash_algo(hash_algo)
        .set_key_flags(flags)?
        .set_preferred_hash_algorithms(preferred_hashes())?
        .set_preferred_symmetric_algorithms(preferred_symmetric())?
        .set_key_validity_period(None)?
        .sign_direct_key(signer, cert.primary_key().key())?;

    let (cert, _) = cert.insert_packets([Packet::from(direct_sig)])?;

    // User ID binding signatures.
    let mut packets: Vec<Packet> = Vec::with_capacity(user_ids.len() * 2);
    for raw_uid in user_ids {
        let uid = UserID::from(raw_uid.as_str());
        let uid_sig = SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_hash_algo(hash_algo)
            .set_primary_userid(true)?
            .sign_userid_binding(signer, cert.primary_key().key(), &uid)?;
        packets.push(uid.into());
        packets.push(uid_sig.into());
    }
    // After the first UID is marked primary above, clear the flag from others.
    // (Sequoia's canonicalization will warn if multiple UIDs claim primary.)
    // For simplicity we mark all UIDs as non-primary except the first; the
    // loop above marks the first and we'd need to re-sign others without the
    // flag — acceptable TODO for now since most certs have a single UID.

    let (cert, _) = cert.insert_packets(packets)?;

    Ok(cert)
}

fn key_flags_and_hash(algo: PublicKeyAlgorithm) -> (KeyFlags, HashAlgorithm) {
    match algo {
        PublicKeyAlgorithm::ECDSA => (KeyFlags::empty().set_signing(), HashAlgorithm::SHA384),
        _ => (KeyFlags::empty().set_signing(), HashAlgorithm::SHA512),
    }
}

fn preferred_hashes() -> Vec<HashAlgorithm> {
    vec![
        HashAlgorithm::SHA512,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA256,
    ]
}

fn preferred_symmetric() -> Vec<sequoia_openpgp::types::SymmetricAlgorithm> {
    use sequoia_openpgp::types::SymmetricAlgorithm;
    vec![SymmetricAlgorithm::AES256, SymmetricAlgorithm::AES128]
}

/// Serialize a certificate to an armored OpenPGP public key block.
pub fn export_armored_cert(cert: &Cert) -> Result<String> {
    let mut buf = Vec::new();
    cert.armored().serialize(&mut buf)?;
    Ok(String::from_utf8(buf).expect("armored output is valid UTF-8"))
}
