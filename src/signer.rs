use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::Session,
};
use sequoia_openpgp::{
    crypto::{mpi, HashAlgorithm, PublicKeyAlgorithm, Signer},
    packet::key::{Key4, PrimaryRole, PublicParts, UnspecifiedRole},
    packet::Key,
    types::Curve,
};

use crate::error::{Error, Result};
use crate::session::key_type;

/// A Sequoia `Signer` that delegates all private-key operations to a PKCS#11 session.
///
/// `Session` is `Send` but not `Sync` by design (PKCS#11 sessions must not
/// be shared across threads).  We implement `Sync` here because the only
/// `&self` method (`public()`) never touches the session; `sign()` requires
/// `&mut self` and therefore already has exclusive access.
pub struct Pkcs11Signer {
    session: Session,
    priv_handle: ObjectHandle,
    key_type: KeyType,
    public: Key<PublicParts, UnspecifiedRole>,
}

// SAFETY: Session is not Sync because concurrent PKCS#11 calls on the same
// session are not allowed.  Our Signer::sign() takes &mut self (exclusive),
// so concurrent signing is impossible.  Signer::public() takes &self but
// only reads the cached Key packet, never touching the session.
unsafe impl Sync for Pkcs11Signer {}

impl Pkcs11Signer {
    pub fn new(session: Session, priv_handle: ObjectHandle) -> Result<Self> {
        let kt = key_type(&session, priv_handle)?;
        let public = read_public_key(&session, priv_handle, kt)?;
        Ok(Self {
            session,
            priv_handle,
            key_type: kt,
            public,
        })
    }

    pub fn public_key(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    /// Stamp the cached public key with a specific creation time.
    ///
    /// The OpenPGP fingerprint is derived from the key material **and** the
    /// creation time.  When building a certificate, the cert key and every
    /// self-signature's issuer fingerprint must agree.  Call this before
    /// `cert::build_cert` so the signer's fingerprint matches the stamped
    /// key inserted into the certificate.
    pub fn set_creation_time(&mut self, t: std::time::SystemTime) -> Result<()> {
        let new_key = Key4::<PublicParts, PrimaryRole>::new(
            t,
            self.public.pk_algo(),
            self.public.mpis().clone(),
        )?;
        self.public = sequoia_openpgp::packet::Key::V4(new_key.role_into_unspecified());
        Ok(())
    }
}

impl Signer for Pkcs11Signer {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    fn sign(
        &mut self,
        _hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> sequoia_openpgp::Result<mpi::Signature> {
        // Compute the mechanism inline — Mechanism<'_> contains raw pointers
        // and is not Send+Sync, so it cannot be stored in the struct.
        let mechanism = match self.key_type {
            KeyType::RSA => Mechanism::RsaPkcs,
            KeyType::EC => Mechanism::Ecdsa,
            other => {
                return Err(sequoia_openpgp::Error::InvalidArgument(format!(
                    "unsupported key type {other:?}"
                ))
                .into())
            }
        };

        let raw = self
            .session
            .sign(&mechanism, self.priv_handle, digest)
            .map_err(|e| anyhow::anyhow!("PKCS#11 C_Sign failed: {e}"))?;

        encode_signature(&self.public, &raw)
    }
}

/// Read public key material from the HSM and return a Sequoia Key packet.
pub fn read_public_key(
    session: &Session,
    priv_handle: ObjectHandle,
    kt: KeyType,
) -> Result<Key<PublicParts, UnspecifiedRole>> {
    match kt {
        KeyType::RSA => read_rsa_public(session, priv_handle),
        KeyType::EC => read_ec_public(session, priv_handle),
        other => Err(Error::UnsupportedKeyType(format!("{other:?}"))),
    }
}

/// Find the CKO_PUBLIC_KEY object that shares CKA_ID with a private key object.
///
/// PKCS#11 mandates that key pairs share a CKA_ID value.  Public key attributes
/// such as CKA_EC_POINT are only guaranteed to be present on the public key
/// object, not the private key object.
fn find_companion_public_key(
    session: &Session,
    priv_handle: ObjectHandle,
) -> Result<ObjectHandle> {
    let id_attr = session
        .get_attributes(priv_handle, &[AttributeType::Id])?
        .into_iter()
        .find_map(|a| match a {
            Attribute::Id(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| Error::UnsupportedKeyType("private key has no CKA_ID".into()))?;

    let candidates = session.find_objects(&[
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Id(id_attr),
    ])?;

    candidates
        .into_iter()
        .next()
        .ok_or_else(|| {
            Error::UnsupportedKeyType(
                "no CKO_PUBLIC_KEY object found with matching CKA_ID".into(),
            )
        })
}

fn read_rsa_public(
    session: &Session,
    handle: ObjectHandle,
) -> Result<Key<PublicParts, UnspecifiedRole>> {
    let attrs = session.get_attributes(
        handle,
        &[AttributeType::Modulus, AttributeType::PublicExponent],
    )?;

    let mut modulus = None;
    let mut exponent = None;
    for attr in attrs {
        match attr {
            Attribute::Modulus(v) => modulus = Some(v),
            Attribute::PublicExponent(v) => exponent = Some(v),
            _ => {}
        }
    }

    let n = mpi::MPI::new(
        &modulus.ok_or_else(|| Error::UnsupportedKeyType("RSA key missing modulus".into()))?,
    );
    let e = mpi::MPI::new(
        &exponent.ok_or_else(|| Error::UnsupportedKeyType("RSA key missing exponent".into()))?,
    );

    let key = Key4::<PublicParts, PrimaryRole>::new(
        std::time::SystemTime::UNIX_EPOCH,
        PublicKeyAlgorithm::RSAEncryptSign,
        mpi::PublicKey::RSA { e, n },
    )?;

    Ok(sequoia_openpgp::packet::Key::V4(key.role_into_unspecified()))
}

fn read_ec_public(
    session: &Session,
    priv_handle: ObjectHandle,
) -> Result<Key<PublicParts, UnspecifiedRole>> {
    // CKA_EC_POINT is only on the CKO_PUBLIC_KEY object, not the private key.
    // Find the companion public key by matching CKA_ID.
    let pub_handle = find_companion_public_key(session, priv_handle)?;

    let attrs = session
        .get_attributes(pub_handle, &[AttributeType::EcParams, AttributeType::EcPoint])?;

    let mut ec_params = None;
    let mut ec_point = None;
    for attr in attrs {
        match attr {
            Attribute::EcParams(v) => ec_params = Some(v),
            Attribute::EcPoint(v) => ec_point = Some(v),
            _ => {}
        }
    }

    let params =
        ec_params.ok_or_else(|| Error::UnsupportedKeyType("EC key missing CKA_EC_PARAMS".into()))?;
    let curve = oid_to_curve(&params)?;

    let point_der =
        ec_point.ok_or_else(|| Error::UnsupportedKeyType("EC key missing CKA_EC_POINT".into()))?;
    // CKA_EC_POINT is a DER OCTET STRING wrapping the uncompressed point.
    let point_bytes = unwrap_octet_string(&point_der)?;
    let q = mpi::MPI::new(&point_bytes);

    let key = Key4::<PublicParts, PrimaryRole>::new(
        std::time::SystemTime::UNIX_EPOCH,
        PublicKeyAlgorithm::ECDSA,
        mpi::PublicKey::ECDSA { curve, q },
    )?;

    Ok(sequoia_openpgp::packet::Key::V4(key.role_into_unspecified()))
}

/// Map a DER-encoded OID from CKA_EC_PARAMS to a Sequoia `Curve`.
fn oid_to_curve(der: &[u8]) -> Result<Curve> {
    // DER: tag 0x06, length byte, OID content bytes.
    let oid_bytes = match der {
        [0x06, len, rest @ ..] if rest.len() >= *len as usize => &rest[..*len as usize],
        _ => {
            return Err(Error::UnsupportedKeyType(
                "CKA_EC_PARAMS is not a DER OID".into(),
            ))
        }
    };

    match oid_bytes {
        // 1.2.840.10045.3.1.7  P-256
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Ok(Curve::NistP256),
        // 1.3.132.0.34  P-384
        &[0x2b, 0x81, 0x04, 0x00, 0x22] => Ok(Curve::NistP384),
        // 1.3.132.0.35  P-521
        &[0x2b, 0x81, 0x04, 0x00, 0x23] => Ok(Curve::NistP521),
        other => Err(Error::UnsupportedKeyType(format!(
            "unsupported EC OID: {}",
            hex::encode(other)
        ))),
    }
}

/// CKA_EC_POINT is DER: OCTET STRING (0x04) wrapping the raw EC point.
fn unwrap_octet_string(der: &[u8]) -> Result<Vec<u8>> {
    match der {
        [0x04, len, rest @ ..] if rest.len() >= *len as usize => {
            Ok(rest[..*len as usize].to_vec())
        }
        _ => Err(Error::UnsupportedKeyType(
            "CKA_EC_POINT is not a DER OCTET STRING".into(),
        )),
    }
}

/// Encode raw PKCS#11 signature bytes into the Sequoia MPI format.
fn encode_signature(
    public: &Key<PublicParts, UnspecifiedRole>,
    raw: &[u8],
) -> sequoia_openpgp::Result<mpi::Signature> {
    match public.pk_algo() {
        PublicKeyAlgorithm::RSAEncryptSign => Ok(mpi::Signature::RSA {
            s: mpi::MPI::new(raw),
        }),
        PublicKeyAlgorithm::ECDSA => {
            // CKM_ECDSA returns a fixed-size r||s blob (each half = curve order size).
            let half = raw.len() / 2;
            Ok(mpi::Signature::ECDSA {
                r: mpi::MPI::new(&raw[..half]),
                s: mpi::MPI::new(&raw[half..]),
            })
        }
        other => Err(sequoia_openpgp::Error::InvalidArgument(format!(
            "unsupported algorithm for signature encoding: {other:?}"
        ))
        .into()),
    }
}
