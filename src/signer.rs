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
        hash_algo: HashAlgorithm,
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

        // CKM_RSA_PKCS expects a DER-encoded DigestInfo, not a raw hash.
        // CKM_ECDSA takes the raw digest directly.
        let signing_input: Vec<u8> = match self.key_type {
            KeyType::RSA => {
                let prefix = digest_info_prefix(hash_algo)?;
                let mut buf = Vec::with_capacity(prefix.len() + digest.len());
                buf.extend_from_slice(prefix);
                buf.extend_from_slice(digest);
                buf
            }
            _ => digest.to_vec(),
        };

        let raw = self
            .session
            .sign(&mechanism, self.priv_handle, &signing_input)
            .map_err(|e| anyhow::anyhow!("PKCS#11 C_Sign failed: {e}"))?;

        encode_signature(&self.public, &raw)
    }
}

/// DER-encoded DigestInfo prefix (everything before the actual hash bytes)
/// for use with CKM_RSA_PKCS signing.
///
/// DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
fn digest_info_prefix(hash_algo: HashAlgorithm) -> sequoia_openpgp::Result<&'static [u8]> {
    Ok(match hash_algo {
        HashAlgorithm::SHA256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        HashAlgorithm::SHA384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        HashAlgorithm::SHA512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        other => {
            return Err(sequoia_openpgp::Error::InvalidArgument(format!(
                "RSA signing with hash algorithm {other:?} is not supported \
                 (use SHA-256, SHA-384, or SHA-512)"
            ))
            .into())
        }
    })
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
///
/// Handles both DER short-form length (single byte, value < 128) and
/// long-form length (0x80 | n, then n length bytes big-endian).  P-521
/// uncompressed points are 133 bytes and require long-form, encoded as
/// `0x04 0x81 0x85 …`.
fn unwrap_octet_string(der: &[u8]) -> Result<Vec<u8>> {
    let after_tag = match der.split_first() {
        Some((&0x04, rest)) => rest,
        _ => {
            return Err(Error::UnsupportedKeyType(
                "CKA_EC_POINT is not a DER OCTET STRING".into(),
            ));
        }
    };
    let (len, body) = parse_der_length(after_tag)?;
    if body.len() < len {
        return Err(Error::UnsupportedKeyType(
            "CKA_EC_POINT length exceeds buffer".into(),
        ));
    }
    Ok(body[..len].to_vec())
}

/// Parse an ASN.1 DER length octet sequence.
///
/// Returns (length value, slice positioned just after the length octets).
fn parse_der_length(b: &[u8]) -> Result<(usize, &[u8])> {
    let (&first, rest) = b
        .split_first()
        .ok_or_else(|| Error::UnsupportedKeyType("DER length missing".into()))?;
    if first & 0x80 == 0 {
        // Short form: length is the byte itself.
        Ok((first as usize, rest))
    } else {
        // Long form: low 7 bits = number of length bytes that follow.
        let n = (first & 0x7f) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() {
            return Err(Error::UnsupportedKeyType(format!(
                "DER long-form length count {n} unsupported"
            )));
        }
        if rest.len() < n {
            return Err(Error::UnsupportedKeyType(
                "DER long-form length truncated".into(),
            ));
        }
        let mut len = 0usize;
        for &byte in &rest[..n] {
            len = (len << 8) | byte as usize;
        }
        Ok((len, &rest[n..]))
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

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // oid_to_curve
    // -------------------------------------------------------------------

    #[test]
    fn oid_to_curve_p256() {
        // 1.2.840.10045.3.1.7
        let der = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        assert!(matches!(oid_to_curve(der).unwrap(), Curve::NistP256));
    }

    #[test]
    fn oid_to_curve_p384() {
        // 1.3.132.0.34
        let der = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        assert!(matches!(oid_to_curve(der).unwrap(), Curve::NistP384));
    }

    #[test]
    fn oid_to_curve_p521() {
        // 1.3.132.0.35
        let der = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];
        assert!(matches!(oid_to_curve(der).unwrap(), Curve::NistP521));
    }

    #[test]
    fn oid_to_curve_unsupported_curve() {
        // 1.2.840.10045.3.1.1 (P-192) — valid OID, unsupported curve
        let der = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01];
        assert!(oid_to_curve(der).is_err());
    }

    #[test]
    fn oid_to_curve_wrong_tag() {
        // OCTET STRING (0x04) instead of OID (0x06)
        let der = &[0x04, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        assert!(oid_to_curve(der).is_err());
    }

    #[test]
    fn oid_to_curve_truncated() {
        // Length byte says 8 but only 2 bytes follow
        let der = &[0x06, 0x08, 0x2a, 0x86];
        assert!(oid_to_curve(der).is_err());
    }

    #[test]
    fn oid_to_curve_empty() {
        assert!(oid_to_curve(&[]).is_err());
    }

    // -------------------------------------------------------------------
    // unwrap_octet_string
    // -------------------------------------------------------------------

    #[test]
    fn unwrap_octet_string_valid() {
        let der = &[0x04, 0x03, 0xaa, 0xbb, 0xcc];
        assert_eq!(unwrap_octet_string(der).unwrap(), vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn unwrap_octet_string_empty_payload() {
        let der = &[0x04, 0x00];
        assert_eq!(unwrap_octet_string(der).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn unwrap_octet_string_wrong_tag() {
        // OID tag instead of OCTET STRING
        let der = &[0x06, 0x03, 0xaa, 0xbb, 0xcc];
        assert!(unwrap_octet_string(der).is_err());
    }

    #[test]
    fn unwrap_octet_string_truncated() {
        // Length byte says 5 but only 2 bytes follow
        let der = &[0x04, 0x05, 0xaa, 0xbb];
        assert!(unwrap_octet_string(der).is_err());
    }

    #[test]
    fn unwrap_octet_string_p384_point_shape() {
        // CKA_EC_POINT for a P-384 key wraps a 97-byte uncompressed point
        // (0x04 || x[48] || y[48]).  Encoded length is 97 = 0x61, but DER
        // requires multi-byte length form for values ≥ 128 — for 97 the
        // short form is fine: 0x04 0x61 <97 bytes>.
        let mut payload = vec![0x04];
        payload.extend(vec![0xaa; 48]);
        payload.extend(vec![0xbb; 48]);
        assert_eq!(payload.len(), 97);

        let mut der = vec![0x04, 0x61];
        der.extend(&payload);
        assert_eq!(unwrap_octet_string(&der).unwrap(), payload);
    }

    #[test]
    fn unwrap_octet_string_p521_long_form_length() {
        // P-521 uncompressed point is 133 bytes (0x04 || x[66] || y[66]).
        // 133 ≥ 128 → DER long-form length: 0x81 0x85 (one length byte = 133).
        let mut payload = vec![0x04];
        payload.extend(vec![0xaa; 66]);
        payload.extend(vec![0xbb; 66]);
        assert_eq!(payload.len(), 133);

        let mut der = vec![0x04, 0x81, 0x85];
        der.extend(&payload);
        assert_eq!(unwrap_octet_string(&der).unwrap(), payload);
    }

    #[test]
    fn unwrap_octet_string_long_form_two_byte_length() {
        // Synthetic 300-byte payload to exercise 0x82 NN MM long-form length.
        let payload: Vec<u8> = (0..300).map(|i| (i & 0xff) as u8).collect();
        let mut der = vec![0x04, 0x82, 0x01, 0x2c]; // 0x012c = 300
        der.extend(&payload);
        assert_eq!(unwrap_octet_string(&der).unwrap(), payload);
    }

    #[test]
    fn unwrap_octet_string_long_form_truncated_rejected() {
        // 0x81 says "1 length byte follows", but no bytes follow.
        let der = &[0x04, 0x81];
        assert!(unwrap_octet_string(der).is_err());
    }

    // -------------------------------------------------------------------
    // digest_info_prefix
    //
    // Reference values from RFC 8017 §9.2 (PKCS #1 v2.2).
    // -------------------------------------------------------------------

    #[test]
    fn digest_info_prefix_sha256() {
        let prefix = digest_info_prefix(HashAlgorithm::SHA256).unwrap();
        assert_eq!(
            prefix,
            &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
            ]
        );
        // Trailing length byte must equal SHA-256 output size in bytes.
        assert_eq!(*prefix.last().unwrap(), 32);
    }

    #[test]
    fn digest_info_prefix_sha384() {
        let prefix = digest_info_prefix(HashAlgorithm::SHA384).unwrap();
        assert_eq!(
            prefix,
            &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
            ]
        );
        assert_eq!(*prefix.last().unwrap(), 48);
    }

    #[test]
    fn digest_info_prefix_sha512() {
        let prefix = digest_info_prefix(HashAlgorithm::SHA512).unwrap();
        assert_eq!(
            prefix,
            &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
            ]
        );
        assert_eq!(*prefix.last().unwrap(), 64);
    }

    #[test]
    fn digest_info_prefix_rejects_sha1() {
        assert!(digest_info_prefix(HashAlgorithm::SHA1).is_err());
    }

    #[test]
    fn digest_info_prefix_rejects_md5() {
        assert!(digest_info_prefix(HashAlgorithm::MD5).is_err());
    }

    // -------------------------------------------------------------------
    // encode_signature
    //
    // Constructs synthetic public keys with arbitrary MPI material — we
    // are testing the signature splitting/MPI encoding, not cryptographic
    // validity.
    // -------------------------------------------------------------------

    fn rsa_test_key() -> Key<PublicParts, UnspecifiedRole> {
        let n = mpi::MPI::new(&[0xff; 256]); // 2048-bit-shaped value
        let e = mpi::MPI::new(&[0x01, 0x00, 0x01]); // 65537
        let key = Key4::<PublicParts, PrimaryRole>::new(
            std::time::SystemTime::UNIX_EPOCH,
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA { e, n },
        )
        .unwrap();
        sequoia_openpgp::packet::Key::V4(key.role_into_unspecified())
    }

    fn ecdsa_p384_test_key() -> Key<PublicParts, UnspecifiedRole> {
        // 0x04 || x[48] || y[48] = 97 bytes, leading bytes non-zero so the
        // MPI representation matches what we put in.
        let mut q_bytes = vec![0x04];
        q_bytes.extend(vec![0xaa; 48]);
        q_bytes.extend(vec![0xbb; 48]);
        let q = mpi::MPI::new(&q_bytes);
        let key = Key4::<PublicParts, PrimaryRole>::new(
            std::time::SystemTime::UNIX_EPOCH,
            PublicKeyAlgorithm::ECDSA,
            mpi::PublicKey::ECDSA {
                curve: Curve::NistP384,
                q,
            },
        )
        .unwrap();
        sequoia_openpgp::packet::Key::V4(key.role_into_unspecified())
    }

    #[test]
    fn encode_signature_rsa_passthrough() {
        let key = rsa_test_key();
        let raw = vec![0x11, 0x22, 0x33, 0x44, 0x55];
        let sig = encode_signature(&key, &raw).unwrap();
        match sig {
            mpi::Signature::RSA { s } => assert_eq!(s.value(), raw.as_slice()),
            _ => panic!("expected RSA signature"),
        }
    }

    #[test]
    fn encode_signature_ecdsa_splits_in_half() {
        // P-384: 96 bytes total, r and s are each 48 bytes.
        // Use leading-non-zero bytes so MPI doesn't trim.
        let r_bytes = [0x11u8; 48];
        let s_bytes = [0x22u8; 48];
        let mut raw = Vec::with_capacity(96);
        raw.extend_from_slice(&r_bytes);
        raw.extend_from_slice(&s_bytes);

        let key = ecdsa_p384_test_key();
        let sig = encode_signature(&key, &raw).unwrap();
        match sig {
            mpi::Signature::ECDSA { r, s } => {
                assert_eq!(r.value(), r_bytes.as_slice());
                assert_eq!(s.value(), s_bytes.as_slice());
            }
            _ => panic!("expected ECDSA signature"),
        }
    }
}
