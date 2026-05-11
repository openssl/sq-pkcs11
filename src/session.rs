use cryptoki::{
    context::Pkcs11,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};

use crate::error::{Error, Result};

/// Parsed form of a key selector supplied on the command line.
#[derive(Debug, Clone)]
pub enum KeySelector {
    Uri(Pkcs11Uri),
    Label(String),
    Id(Vec<u8>),
    Auto,
}

/// Minimal subset of a PKCS#11 URI (RFC 7512) that we care about.
#[derive(Debug, Clone, Default)]
pub struct Pkcs11Uri {
    pub token_label: Option<String>,
    pub object_label: Option<String>,
    pub key_id: Option<Vec<u8>>,
}

impl std::str::FromStr for Pkcs11Uri {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s
            .strip_prefix("pkcs11:")
            .ok_or_else(|| anyhow::anyhow!("not a PKCS#11 URI (must start with 'pkcs11:')"))?;
        let mut uri = Pkcs11Uri::default();
        for part in s.split(';') {
            if let Some((k, v)) = part.split_once('=') {
                match k {
                    "token" => uri.token_label = Some(percent_decode(v)?),
                    "object" => uri.object_label = Some(percent_decode(v)?),
                    // Pass the raw value; parse_id_bytes disambiguates between
                    // RFC 7512 percent-encoding and a hex shortcut by checking
                    // for '%' itself.  Decoding here would erase that signal.
                    "id" => uri.key_id = Some(parse_id_bytes(v)?),
                    // `type=` is part of RFC 7512.  sq-pkcs11 only operates
                    // on private signing keys, so any explicit `type=` value
                    // other than "private" silently contradicts what the
                    // tool will actually look up — refuse loudly.
                    "type" => {
                        if v != "private" {
                            anyhow::bail!(
                                "PKCS#11 URI attribute type={v:?} is incompatible with sq-pkcs11; \
                                 sq-pkcs11 always operates on private signing keys, so only \
                                 type=private (or omitting type=) is accepted"
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(uri)
    }
}

/// Percent-decode a URI text value into a UTF-8 string.
///
/// Decodes byte-by-byte (so multi-byte UTF-8 sequences like `%C3%A9` →
/// `é` round-trip correctly), then validates the result is valid UTF-8.
/// Malformed escapes (e.g. `%XY` where the digits are non-hex, or a
/// trailing `%` with fewer than two characters after it) are rejected.
fn percent_decode(s: &str) -> anyhow::Result<String> {
    let bytes = percent_decode_bytes(s)?;
    String::from_utf8(bytes).map_err(|e| anyhow::anyhow!("URI value {s:?} is not valid UTF-8: {e}"))
}

fn parse_id_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.contains('%') {
        percent_decode_bytes(s)
    } else {
        hex::decode(s).map_err(|e| anyhow::anyhow!("invalid key id hex: {e}"))
    }
}

/// Percent-decode directly to bytes (no UTF-8 round-trip).
///
/// Required for the `id` URI attribute because CKA_ID is binary; routing it
/// through `String` would re-encode bytes ≥ 0x80 as multi-byte UTF-8.
/// Malformed escapes are rejected.
fn percent_decode_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                anyhow::bail!(
                    "truncated percent-encoded sequence in URI value {s:?} \
                     (need two hex digits after '%')"
                );
            }
            let hi = (bytes[i + 1] as char).to_digit(16).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid hex digit after '%' in URI value {s:?}: {:?}",
                    bytes[i + 1] as char
                )
            })?;
            let lo = (bytes[i + 2] as char).to_digit(16).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid hex digit after '%' in URI value {s:?}: {:?}",
                    bytes[i + 2] as char
                )
            })?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// How to authenticate the session once it is open.
///
/// For K>1 OCS quorum logins, wrap the sq-pkcs11 invocation in nShield's
/// `preload` utility — it runs the quorum ceremony, and the preloaded OCS
/// is picked up by the PKCS#11 module so this end sees an already-
/// authenticated session (typically `LoginMode::None`, or `Pin("")` for
/// modules configured to still demand a C_Login call).
#[derive(Debug)]
pub enum LoginMode {
    /// Module-protected key, or a session pre-authenticated by `preload`
    /// — no C_Login call needed.
    None,
    /// Softcard or single-card OCS (K=1): standard C_Login with a passphrase.
    /// The passphrase is owned because it may have been read from a file or
    /// environment variable that doesn't outlive the args struct.
    Pin(String),
}

/// Open a PKCS#11 session on the slot best matching `selector` and log in
/// according to `login_mode`.
///
/// Slot selection logic:
///  - URI with a `token=` label → find the matching slot.
///  - URI without `token=` (or any non-URI selector) → fall through to
///    login-mode-aware selection.
///  - LoginMode::None: pick any slot whose token does not require login
///    (filters out OCS / softcard slots that may also be visible).
///  - Login required: require a single visible slot; error if there are
///    several, since the caller must specify which token to authenticate
///    against — use `--key-uri pkcs11:token=<label>...` to disambiguate.
pub fn open_session(
    pkcs11: &Pkcs11,
    selector: &KeySelector,
    login_mode: &LoginMode,
) -> Result<(Session, Slot)> {
    let slots = pkcs11.get_slots_with_initialized_token()?;
    if slots.is_empty() {
        return Err(Error::KeyNotFound(
            "no initialised PKCS#11 slots found".into(),
        ));
    }

    let slot = match selector {
        KeySelector::Uri(uri) if uri.token_label.is_some() => {
            find_slot_by_uri(pkcs11, &slots, uri)?
        }
        // Any other case (non-URI selectors, or URI without `token=`) shares
        // the login-mode-aware selection path.
        _ => smart_slot_selection(pkcs11, &slots, login_mode)?,
    };

    let session = pkcs11.open_ro_session(slot)?;

    match login_mode {
        LoginMode::None => {}

        LoginMode::Pin(pin) => {
            session.login(UserType::User, Some(&AuthPin::from(pin.clone())))?;
        }
    }

    Ok((session, slot))
}

/// Find all private signing key handles in `session` matching `selector`.
pub fn find_private_keys(session: &Session, selector: &KeySelector) -> Result<Vec<ObjectHandle>> {
    let mut template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Sign(true),
    ];

    match selector {
        KeySelector::Label(label) => {
            template.push(Attribute::Label(label.as_bytes().to_vec()));
        }
        KeySelector::Id(id) => {
            template.push(Attribute::Id(id.clone()));
        }
        KeySelector::Uri(uri) => {
            if let Some(label) = &uri.object_label {
                template.push(Attribute::Label(label.as_bytes().to_vec()));
            }
            if let Some(id) = &uri.key_id {
                template.push(Attribute::Id(id.clone()));
            }
        }
        KeySelector::Auto => {}
    }

    let handles = session.find_objects(&template)?;
    Ok(handles)
}

/// Return the single private key handle, or error on zero or multiple matches.
pub fn resolve_single_key(session: &Session, selector: &KeySelector) -> Result<ObjectHandle> {
    let keys = find_private_keys(session, selector)?;
    match keys.len() {
        0 => Err(Error::KeyNotFound(format!(
            "no signing key matched selector {selector:?}"
        ))),
        1 => Ok(keys[0]),
        n => Err(Error::AmbiguousKey { count: n }),
    }
}

/// Read a single attribute value from an object.
pub fn get_attribute(
    session: &Session,
    handle: ObjectHandle,
    attr_type: AttributeType,
) -> Result<Attribute> {
    let attrs = session.get_attributes(handle, &[attr_type])?;
    attrs
        .into_iter()
        .next()
        .ok_or_else(|| Error::KeyNotFound(format!("attribute {attr_type:?} not present on key")))
}

/// Return the PKCS#11 key type for the given key handle.
pub fn key_type(session: &Session, handle: ObjectHandle) -> Result<KeyType> {
    match get_attribute(session, handle, AttributeType::KeyType)? {
        Attribute::KeyType(kt) => Ok(kt),
        _ => unreachable!(),
    }
}

fn find_slot_by_uri(pkcs11: &Pkcs11, slots: &[Slot], uri: &Pkcs11Uri) -> Result<Slot> {
    let label = uri
        .token_label
        .as_deref()
        .expect("caller guarantees uri.token_label is set");
    let matching: Vec<Slot> = slots
        .iter()
        .filter(|&&slot| {
            pkcs11
                .get_token_info(slot)
                .map(|i| i.label().trim() == label.trim())
                .unwrap_or(false)
        })
        .copied()
        .collect();

    match matching.len() {
        0 => Err(Error::KeyNotFound(format!(
            "no token matched label {label:?}",
        ))),
        1 => Ok(matching[0]),
        n => Err(Error::AmbiguousKey { count: n }),
    }
}

/// Login-mode-aware slot picker used when the selector doesn't pin a token.
fn smart_slot_selection(
    pkcs11: &Pkcs11,
    slots: &[Slot],
    login_mode: &LoginMode,
) -> Result<Slot> {
    match login_mode {
        // Module-protected: filter out token slots that require login (OCS /
        // softcard). All remaining accelerator-style slots carry the same
        // module-protected keys, so any one works.
        LoginMode::None => {
            let no_login: Vec<Slot> = slots
                .iter()
                .filter(|&&s| {
                    pkcs11
                        .get_token_info(s)
                        .map(|i| !i.login_required())
                        .unwrap_or(false)
                })
                .copied()
                .collect();
            if no_login.is_empty() {
                Err(Error::KeyNotFound(
                    "no module-protected slots found; \
                     use --key-uri pkcs11:token=<label>... to address a token slot directly"
                        .into(),
                ))
            } else {
                Ok(no_login[0])
            }
        }
        // Login required: caller must disambiguate via a PKCS#11 URI with
        // token=<label> when multiple token slots are visible.
        _ => {
            if slots.len() == 1 {
                Ok(slots[0])
            } else {
                Err(Error::AmbiguousKey { count: slots.len() })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_full() {
        let uri: Pkcs11Uri = "pkcs11:token=mytoken;object=mykey;type=private"
            .parse()
            .unwrap();
        assert_eq!(uri.token_label.as_deref(), Some("mytoken"));
        assert_eq!(uri.object_label.as_deref(), Some("mykey"));
        assert!(uri.key_id.is_none());
    }

    #[test]
    fn uri_token_only() {
        let uri: Pkcs11Uri = "pkcs11:token=t".parse().unwrap();
        assert_eq!(uri.token_label.as_deref(), Some("t"));
        assert_eq!(uri.object_label, None);
        assert_eq!(uri.key_id, None);
    }

    #[test]
    fn uri_object_only() {
        let uri: Pkcs11Uri = "pkcs11:object=k".parse().unwrap();
        assert_eq!(uri.token_label, None);
        assert_eq!(uri.object_label.as_deref(), Some("k"));
    }

    #[test]
    fn uri_no_prefix_rejected() {
        let res: std::result::Result<Pkcs11Uri, _> = "token=foo".parse();
        assert!(res.is_err());
    }

    #[test]
    fn uri_type_private_accepted() {
        let uri: Pkcs11Uri = "pkcs11:object=k;type=private".parse().unwrap();
        assert_eq!(uri.object_label.as_deref(), Some("k"));
    }

    #[test]
    fn uri_type_other_rejected() {
        // sq-pkcs11 only operates on private signing keys; an explicit
        // type= attribute that says otherwise is a silent contradiction
        // and must be refused.
        for bad in [
            "pkcs11:object=k;type=public",
            "pkcs11:object=k;type=cert",
            "pkcs11:object=k;type=data",
            "pkcs11:object=k;type=secret-key",
        ] {
            let res: std::result::Result<Pkcs11Uri, _> = bad.parse();
            let err = res
                .err()
                .unwrap_or_else(|| panic!("parser must reject {bad:?}"))
                .to_string();
            assert!(
                err.contains("type=") && err.contains("private"),
                "expected error to mention type= and private for {bad:?}, got: {err}"
            );
        }
    }

    #[test]
    fn uri_id_hex() {
        let uri: Pkcs11Uri = "pkcs11:id=01ab02".parse().unwrap();
        assert_eq!(uri.key_id.unwrap(), vec![0x01, 0xab, 0x02]);
    }

    #[test]
    fn uri_id_percent_encoded() {
        let uri: Pkcs11Uri = "pkcs11:id=%01%ab%02".parse().unwrap();
        assert_eq!(uri.key_id.unwrap(), vec![0x01, 0xab, 0x02]);
    }

    #[test]
    fn uri_id_percent_encoded_high_bytes_dont_utf8_expand() {
        // Regression: previously we routed percent-decoded id bytes through
        // String, so 0xAB (a single byte) became 0xC2 0xAB (UTF-8 of U+00AB).
        let uri: Pkcs11Uri = "pkcs11:id=%80%ff%c0".parse().unwrap();
        assert_eq!(uri.key_id.unwrap(), vec![0x80, 0xff, 0xc0]);
    }

    #[test]
    fn uri_label_with_utf8_percent_encoding() {
        // %C3%A9 is the UTF-8 encoding of 'é'.  A correct decoder produces
        // the 1-character string "é"; the previous byte-as-char decoder
        // produced "Ã©" (UTF-8 expansion of each byte through char::from).
        let uri: Pkcs11Uri = "pkcs11:object=caf%C3%A9".parse().unwrap();
        assert_eq!(uri.object_label.as_deref(), Some("café"));
    }

    #[test]
    fn uri_token_label_with_utf8_percent_encoding() {
        let uri: Pkcs11Uri = "pkcs11:token=%E2%9C%93-token".parse().unwrap();
        assert_eq!(uri.token_label.as_deref(), Some("✓-token"));
    }

    #[test]
    fn uri_rejects_malformed_percent_escape() {
        let cases = [
            "pkcs11:object=ba%XY", // non-hex digits
            "pkcs11:object=ba%",   // truncated (no digits)
            "pkcs11:object=ba%2",  // truncated (one digit)
            "pkcs11:id=%XY",       // non-hex digits in id
        ];
        for c in cases {
            let res: std::result::Result<Pkcs11Uri, _> = c.parse();
            assert!(res.is_err(), "expected {c:?} to be rejected");
        }
    }

    #[test]
    fn uri_rejects_invalid_utf8_in_text_field() {
        // 0xFF is never valid UTF-8 — must be rejected for text fields
        // (token/object) but is fine for binary id (already covered above).
        let res: std::result::Result<Pkcs11Uri, _> = "pkcs11:object=%ff".parse();
        assert!(
            res.is_err(),
            "expected invalid UTF-8 in object= to be rejected"
        );
    }

    #[test]
    fn uri_percent_encoded_label() {
        let uri: Pkcs11Uri = "pkcs11:object=my%20key".parse().unwrap();
        assert_eq!(uri.object_label.as_deref(), Some("my key"));
    }

    #[test]
    fn uri_unknown_attribute_ignored() {
        // RFC 7512 defines several attributes (slot-id, type, ...) we don't
        // act on; they must be parsed and discarded without error.
        let uri: Pkcs11Uri = "pkcs11:slot-id=1;token=t;type=private".parse().unwrap();
        assert_eq!(uri.token_label.as_deref(), Some("t"));
    }

    #[test]
    fn uri_empty_after_prefix() {
        // No attributes at all — must parse to an empty Pkcs11Uri.
        let uri: Pkcs11Uri = "pkcs11:".parse().unwrap();
        assert!(uri.token_label.is_none());
        assert!(uri.object_label.is_none());
        assert!(uri.key_id.is_none());
    }
}
