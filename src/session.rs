use std::path::Path;

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
                let v = percent_decode(v);
                match k {
                    "token" => uri.token_label = Some(v),
                    "object" => uri.object_label = Some(v),
                    "id" => uri.key_id = Some(parse_id_bytes(&v)?),
                    _ => {}
                }
            }
        }
        Ok(uri)
    }
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hi = chars.next().unwrap_or('0');
            let lo = chars.next().unwrap_or('0');
            if let Ok(b) = u8::from_str_radix(&format!("{hi}{lo}"), 16) {
                out.push(b as char);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_id_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.contains('%') {
        Ok(percent_decode(s).bytes().collect())
    } else {
        hex::decode(s).map_err(|e| anyhow::anyhow!("invalid key id hex: {e}"))
    }
}

/// How to authenticate the session once it is open.
#[derive(Debug)]
pub enum LoginMode<'a> {
    /// Module-protected key — no C_Login call needed.
    None,
    /// Softcard or single-card OCS (K=1): standard C_Login with a passphrase.
    Pin(&'a str),
    /// OCS with K > 1: nShield C_LoginBegin / C_LoginNext / C_LoginEnd.
    OcsQuorum {
        module_path: &'a Path,
    },
}

/// Open a PKCS#11 session on the slot best matching `selector` and log in
/// according to `login_mode`.
///
/// Slot selection logic:
///  - URI with a token label: find the slot whose token label matches.
///  - Any other selector with a single slot: use it directly.
///  - Any other selector with multiple slots + no login needed: use the first
///    slot.  With multiple HSM modules in one Security World every accelerator
///    slot carries the same module-protected keys, so any slot is equivalent.
///  - Any other selector with multiple slots + login required: error — the
///    caller must provide a PKCS#11 URI with `token=<label>` to identify which
///    token to authenticate against.
pub fn open_session<'a>(
    pkcs11: &Pkcs11,
    selector: &KeySelector,
    login_mode: &LoginMode<'_>,
) -> Result<(Session, Slot)> {
    let slots = pkcs11.get_slots_with_initialized_token()?;
    if slots.is_empty() {
        return Err(Error::KeyNotFound("no initialised PKCS#11 slots found".into()));
    }

    let slot = match selector {
        KeySelector::Uri(uri) => find_slot_by_uri(pkcs11, &slots, uri)?,
        _ => {
            if slots.len() == 1 {
                slots[0]
            } else {
                match login_mode {
                    // Module-protected: all accelerator slots are equivalent,
                    // use the first one.
                    LoginMode::None => slots[0],
                    // Login required: we must know which token to authenticate.
                    _ => {
                        return Err(Error::AmbiguousKey { count: slots.len() });
                    }
                }
            }
        }
    };

    let session = pkcs11.open_ro_session(slot)?;

    match login_mode {
        LoginMode::None => {}

        LoginMode::Pin(pin) => {
            session.login(UserType::User, Some(&AuthPin::from(pin.to_string())))?;
        }

        LoginMode::OcsQuorum { module_path } => {
            let ext = crate::nfast::NfastQuorumLogin::load(module_path)?;
            ext.quorum_login(session.handle(), |card_n, k, n| {
                let prompt = format!(
                    "Insert card {card_n} of {k} (K={k}/N={n}) and enter passphrase \
                     (leave blank if not passphrase-protected): "
                );
                let pin = rpassword::prompt_password(prompt)
                    .map_err(|e| anyhow::anyhow!("passphrase prompt failed: {e}"))?;
                Ok(pin)
            })?;
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
    let matching: Vec<Slot> = slots
        .iter()
        .filter(|&&slot| {
            if let Some(label) = &uri.token_label {
                if let Ok(info) = pkcs11.get_token_info(slot) {
                    return info.label().trim() == label.trim();
                }
                return false;
            }
            true
        })
        .copied()
        .collect();

    match matching.len() {
        0 => Err(Error::KeyNotFound(format!(
            "no token matched label {:?}",
            uri.token_label
        ))),
        1 => Ok(matching[0]),
        n => Err(Error::AmbiguousKey { count: n }),
    }
}
