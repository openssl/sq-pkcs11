use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("PKCS#11: {0}")]
    Pkcs11(#[from] cryptoki::error::Error),

    #[error("OpenPGP: {0}")]
    OpenPgp(#[from] sequoia_openpgp::Error),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("ambiguous key selection: {count} usable keys found; use --key-label, --key-id, or a PKCS#11 URI")]
    AmbiguousKey { count: usize },

    #[error("unsupported key type on HSM: {0}")]
    UnsupportedKeyType(String),

    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
