use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("PKCS#11: {0}")]
    Pkcs11(#[from] cryptoki::error::Error),

    #[error("OpenPGP: {0}")]
    OpenPgp(#[from] sequoia_openpgp::Error),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error(
        "ambiguous slot selection: {count} token slots found; \
         use --key-uri with token=<label> to identify which token to authenticate against \
         (e.g. pkcs11:token=my-softcard;object=my-key;type=private)"
    )]
    AmbiguousKey { count: usize },

    #[error("unsupported key type on HSM: {0}")]
    UnsupportedKeyType(String),

    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
