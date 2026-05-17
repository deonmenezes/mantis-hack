//! Errors emitted by workspace operations.

use std::io;

use thiserror::Error;

use crate::keystore::KeyStoreError;

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("workspace already initialized at {path}")]
    AlreadyInitialized { path: String },

    #[error("workspace not found at {path} (run `mantis workspace init`)")]
    NotFound { path: String },

    #[error("config malformed: {0}")]
    ConfigMalformed(String),

    #[error("operator not found: {id}")]
    OperatorNotFound { id: String },

    #[error("operator name already in use: {name}")]
    OperatorNameTaken { name: String },

    #[error("operator name is empty or whitespace-only")]
    OperatorNameEmpty,

    #[error("keystore failure: {0}")]
    KeyStore(#[from] KeyStoreError),

    #[error("malformed key bytes")]
    MalformedKey,

    #[error("workspace public key in config does not match keystore secret")]
    KeyMismatch,

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("toml encode: {0}")]
    TomlEncode(#[from] toml::ser::Error),

    #[error("toml decode: {0}")]
    TomlDecode(#[from] toml::de::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
}
