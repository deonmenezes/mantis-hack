//! Errors emitted by scope operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("invalid port range '{0}': {1}")]
    PortRange(String, String),

    #[error("invalid host pattern '{0}': {1}")]
    HostPattern(String, String),

    #[error("scope expired at {expires_at_unix}, now {now_unix}")]
    Expired { expires_at_unix: u64, now_unix: u64 },

    #[error("signature does not verify against authorizing operator's public key")]
    SignatureInvalid,

    #[error("malformed signed-scope envelope: {0}")]
    Envelope(String),

    #[error("schema version {got} not supported (max {max})")]
    UnsupportedSchema { got: u32, max: u32 },
}
