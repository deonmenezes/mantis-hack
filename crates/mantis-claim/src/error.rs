use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClaimError {
    #[error("reqwest: {0}")]
    Http(#[from] reqwest::Error),

    #[error("no verifier registered for vuln_class {0}")]
    NoVerifier(String),

    #[error("malformed claim: {0}")]
    Malformed(String),
}
