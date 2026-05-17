use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrimitiveError {
    #[error("reqwest: {0}")]
    Http(#[from] reqwest::Error),

    #[error("primitive {0} does not apply to this surface")]
    DoesNotApply(&'static str),

    #[error("internal: {0}")]
    Internal(String),
}
