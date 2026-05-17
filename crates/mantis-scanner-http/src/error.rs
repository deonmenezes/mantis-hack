//! Errors emitted by the HTTP scanner.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("reqwest: {0}")]
    Http(#[from] reqwest::Error),

    #[error("event store: {0}")]
    EventStore(#[from] mantis_event_store::EventStoreError),

    #[error("invalid target: {0}")]
    InvalidTarget(String),

    #[error("invalid proxy URL: {0}")]
    InvalidProxy(String),
}
