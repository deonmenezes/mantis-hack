//! Errors emitted by the egress proxy.

use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EgressError {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("event store: {0}")]
    EventStore(#[from] mantis_event_store::EventStoreError),

    #[error("malformed CONNECT request: {0}")]
    Malformed(String),

    #[error("DNS resolution failed for {host}: {reason}")]
    Resolve { host: String, reason: String },

    #[error("scope rejected: {reason}")]
    OutOfScope { reason: String },

    #[error("budget exhausted: {0:?}")]
    Budget(mantis_scope::BudgetDecision),

    #[error("connection closed before request complete")]
    PrematureClose,

    #[error("request larger than maximum ({max} bytes)")]
    RequestTooLarge { max: usize },
}
