//! Errors emitted by event store operations.

use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EventStoreError {
    #[error("rocksdb: {0}")]
    RocksDb(#[from] rocksdb::Error),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("engagement {0} not found")]
    EngagementNotFound(String),

    #[error("leaf index {index} out of range for leaf count {count}")]
    LeafOutOfRange { index: u64, count: u64 },

    #[error("internal invariant violated: {0}")]
    Invariant(String),
}
