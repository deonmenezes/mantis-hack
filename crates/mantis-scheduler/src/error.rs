use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("malformed cron expression {expr:?}: {reason}")]
    Cron { expr: String, reason: String },

    #[error("schedule {id} not found")]
    NotFound { id: String },

    #[error("internal lock poisoned")]
    Poisoned,
}
