use thiserror::Error;

#[derive(Debug, Error)]
pub enum HypothesisError {
    #[error("event store: {0}")]
    EventStore(#[from] mantis_event_store::EventStoreError),
}
