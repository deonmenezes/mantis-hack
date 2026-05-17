//! Shared state model exposed to the browser.
//!
//! The daemon owns a single [`WebState`] and pushes updates into the
//! [`EventChannel`]. The HTTP server reads the state for `/api/state`
//! and forwards channel events to SSE subscribers on `/api/events`.

use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebState {
    pub engagements: Vec<EngagementView>,
    pub claims: Vec<ClaimView>,
    pub log_tail: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementView {
    pub id: String,
    pub name: String,
    pub state: String,
    pub events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimView {
    pub vuln_class: String,
    pub severity: String,
    pub status: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Event {
    EngagementUpserted(EngagementView),
    ClaimAdded(ClaimView),
    LogLine { line: String },
}

/// Wrapper over a tokio broadcast channel sized for the daemon's
/// fan-out — many SSE subscribers, one writer.
#[derive(Clone)]
pub struct EventChannel {
    tx: broadcast::Sender<Event>,
}

impl EventChannel {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    pub fn send(&self, event: Event) {
        // Ignore SendError: subscribers may have all dropped, which
        // is normal during shutdown.
        let _ = self.tx.send(event);
    }

    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl std::fmt::Debug for EventChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventChannel")
            .field("receivers", &self.tx.receiver_count())
            .finish()
    }
}

pub type SharedState = Arc<RwLock<WebState>>;

pub fn new_shared() -> SharedState {
    Arc::new(RwLock::new(WebState::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webstate_serializes_with_stable_field_names() {
        let mut s = WebState::default();
        s.engagements.push(EngagementView {
            id: "01HA".into(),
            name: "demo".into(),
            state: "active".into(),
            events: 7,
        });
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"engagements\""));
        assert!(json.contains("\"01HA\""));
        assert!(json.contains("\"events\":7"));
    }

    #[test]
    fn event_serializes_with_type_tag() {
        let e = Event::LogLine {
            line: "hello".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"type\":\"LogLine\""));
        assert!(json.contains("\"line\":\"hello\""));
    }

    #[tokio::test]
    async fn event_channel_broadcasts_to_subscribers() {
        let ch = EventChannel::new(16);
        let mut rx1 = ch.subscribe();
        let mut rx2 = ch.subscribe();
        ch.send(Event::LogLine { line: "x".into() });
        let a = rx1.recv().await.unwrap();
        let b = rx2.recv().await.unwrap();
        assert!(matches!(a, Event::LogLine { .. }));
        assert!(matches!(b, Event::LogLine { .. }));
    }

    #[test]
    fn event_channel_receiver_count_tracks_live_subscribers() {
        let ch = EventChannel::new(4);
        assert_eq!(ch.receiver_count(), 0);
        let r = ch.subscribe();
        assert_eq!(ch.receiver_count(), 1);
        drop(r);
        assert_eq!(ch.receiver_count(), 0);
    }
}
