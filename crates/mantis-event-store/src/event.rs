//! Event payloads.
//!
//! Phase 0 ships a minimal set of variants — enough to exercise the
//! append-and-verify path. Later milestones extend [`EventKind`] with
//! engagement-state transitions, scope decisions, observations, claim
//! transitions, exploit synthesis events, and so on.
//!
//! Every variant carries a `schema_version` on the outer [`Event`] so
//! that breaking changes to the wire shape are explicit. Adding a new
//! optional field is non-breaking; renaming or removing a field is.

use serde::{Deserialize, Serialize};

pub const EVENT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: u16,
    pub seq: u64,
    pub wall_clock_unix: u64,
    pub kind: EventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum EventKind {
    EngagementCreated {
        name: String,
    },
    EngagementAuthorized {
        scope_hash: String,
    },
    EngagementStarted,
    EngagementPaused,
    EngagementResumed,
    EngagementCompleted,
    ObservationRecorded {
        payload_hex: String,
    },
    ScopeDecisionLogged {
        in_scope: bool,
        target: String,
        reason: String,
    },
    SurfaceDiscovered {
        host: String,
        port: u16,
        scheme: String,
        path: String,
        status: u16,
        server: Option<String>,
        content_length: Option<u64>,
        tech_hints: Vec<String>,
    },
    HypothesisGenerated {
        surface_id: String,
        vuln_class: String,
        summary: String,
        prior: u32,
    },
    PrimitiveExecuted {
        surface_id: String,
        primitive_id: String,
        vuln_class: String,
        verdict: String,
    },
    ClaimVerified {
        surface_id: String,
        primitive_id: String,
        verifier_id: String,
    },
    ClaimRejected {
        surface_id: String,
        primitive_id: String,
        reason: String,
    },
    ClaimRetained {
        surface_id: String,
        primitive_id: String,
        reason: String,
    },
}

impl Event {
    pub fn new(seq: u64, wall_clock_unix: u64, kind: EventKind) -> Self {
        Self {
            schema_version: EVENT_SCHEMA_VERSION,
            seq,
            wall_clock_unix,
            kind,
        }
    }

    /// Deterministic JSON encoding used as the input to leaf hashing.
    /// Field order on a struct is declaration order; this enum tags
    /// variants explicitly so the wire shape is stable across Rust
    /// releases.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_are_stable() {
        let e1 = Event::new(0, 1_000_000, EventKind::EngagementStarted);
        let e2 = Event::new(0, 1_000_000, EventKind::EngagementStarted);
        assert_eq!(e1.canonical_bytes().unwrap(), e2.canonical_bytes().unwrap());
    }

    #[test]
    fn canonical_bytes_differ_for_different_events() {
        let e1 = Event::new(0, 1, EventKind::EngagementStarted);
        let e2 = Event::new(1, 1, EventKind::EngagementStarted);
        assert_ne!(e1.canonical_bytes().unwrap(), e2.canonical_bytes().unwrap());
    }

    #[test]
    fn round_trip_json() {
        let e = Event::new(
            7,
            1_700_000_000,
            EventKind::EngagementAuthorized {
                scope_hash: "abc".into(),
            },
        );
        let bytes = e.canonical_bytes().unwrap();
        let back: Event = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(e, back);
    }
}
