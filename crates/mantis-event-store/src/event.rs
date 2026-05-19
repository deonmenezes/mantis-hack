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
    /// FSM phase transition. Recorded by the daemon when an operator
    /// (or the orchestrator) advances the pipeline from one phase to
    /// the next. `blockers` is non-empty iff `override_reason` is set
    /// — in which case the operator explicitly accepted the gate
    /// failure and the override is part of the audit trail.
    PhaseTransitioned {
        from: String,
        to: String,
        /// Operator-supplied rationale when an override was applied.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        override_reason: Option<String>,
        /// Stable blocker codes captured at transition time. Empty
        /// list means the gate was open and no override was needed.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        blocker_codes: Vec<String>,
    },
    /// A verification attempt opened. Carries the deterministic
    /// snapshot hash so independent observers can verify which
    /// finding set the cascade was bound to.
    VerificationAttemptOpened {
        attempt_id: String,
        snapshot_hash: String,
        finding_ids: Vec<String>,
    },
    /// One of the three cascade rounds wrote its verdicts. `round` is
    /// `brutalist|balanced|final`. `results_canonical_hash` is a
    /// blake3 fingerprint of the canonical-JSON of the full round
    /// payload — operators can detect tampering across re-renders.
    VerificationRoundWritten {
        attempt_id: String,
        round: String,
        results_canonical_hash: String,
        results_count: u32,
        /// Set only on `final`: the adjudication plan hash this
        /// round was bound to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        references_plan_hash: Option<String>,
    },
    /// Daemon built the deterministic adjudication from brutalist +
    /// balanced. The plan hash gates the final round.
    AdjudicationBuilt {
        attempt_id: String,
        plan_hash: String,
        agreed_count: u32,
        disagreements_count: u32,
        replay_required_count: u32,
        qa_sample_count: u32,
    },
    /// Tiered runner produced a finding via LLM codegen (medium / hard
    /// tier). Mirrors the shape of `ClaimVerified` but carries the
    /// tier kind + iteration count so operators see how expensive the
    /// finding was.
    TieredFindingProduced {
        surface_id: String,
        vuln_class: String,
        tier: String,
        severity: String,
        verifier_verdict: String,
        hard_iterations: u32,
    },
    /// Tiered runner ran and produced no finding (or errored). The
    /// per-tier results are captured so operators can audit
    /// escalation decisions after the fact.
    TieredEscalationExhausted {
        surface_id: String,
        light_result: Option<String>,
        medium_result: Option<String>,
        hard_result: Option<String>,
        notes_joined: String,
    },
    /// Grader wrote a SUBMIT/HOLD/SKIP verdict. `verdict_json` is the
    /// canonical JSON of the full `GradeVerdict` for event-log replay
    /// on daemon restart. `verdict_canonical_hash` is its blake3
    /// fingerprint for operator tamper-detection.
    GradeVerdictRecorded {
        verdict: String,
        total_score: u32,
        verdict_canonical_hash: String,
        /// Full canonical JSON stored for replay.
        verdict_json: String,
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

    #[test]
    fn phase_transitioned_round_trips() {
        let e = Event::new(
            10,
            1_700_000_000,
            EventKind::PhaseTransitioned {
                from: "RECON".into(),
                to: "AUTH".into(),
                override_reason: None,
                blocker_codes: Vec::new(),
            },
        );
        let back: Event = serde_json::from_slice(&e.canonical_bytes().unwrap()).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn verification_attempt_opened_round_trips() {
        let e = Event::new(
            20,
            1_700_000_000,
            EventKind::VerificationAttemptOpened {
                attempt_id: "att-1".into(),
                snapshot_hash: "deadbeef".into(),
                finding_ids: vec!["F-1".into(), "F-2".into()],
            },
        );
        let back: Event = serde_json::from_slice(&e.canonical_bytes().unwrap()).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn verification_round_written_includes_plan_hash() {
        let e = Event::new(
            21,
            1_700_000_000,
            EventKind::VerificationRoundWritten {
                attempt_id: "att-1".into(),
                round: "final".into(),
                results_canonical_hash: "feedbeef".into(),
                results_count: 3,
                references_plan_hash: Some("planhash".into()),
            },
        );
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("VerificationRoundWritten"));
        assert!(json.contains("references_plan_hash"));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn adjudication_built_round_trips() {
        let e = Event::new(
            22,
            1_700_000_000,
            EventKind::AdjudicationBuilt {
                attempt_id: "att-1".into(),
                plan_hash: "planhash".into(),
                agreed_count: 5,
                disagreements_count: 1,
                replay_required_count: 6,
                qa_sample_count: 3,
            },
        );
        let back: Event = serde_json::from_slice(&e.canonical_bytes().unwrap()).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn phase_transitioned_carries_override() {
        let e = Event::new(
            11,
            1_700_000_000,
            EventKind::PhaseTransitioned {
                from: "HUNT".into(),
                to: "CHAIN".into(),
                override_reason: Some(
                    "operator accepted unexplored high surface; tracked in PR-42".into(),
                ),
                blocker_codes: vec!["unexplored_high_surfaces".into()],
            },
        );
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("PhaseTransitioned"));
        assert!(json.contains("override_reason"));
        assert!(json.contains("unexplored_high_surfaces"));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}
