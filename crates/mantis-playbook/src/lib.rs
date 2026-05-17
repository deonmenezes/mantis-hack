//! Playbook distiller (Phase 3 M3.1).
//!
//! After each engagement, the distiller scans the event log and
//! proposes named, parameterized [`Playbook`]s derived from
//! successful exploit chains. A playbook is a typed sequence of
//! preconditions, ordered primitive invocations, oracle assertions,
//! and exploit templates (PRD §5.8.1).
//!
//! Phase 3 M3.1 ships the basic distiller: mine
//! `(SurfaceDiscovered → HypothesisGenerated → PrimitiveExecuted
//! → ClaimVerified)` sequences. A future milestone adds
//! cross-engagement aggregation, parameter generalization, and
//! tournament selection (PRD §5.8.4).

pub mod distiller;
pub mod tournament;

use serde::{Deserialize, Serialize};
use ulid::Ulid;

pub use crate::distiller::distill;
pub use crate::tournament::{tournament_prune, PlaybookStats};

/// Stable identifier for a playbook within a workspace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlaybookId(pub Ulid);

impl PlaybookId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }
}

impl Default for PlaybookId {
    fn default() -> Self {
        Self::new()
    }
}

/// Playbook record. Preconditions describe the surface shape this
/// playbook targets; steps are the primitive invocations to run in
/// order; stats track historical outcomes for the tournament
/// selector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: PlaybookId,
    /// Human-readable name. Derived from the head step's vuln_class.
    pub name: String,
    /// What the surface must look like for this playbook to apply.
    pub preconditions: Preconditions,
    /// Ordered primitives to execute.
    pub steps: Vec<PlaybookStep>,
    /// Tournament statistics, updated each invocation.
    pub stats: PlaybookStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Preconditions {
    /// Surface URL prefix (None = any).
    pub url_prefix: Option<String>,
    /// Tech-hint that must be present (None = any).
    pub tech_hint: Option<String>,
    /// Status range (inclusive). Default 200..=399.
    pub status_min: u16,
    pub status_max: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub primitive_id: String,
    pub vuln_class: String,
    /// Identifier of the verifier this step's `ClaimVerified` event
    /// referenced. Phase 3 stores this for telemetry; M3.2 will use
    /// it as an explicit oracle the runner re-checks.
    pub verifier_id: Option<String>,
}

impl Playbook {
    pub fn new(name: String, preconditions: Preconditions, steps: Vec<PlaybookStep>) -> Self {
        Self {
            id: PlaybookId::new(),
            name,
            preconditions,
            steps,
            stats: PlaybookStats::default(),
        }
    }
}
