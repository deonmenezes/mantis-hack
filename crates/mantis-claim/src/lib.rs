//! Claim verification.
//!
//! When a [`Primitive`](mantis_primitive::Primitive) returns
//! `Confirmed`, the result becomes a [`Claim`] in the
//! [`ClaimState::Pending`] state. An independent [`Verifier`] then
//! re-runs the reproducer against the target. If the verifier
//! observes the same evidence, the claim transitions to
//! [`ClaimState::Verified`] and becomes reportable (PRD §5.6.2).
//!
//! The verifier MUST be independent of the primitive: it takes only
//! the reproducer and the original evidence summary as input. It
//! does NOT see the primitive's internal state or the original
//! response. This is the property that lets us catch
//! primitive-implementation bugs as verifier rejections.

pub mod error;
pub mod verifier;
pub mod verifiers;

pub use crate::error::ClaimError;
pub use crate::verifier::{verify_claim, Verifier};

use mantis_primitive::{EvidenceItem, Reproducer};
use mantis_scanner_http::Surface;
use serde::{Deserialize, Serialize};

/// A claim is a primitive verdict promoted out of the result type so
/// it can carry its verification state across daemon restarts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    /// `vuln_class.name` (matches the primitive's `id()`).
    pub primitive_id: String,
    pub vuln_class: String,
    /// Frozen snapshot of the surface this claim references.
    pub surface: SurfaceSnapshot,
    pub evidence: Vec<EvidenceItem>,
    pub reproducer: Reproducer,
    pub state: ClaimState,
}

/// Cut-down [`Surface`] that's deterministically serializable. The
/// full Surface contains a reqwest-side `Response` reference; we
/// only need the request side here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurfaceSnapshot {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub status: u16,
}

impl From<&Surface> for SurfaceSnapshot {
    fn from(s: &Surface) -> Self {
        Self {
            scheme: s.target.scheme.clone(),
            host: s.target.host.clone(),
            port: s.target.port,
            path: s.target.path.clone(),
            status: s.status,
        }
    }
}

impl SurfaceSnapshot {
    pub fn url(&self) -> String {
        format!("{}://{}:{}{}", self.scheme, self.host, self.port, self.path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ClaimState {
    /// Primitive confirmed but verifier hasn't run yet.
    Pending,
    /// Independent verifier observed the same evidence.
    Verified { verifier_id: String },
    /// Verifier could not reproduce. Reason explains what changed
    /// between primitive and verifier.
    Rejected { reason: String },
    /// Verifier hit a non-deterministic error (network, timeout,
    /// 5xx). Kept for human review but not reported.
    Retained { reason: String },
}

impl Claim {
    pub fn pending(
        primitive_id: String,
        vuln_class: String,
        surface: SurfaceSnapshot,
        evidence: Vec<EvidenceItem>,
        reproducer: Reproducer,
    ) -> Self {
        Self {
            primitive_id,
            vuln_class,
            surface,
            evidence,
            reproducer,
            state: ClaimState::Pending,
        }
    }
}
