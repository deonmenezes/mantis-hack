//! Shared types, errors, and pure logic for the Mantis daemon.
//!
//! This crate has no I/O and no async dependencies. Every other crate in the
//! workspace may depend on it. Keep it that way — anything that needs the
//! network, the filesystem, or a runtime belongs in a different crate.
//!
//! Phase 0 scope: identifier newtypes, the root [`MantisError`], and the
//! [`EngagementState`] enum. The full data model from PRD §7.4 lands across
//! milestones M0.1 through M0.5.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

/// Unique identifier for an engagement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EngagementId(pub Ulid);

/// Unique identifier for an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperatorId(pub Ulid);

/// Unique identifier for a workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceId(pub Ulid);

impl std::fmt::Display for EngagementId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for OperatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// State machine for an engagement, per PRD §5.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngagementState {
    Draft,
    Authorized,
    Active,
    Paused,
    Completed,
    Archived,
}

impl EngagementState {
    /// Validate a transition. Returns `false` if the target state is
    /// unreachable from `self`. PRD §5.1.3 mandates that every transition
    /// land in the event log; this function only governs which transitions
    /// are legal in the first place.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        use EngagementState::{Active, Archived, Authorized, Completed, Draft, Paused};
        matches!(
            (self, next),
            (Draft, Authorized)
                | (Authorized, Active)
                | (Active, Paused)
                | (Paused, Active)
                | (Active, Completed)
                | (Paused, Completed)
                | (Completed, Archived)
        )
    }
}

/// Root error type for the Mantis system.
#[derive(Debug, Error)]
pub enum MantisError {
    #[error("invariant violated: {0}")]
    Invariant(String),

    #[error("illegal state transition: {from:?} -> {to:?}")]
    IllegalTransition {
        from: EngagementState,
        to: EngagementState,
    },
}

/// Anything that can produce an Ed25519-equivalent signature over a
/// domain-separated payload. Implemented by `mantis_workspace::Workspace`
/// and `mantis_workspace::Keypair`.
///
/// The contract: the returned 64-byte signature must verify against the
/// implementor's `public_key()` for the same `(context, payload)` pair
/// when fed through the same domain-separation rule.
pub trait Signer: Send + Sync {
    /// Sign `payload` under the named context. The returned bytes are an
    /// Ed25519 signature in canonical form.
    fn sign(&self, context: &str, payload: &[u8]) -> [u8; 64];

    /// Return the verifier-side public key as 32 raw bytes.
    fn public_key_bytes(&self) -> [u8; 32];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_can_only_authorize() {
        assert!(EngagementState::Draft.can_transition_to(EngagementState::Authorized));
        assert!(!EngagementState::Draft.can_transition_to(EngagementState::Active));
    }

    #[test]
    fn archived_is_terminal() {
        for state in [
            EngagementState::Draft,
            EngagementState::Authorized,
            EngagementState::Active,
            EngagementState::Paused,
            EngagementState::Completed,
            EngagementState::Archived,
        ] {
            assert!(!EngagementState::Archived.can_transition_to(state));
        }
    }

    #[test]
    fn pause_resume_round_trip() {
        assert!(EngagementState::Active.can_transition_to(EngagementState::Paused));
        assert!(EngagementState::Paused.can_transition_to(EngagementState::Active));
    }
}
