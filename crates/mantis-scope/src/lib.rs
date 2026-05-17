//! Scope DSL: parsing, signing, verification, and evaluation.
//!
//! Phase 0 milestone M0.3 delivers:
//!
//! - [`ScopeManifest`] in YAML with `include` / `exclude` rules over
//!   host glob, port range, path glob, and protocol.
//! - [`SignedScope`] envelope with Ed25519 signature over the
//!   canonical JSON encoding of the manifest, domain-separated under
//!   the `"scope"` context.
//! - [`ScopeEvaluator`] producing `InScope` / `OutOfScope { reason }`
//!   decisions deterministically from a `ScopeQuery`.
//! - [`BudgetEnvelope`] / [`BudgetTracker`] for request/byte/time/rate
//!   limits.
//!
//! The egress proxy (M0.3, separate ADR) is the only intended caller
//! of the evaluator in production. Other callers — like report
//! generators that want to retroactively label requests — may consume
//! the evaluator too, but never the budget tracker.

pub mod budget;
pub mod error;
pub mod evaluator;
pub mod host_pattern;
pub mod manifest;
pub mod port_range;
pub mod signed;

pub use crate::budget::{BudgetDecision, BudgetEnvelope, BudgetTracker};
pub use crate::error::ScopeError;
pub use crate::evaluator::{ScopeDecision, ScopeEvaluator, ScopeQuery};
pub use crate::host_pattern::HostPattern;
pub use crate::manifest::{
    Protocol, ScopeManifest, ScopeRules, MANIFEST_SCHEMA_MAX, MANIFEST_SCHEMA_VERSION,
};
pub use crate::port_range::PortMatcher;
pub use crate::signed::{SignedScope, SCOPE_SIGN_CONTEXT};

pub(crate) mod hex64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}
