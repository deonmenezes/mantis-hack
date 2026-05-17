//! Kubernetes operator types (Phase 5 M5.1).
//!
//! PRD §14.5 describes Mantis as a Kubernetes Operator hosting
//! engagements as Custom Resources. M5.1 ships the CRD schemas
//! (Engagement, ScheduledScan, ResultExport) as Rust structs that
//! serialize to the YAML Kubernetes expects.
//!
//! The actual controller loop (watch → reconcile → status update)
//! lands in M5.1b alongside a `kube-rs`-backed adapter; the CRD
//! types here let an operator `kubectl apply -f engagement.yaml`
//! against a cluster that has the CRDs installed.

pub mod engagement;
pub mod export;
pub mod schedule;

use serde::{Deserialize, Serialize};

pub use crate::engagement::{Engagement, EngagementSpec, EngagementStatus};
pub use crate::export::{ResultExport, ResultExportSpec};
pub use crate::schedule::{ScheduledScan, ScheduledScanSpec};

/// Common Kubernetes object metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub annotations: std::collections::BTreeMap<String, String>,
}

impl ObjectMeta {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: None,
            labels: Default::default(),
            annotations: Default::default(),
        }
    }
}

pub const API_VERSION: &str = "mantis.security/v1";
