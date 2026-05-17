//! Engagement Custom Resource.

use serde::{Deserialize, Serialize};

use crate::{ObjectMeta, API_VERSION};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Engagement {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: EngagementSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<EngagementStatus>,
}

impl Engagement {
    pub fn new(name: impl Into<String>, spec: EngagementSpec) -> Self {
        Self {
            api_version: API_VERSION.into(),
            kind: "Engagement".into(),
            metadata: ObjectMeta::new(name),
            spec,
            status: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementSpec {
    /// Targets in scope (URL patterns matching the engagement's
    /// signed scope manifest).
    pub targets: Vec<String>,
    /// Reference to the signed scope manifest ConfigMap or Secret.
    pub scope_ref: SecretRef,
    /// Operator identity reference.
    pub operator_ref: SecretRef,
    /// Optional override of the per-engagement budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<EngagementBudget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementBudget {
    pub max_requests: u64,
    pub max_egress_bytes: u64,
    pub max_wall_clock_seconds: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngagementStatus {
    pub phase: String,
    pub events_recorded: u64,
    pub verified_claims: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub type_: String,
    pub status: String,
    pub reason: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_round_trip() {
        let spec = EngagementSpec {
            targets: vec!["https://api.example.com/**".into()],
            scope_ref: SecretRef {
                name: "scope".into(),
                namespace: Some("default".into()),
                key: "scope.json".into(),
            },
            operator_ref: SecretRef {
                name: "operator".into(),
                namespace: None,
                key: "id.pub".into(),
            },
            budget: Some(EngagementBudget {
                max_requests: 10_000,
                max_egress_bytes: 1_000_000_000,
                max_wall_clock_seconds: 3600,
            }),
        };
        let engagement = Engagement::new("acme-monitor", spec);
        let yaml = serde_yaml_ng::to_string(&engagement).unwrap();
        let back: Engagement = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(back.api_version, "mantis.security/v1");
        assert_eq!(back.kind, "Engagement");
        assert_eq!(back.metadata.name, "acme-monitor");
        assert_eq!(back.spec.targets.len(), 1);
    }

    #[test]
    fn status_optional() {
        let spec = EngagementSpec {
            targets: vec![],
            scope_ref: SecretRef {
                name: "x".into(),
                namespace: None,
                key: "y".into(),
            },
            operator_ref: SecretRef {
                name: "x".into(),
                namespace: None,
                key: "y".into(),
            },
            budget: None,
        };
        let engagement = Engagement::new("e", spec);
        let yaml = serde_yaml_ng::to_string(&engagement).unwrap();
        assert!(!yaml.contains("status:"));
    }
}
