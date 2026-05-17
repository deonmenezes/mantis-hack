//! Scope manifest.
//!
//! A `ScopeManifest` declares what an authorized engagement may touch.
//! Persisted as YAML; signed as canonical JSON (since YAML allows
//! multiple equivalent encodings, the JSON form is the canonical input
//! to the signing routine).

use mantis_core::{EngagementId, OperatorId};
use serde::{Deserialize, Serialize};

use crate::budget::BudgetEnvelope;
use crate::error::ScopeError;
use crate::host_pattern::HostPattern;
use crate::port_range::PortMatcher;

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_SCHEMA_MAX: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeManifest {
    pub schema_version: u32,
    pub engagement_id: EngagementId,
    pub authorized_by: OperatorId,
    pub expires_at_unix: u64,
    pub budget: BudgetEnvelope,
    pub include: ScopeRules,
    #[serde(default)]
    pub exclude: ScopeRules,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRules {
    #[serde(default)]
    pub hosts: Vec<HostPattern>,
    #[serde(default)]
    pub ports: Vec<PortMatcher>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<Protocol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
}

impl ScopeManifest {
    pub fn from_yaml(s: &str) -> Result<Self, ScopeError> {
        let manifest: Self = serde_yaml_ng::from_str(s)?;
        if manifest.schema_version > MANIFEST_SCHEMA_MAX {
            return Err(ScopeError::UnsupportedSchema {
                got: manifest.schema_version,
                max: MANIFEST_SCHEMA_MAX,
            });
        }
        Ok(manifest)
    }

    pub fn to_yaml(&self) -> Result<String, ScopeError> {
        serde_yaml_ng::to_string(self).map_err(Into::into)
    }

    /// Canonical bytes used as the signing input. Always JSON — same
    /// output regardless of which YAML formatting the producer used.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ScopeError> {
        serde_json::to_vec(self).map_err(Into::into)
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn sample_manifest() -> ScopeManifest {
        ScopeManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            engagement_id: EngagementId(Ulid::new()),
            authorized_by: OperatorId(Ulid::new()),
            expires_at_unix: 1_900_000_000,
            budget: BudgetEnvelope {
                max_requests: 1000,
                max_egress_bytes: 100_000_000,
                max_wall_clock_seconds: 3600,
                max_requests_per_second: 50,
            },
            include: ScopeRules {
                hosts: vec![HostPattern::new("api.example.com")],
                ports: vec![PortMatcher::single(443)],
                paths: vec!["/api/*".into()],
                protocols: vec![Protocol::Https],
            },
            exclude: ScopeRules::default(),
        }
    }

    #[test]
    fn yaml_round_trip() {
        let m = sample_manifest();
        let yaml = m.to_yaml().unwrap();
        let back = ScopeManifest::from_yaml(&yaml).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn canonical_bytes_are_stable() {
        let m1 = sample_manifest();
        let m2 = m1.clone();
        assert_eq!(m1.canonical_bytes().unwrap(), m2.canonical_bytes().unwrap());
    }

    #[test]
    fn schema_version_too_high_rejected() {
        let mut m = sample_manifest();
        m.schema_version = MANIFEST_SCHEMA_MAX + 1;
        let yaml = m.to_yaml().unwrap();
        let result = ScopeManifest::from_yaml(&yaml);
        assert!(matches!(result, Err(ScopeError::UnsupportedSchema { .. })));
    }

    #[test]
    fn is_expired_at_or_after_expires_at() {
        let m = sample_manifest();
        assert!(!m.is_expired(0));
        assert!(!m.is_expired(m.expires_at_unix - 1));
        assert!(m.is_expired(m.expires_at_unix));
        assert!(m.is_expired(m.expires_at_unix + 100));
    }

    #[test]
    fn exclude_defaults_to_empty() {
        let yaml = r#"
schema_version: 1
engagement_id: 01HXXXXXXXXXXXXXXXXXXXXXXX
authorized_by: 01HYYYYYYYYYYYYYYYYYYYYYY1
expires_at_unix: 1900000000
budget:
  max_requests: 100
  max_egress_bytes: 1000000
  max_wall_clock_seconds: 60
  max_requests_per_second: 10
include:
  hosts: ["example.com"]
  ports: [443]
  paths: ["/"]
  protocols: [https]
"#;
        let m = ScopeManifest::from_yaml(yaml).unwrap();
        assert!(m.exclude.hosts.is_empty());
        assert!(m.exclude.ports.is_empty());
    }
}
