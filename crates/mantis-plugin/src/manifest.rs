//! Plugin manifest (PRD §8.1).
//!
//! Each plugin ships as an OCI artifact containing a WASI 0.2
//! component plus a signed YAML manifest. Phase 2 M2.0 parses and
//! validates the manifest; the OCI fetching and signature
//! verification land in M2.1 alongside the wasmtime backend.

use serde::{Deserialize, Serialize};

use crate::capability::Capability;
use crate::error::PluginError;

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_SCHEMA_MAX: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub schema_version: u32,
    pub id: String,
    pub version: String,
    pub authored_by: String,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    pub budget: PluginBudget,
    pub declares: Vec<PluginRole>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginBudget {
    pub request_count_per_invocation: u32,
    pub wall_clock_seconds_per_invocation: u32,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PluginRole {
    HypothesisGenerator,
    ExperimentRunner,
    Primitive { primitive_id: String },
    Verifier { vuln_class: String },
}

/// Composite of a parsed manifest + the raw WASI module bytes. The
/// runtime stores these together so M2.1 can instantiate without
/// re-parsing.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub manifest: PluginManifest,
    pub module_bytes: Vec<u8>,
}

impl PluginManifest {
    pub fn from_yaml(s: &str) -> Result<Self, PluginError> {
        let parsed: Self = serde_yaml_ng::from_str(s)?;
        if parsed.schema_version > MANIFEST_SCHEMA_MAX {
            return Err(PluginError::UnsupportedSchema {
                got: parsed.schema_version,
                max: MANIFEST_SCHEMA_MAX,
            });
        }
        if parsed.id.is_empty() {
            return Err(PluginError::Manifest("id is empty".into()));
        }
        if parsed.version.is_empty() {
            return Err(PluginError::Manifest("version is empty".into()));
        }
        if parsed.declares.is_empty() {
            return Err(PluginError::Manifest(
                "plugin must declare at least one role".into(),
            ));
        }
        Ok(parsed)
    }

    pub fn to_yaml(&self) -> Result<String, PluginError> {
        serde_yaml_ng::to_string(self).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{LlmProvider, NetworkMethod};

    #[test]
    fn yaml_round_trip() {
        let m = PluginManifest {
            schema_version: 1,
            id: "demo".into(),
            version: "0.1.0".into(),
            authored_by: "alice".into(),
            capabilities: vec![Capability::NetworkHttp {
                methods: vec![NetworkMethod::Get, NetworkMethod::Post],
            }],
            budget: PluginBudget {
                request_count_per_invocation: 100,
                wall_clock_seconds_per_invocation: 30,
                memory_bytes: 64 * 1024 * 1024,
            },
            declares: vec![PluginRole::Primitive {
                primitive_id: "test.example".into(),
            }],
        };
        let yaml = m.to_yaml().unwrap();
        let back = PluginManifest::from_yaml(&yaml).unwrap();
        assert_eq!(back.id, "demo");
        assert_eq!(back.declares.len(), 1);
    }

    #[test]
    fn rejects_empty_id() {
        let yaml = r#"
schema_version: 1
id: ""
version: 0.1.0
authored_by: alice
budget:
  request_count_per_invocation: 100
  wall_clock_seconds_per_invocation: 30
  memory_bytes: 64000000
declares:
  - kind: hypothesis-generator
"#;
        assert!(PluginManifest::from_yaml(yaml).is_err());
    }

    #[test]
    fn rejects_missing_declares() {
        let yaml = r#"
schema_version: 1
id: demo
version: 0.1.0
authored_by: alice
budget:
  request_count_per_invocation: 100
  wall_clock_seconds_per_invocation: 30
  memory_bytes: 64000000
declares: []
"#;
        assert!(PluginManifest::from_yaml(yaml).is_err());
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let yaml = r#"
schema_version: 99
id: demo
version: 0.1.0
authored_by: alice
budget:
  request_count_per_invocation: 100
  wall_clock_seconds_per_invocation: 30
  memory_bytes: 64000000
declares:
  - kind: hypothesis-generator
"#;
        assert!(PluginManifest::from_yaml(yaml).is_err());
    }

    #[test]
    fn parses_llm_capability() {
        let m = PluginManifest {
            schema_version: 1,
            id: "synth".into(),
            version: "0.1.0".into(),
            authored_by: "alice".into(),
            capabilities: vec![Capability::LlmInvoke {
                providers: vec![LlmProvider::Anthropic],
                max_tokens_per_invocation: 10_000,
            }],
            budget: PluginBudget {
                request_count_per_invocation: 0,
                wall_clock_seconds_per_invocation: 60,
                memory_bytes: 128 * 1024 * 1024,
            },
            declares: vec![PluginRole::HypothesisGenerator],
        };
        let yaml = m.to_yaml().unwrap();
        let back = PluginManifest::from_yaml(&yaml).unwrap();
        match &back.capabilities[0] {
            Capability::LlmInvoke { providers, .. } => {
                assert_eq!(providers, &vec![LlmProvider::Anthropic]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
