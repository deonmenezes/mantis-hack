//! In-memory plugin registry. Validates manifests against the
//! workspace capability policy; refuses plugins whose declared
//! capabilities exceed the grant.

use std::collections::HashMap;

use crate::capability::CapabilityGrant;
use crate::error::PluginError;
use crate::manifest::{Plugin, PluginManifest};

#[derive(Debug, Clone)]
pub struct LoadedPlugin {
    pub plugin: Plugin,
}

#[derive(Debug, Default)]
pub struct Registry {
    plugins: HashMap<String, LoadedPlugin>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a plugin after validating that every declared
    /// capability is permitted by the grant.
    pub fn load(
        &mut self,
        manifest: PluginManifest,
        module_bytes: Vec<u8>,
        grant: &CapabilityGrant,
    ) -> Result<(), PluginError> {
        for capability in &manifest.capabilities {
            if !grant.permits(capability) {
                return Err(PluginError::CapabilityRefused {
                    plugin: manifest.id.clone(),
                    capability: format!("{capability:?}"),
                });
            }
        }
        if self.plugins.contains_key(&manifest.id) {
            return Err(PluginError::Duplicate {
                id: manifest.id.clone(),
            });
        }
        let plugin = Plugin {
            manifest,
            module_bytes,
        };
        self.plugins
            .insert(plugin.manifest.id.clone(), LoadedPlugin { plugin });
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&LoadedPlugin> {
        self.plugins.get(id)
    }

    pub fn remove(&mut self, id: &str) -> Result<LoadedPlugin, PluginError> {
        self.plugins
            .remove(id)
            .ok_or_else(|| PluginError::NotFound { id: id.into() })
    }

    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<_> = self.plugins.keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capability, LlmProvider, NetworkMethod};
    use crate::manifest::{PluginBudget, PluginRole};

    fn sample_manifest(id: &str, caps: Vec<Capability>) -> PluginManifest {
        PluginManifest {
            schema_version: 1,
            id: id.into(),
            version: "0.1.0".into(),
            authored_by: "alice".into(),
            capabilities: caps,
            budget: PluginBudget {
                request_count_per_invocation: 10,
                wall_clock_seconds_per_invocation: 10,
                memory_bytes: 64 * 1024 * 1024,
            },
            declares: vec![PluginRole::HypothesisGenerator],
        }
    }

    #[test]
    fn loads_plugin_when_capabilities_granted() {
        let mut r = Registry::new();
        let m = sample_manifest(
            "a",
            vec![Capability::NetworkHttp {
                methods: vec![NetworkMethod::Get],
            }],
        );
        let grant = CapabilityGrant {
            allow_network: true,
            ..Default::default()
        };
        r.load(m, vec![0u8; 16], &grant).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r.get("a").is_some());
    }

    #[test]
    fn refuses_plugin_with_ungranted_capability() {
        let mut r = Registry::new();
        let m = sample_manifest(
            "a",
            vec![Capability::NetworkHttp {
                methods: vec![NetworkMethod::Get],
            }],
        );
        // Empty grant → network refused.
        let grant = CapabilityGrant::default();
        let err = r.load(m, vec![0u8; 16], &grant).unwrap_err();
        assert!(matches!(err, PluginError::CapabilityRefused { .. }));
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut r = Registry::new();
        let grant = CapabilityGrant::default();
        let m1 = sample_manifest("dup", vec![]);
        let m2 = sample_manifest("dup", vec![]);
        r.load(m1, vec![], &grant).unwrap();
        let err = r.load(m2, vec![], &grant).unwrap_err();
        assert!(matches!(err, PluginError::Duplicate { .. }));
    }

    #[test]
    fn remove_unloads() {
        let mut r = Registry::new();
        let grant = CapabilityGrant::default();
        r.load(sample_manifest("x", vec![]), vec![], &grant)
            .unwrap();
        let removed = r.remove("x").unwrap();
        assert_eq!(removed.plugin.manifest.id, "x");
        assert!(r.get("x").is_none());
    }

    #[test]
    fn ids_returns_sorted() {
        let mut r = Registry::new();
        let grant = CapabilityGrant::default();
        for id in ["zebra", "apple", "mango"] {
            r.load(sample_manifest(id, vec![]), vec![], &grant).unwrap();
        }
        assert_eq!(r.ids(), vec!["apple", "mango", "zebra"]);
    }

    #[test]
    fn llm_plugin_requires_provider_grant() {
        let mut r = Registry::new();
        let m = sample_manifest(
            "synth",
            vec![Capability::LlmInvoke {
                providers: vec![LlmProvider::Anthropic],
                max_tokens_per_invocation: 1000,
            }],
        );
        let grant_no_llm = CapabilityGrant::default();
        assert!(r.load(m.clone(), vec![], &grant_no_llm).is_err());

        let grant_with_llm = CapabilityGrant {
            allow_llm_providers: vec![LlmProvider::Anthropic],
            ..Default::default()
        };
        assert!(r.load(m, vec![], &grant_with_llm).is_ok());
    }
}
