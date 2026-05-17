//! Public plugin registry (Phase 5 M5.2).
//!
//! PRD §15 Phase 5 calls for a public plugin registry: an OCI-style
//! artifact registry where third-party plugin authors publish signed
//! plugins and operators pull them by ID.
//!
//! M5.2 ships the registry-side data model + verification primitives.
//! The actual HTTP/2 OCI client (push/pull/manifest fetch) lands in
//! M5.2b once the client uses the same types.

pub mod entry;
pub mod publisher;
pub mod search;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::entry::{Distribution, Entry, EntryId, EntryStatus, EntryVersion};
pub use crate::publisher::{PublisherKey, PublisherProfile};
pub use crate::search::{search, SearchQuery};

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("entry {0} not found")]
    NotFound(String),

    #[error("publisher {0} not trusted by this workspace")]
    UntrustedPublisher(String),

    #[error("signature verification failed for {0}")]
    SignatureInvalid(String),

    #[error("malformed manifest: {0}")]
    Manifest(String),

    #[error("internal lock poisoned")]
    Poisoned,
}

/// OCI-style artifact reference (registry.example.com/plugin:1.2.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub registry: String,
    pub plugin: String,
    pub tag: String,
}

impl ArtifactRef {
    pub fn parse(s: &str) -> Result<Self, RegistryError> {
        let (registry_and_plugin, tag) = s
            .split_once(':')
            .ok_or_else(|| RegistryError::Manifest(format!("missing :tag in artifact ref: {s}")))?;
        let (registry, plugin) = registry_and_plugin.split_once('/').ok_or_else(|| {
            RegistryError::Manifest(format!("missing /plugin in artifact ref: {s}"))
        })?;
        if registry.is_empty() || plugin.is_empty() || tag.is_empty() {
            return Err(RegistryError::Manifest(format!(
                "empty component in artifact ref: {s}"
            )));
        }
        Ok(Self {
            registry: registry.to_owned(),
            plugin: plugin.to_owned(),
            tag: tag.to_owned(),
        })
    }
}

impl std::fmt::Display for ArtifactRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}:{}", self.registry, self.plugin, self.tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trip() {
        let r = ArtifactRef::parse("registry.example.com/scanner:1.2.3").unwrap();
        assert_eq!(r.registry, "registry.example.com");
        assert_eq!(r.plugin, "scanner");
        assert_eq!(r.tag, "1.2.3");
        assert_eq!(r.to_string(), "registry.example.com/scanner:1.2.3");
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(ArtifactRef::parse("scanner:1.2.3").is_err()); // no /
        assert!(ArtifactRef::parse("registry/scanner").is_err()); // no :tag
        assert!(ArtifactRef::parse("/scanner:1").is_err()); // empty registry
        assert!(ArtifactRef::parse("registry/:1").is_err()); // empty plugin
        assert!(ArtifactRef::parse("registry/scanner:").is_err()); // empty tag
    }
}
