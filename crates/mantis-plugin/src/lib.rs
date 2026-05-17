//! Plugin system foundations.
//!
//! Phase 2 M2.0 ships:
//! - Plugin manifest (YAML) per PRD §8.1.
//! - Capability typing for network, fs, and LLM access (PRD §8.2).
//! - Registry that loads + validates manifests; rejects ones whose
//!   declared capabilities exceed what the workspace policy allows.
//!
//! M2.1 adds the actual wasmtime component-model execution backend.
//! Until then the registry stores the manifest + module bytes but
//! does not run them.

pub mod capability;
pub mod error;
pub mod manifest;
pub mod registry;

pub use crate::capability::{Capability, CapabilityGrant, FsAccess, LlmProvider, NetworkMethod};
pub use crate::error::PluginError;
pub use crate::manifest::{Plugin, PluginBudget, PluginManifest, PluginRole};
pub use crate::registry::{LoadedPlugin, Registry};
