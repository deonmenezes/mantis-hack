//! Capability typing.
//!
//! Plugins must declare every capability they need in their
//! manifest. The runtime grants exactly those capabilities and
//! refuses any syscall outside the declared set. This is the
//! contract that lets Mantis run untrusted-author plugins without
//! risking host compromise (PRD §6.4.1).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Capability {
    /// HTTP requests routed through the engagement's egress proxy.
    /// All scope and budget enforcement happens at the proxy; this
    /// capability only opens the door.
    NetworkHttp { methods: Vec<NetworkMethod> },
    /// Filesystem read access, scoped to declared paths.
    FsRead { paths: Vec<String> },
    /// Filesystem write access, scoped to declared paths.
    FsWrite { paths: Vec<String> },
    /// LLM invocation through the workspace's provider abstraction.
    LlmInvoke {
        providers: Vec<LlmProvider>,
        max_tokens_per_invocation: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NetworkMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmProvider {
    Anthropic,
    Openai,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAccess {
    Read,
    Write,
}

/// Workspace-level capability policy: which capabilities the
/// workspace permits its plugins to use. A plugin manifest may not
/// declare capabilities outside this set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub allow_network: bool,
    pub allow_fs_read_paths: Vec<String>,
    pub allow_fs_write_paths: Vec<String>,
    pub allow_llm_providers: Vec<LlmProvider>,
}

impl CapabilityGrant {
    pub fn permits(&self, capability: &Capability) -> bool {
        match capability {
            Capability::NetworkHttp { .. } => self.allow_network,
            Capability::FsRead { paths } => paths.iter().all(|p| {
                self.allow_fs_read_paths
                    .iter()
                    .any(|allowed| path_under(p, allowed))
            }),
            Capability::FsWrite { paths } => paths.iter().all(|p| {
                self.allow_fs_write_paths
                    .iter()
                    .any(|allowed| path_under(p, allowed))
            }),
            Capability::LlmInvoke { providers, .. } => providers
                .iter()
                .all(|p| self.allow_llm_providers.contains(p)),
        }
    }
}

fn path_under(requested: &str, allowed: &str) -> bool {
    // Simple prefix check. M2.1 will add proper path canonicalization.
    requested == allowed || requested.starts_with(&format!("{}/", allowed.trim_end_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_grant_refuses_network() {
        let grant = CapabilityGrant::default();
        let cap = Capability::NetworkHttp {
            methods: vec![NetworkMethod::Get],
        };
        assert!(!grant.permits(&cap));
    }

    #[test]
    fn network_grant_permits_any_method() {
        let grant = CapabilityGrant {
            allow_network: true,
            ..Default::default()
        };
        let cap = Capability::NetworkHttp {
            methods: vec![NetworkMethod::Get, NetworkMethod::Post],
        };
        assert!(grant.permits(&cap));
    }

    #[test]
    fn fs_read_requires_path_under_allowed() {
        let grant = CapabilityGrant {
            allow_fs_read_paths: vec!["/workspace/corpus".into()],
            ..Default::default()
        };
        assert!(grant.permits(&Capability::FsRead {
            paths: vec!["/workspace/corpus".into()],
        }));
        assert!(grant.permits(&Capability::FsRead {
            paths: vec!["/workspace/corpus/subdir".into()],
        }));
        assert!(!grant.permits(&Capability::FsRead {
            paths: vec!["/etc/passwd".into()],
        }));
        assert!(!grant.permits(&Capability::FsRead {
            paths: vec!["/workspace/other".into()],
        }));
    }

    #[test]
    fn llm_requires_specific_provider() {
        let grant = CapabilityGrant {
            allow_llm_providers: vec![LlmProvider::Anthropic],
            ..Default::default()
        };
        assert!(grant.permits(&Capability::LlmInvoke {
            providers: vec![LlmProvider::Anthropic],
            max_tokens_per_invocation: 1000,
        }));
        assert!(!grant.permits(&Capability::LlmInvoke {
            providers: vec![LlmProvider::Openai],
            max_tokens_per_invocation: 1000,
        }));
        // Mixed provider list is rejected if any provider isn't permitted.
        assert!(!grant.permits(&Capability::LlmInvoke {
            providers: vec![LlmProvider::Anthropic, LlmProvider::Openai],
            max_tokens_per_invocation: 1000,
        }));
    }

    #[test]
    fn path_prefix_is_label_aware() {
        assert!(path_under("/a/b", "/a"));
        assert!(path_under("/a/b", "/a/"));
        assert!(!path_under("/abc", "/a"), "label boundary must hold");
    }
}
