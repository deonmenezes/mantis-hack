//! Workspace layout, paths, and key management.
//!
//! Phase 0 milestone M0.1 lives here. The crate provides:
//!
//! - [`KeyStore`] abstraction with [`OsKeyStore`] (production, wraps the
//!   `keyring` crate) and [`InMemoryKeyStore`] (tests).
//! - [`Workspace::init`] / [`Workspace::open`] / [`Workspace::sign`] /
//!   [`Workspace::verify`].
//! - Operator identity management: [`Workspace::create_operator`],
//!   [`Workspace::list_operators`], [`Workspace::delete_operator`].
//! - [`DoctorReport`] for diagnostic checks.
//!
//! The workspace key signs all per-engagement artifacts: scope manifests
//! (M0.3), event-log tree heads (M0.2), and exported reports (M0.5+).
//! Signing uses a domain-separated prefix (`Mantis-v1:<context>:`) so
//! signatures cannot be replayed across contexts.

pub mod config;
pub mod doctor;
pub mod error;
pub mod key;
pub mod keystore;
pub mod operator;
pub mod workspace;

pub use camino::{Utf8Path, Utf8PathBuf};

pub use crate::config::{WorkspaceConfig, CONFIG_FILENAME, SCHEMA_VERSION};
pub use crate::doctor::{run as run_doctor, DoctorReport};
pub use crate::error::WorkspaceError;
pub use crate::key::{verify, Keypair, PublicKey, SIGN_DOMAIN_PREFIX};
pub use crate::keystore::{InMemoryKeyStore, KeyStore, KeyStoreError, OsKeyStore};
pub use crate::operator::{OperatorInfo, OperatorProfile};
pub use crate::workspace::{workspace_keystore_service, Workspace};

/// Resolve the workspace root: `MANTIS_HOME` env var if set, otherwise
/// `~/.mantis`. The directory is not created here; that happens inside
/// [`Workspace::init`].
#[must_use]
pub fn default_workspace_root() -> Utf8PathBuf {
    workspace_root_from_env(|k| std::env::var(k).ok())
}

fn workspace_root_from_env<F>(getenv: F) -> Utf8PathBuf
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(custom) = getenv("MANTIS_HOME") {
        return Utf8PathBuf::from(custom);
    }
    let home = getenv("HOME").unwrap_or_else(|| ".".to_owned());
    Utf8PathBuf::from(home).join(".mantis")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_takes_precedence() {
        let root = workspace_root_from_env(|k| match k {
            "MANTIS_HOME" => Some("/tmp/mantis-probe".to_owned()),
            _ => None,
        });
        assert_eq!(root.as_str(), "/tmp/mantis-probe");
    }

    #[test]
    fn falls_back_to_home_default() {
        let root = workspace_root_from_env(|k| match k {
            "HOME" => Some("/Users/test".to_owned()),
            _ => None,
        });
        assert_eq!(root.as_str(), "/Users/test/.mantis");
    }

    #[test]
    fn falls_back_to_current_dir_when_home_absent() {
        let root = workspace_root_from_env(|_| None);
        assert_eq!(root.as_str(), "./.mantis");
    }
}
