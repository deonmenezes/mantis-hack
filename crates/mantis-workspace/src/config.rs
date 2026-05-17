//! Workspace-level configuration persisted as TOML.

use std::time::{SystemTime, UNIX_EPOCH};

use mantis_core::WorkspaceId;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::error::WorkspaceError;
use crate::key::PublicKey;

pub const CONFIG_FILENAME: &str = "workspace.config.toml";
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    pub id: WorkspaceId,
    pub schema_version: u32,
    pub created_at_unix: u64,
    pub workspace_key: PublicKey,
}

impl WorkspaceConfig {
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            id: WorkspaceId(Ulid::new()),
            schema_version: SCHEMA_VERSION,
            created_at_unix: now_unix(),
            workspace_key: public_key,
        }
    }

    pub fn to_toml(&self) -> Result<String, WorkspaceError> {
        toml::to_string_pretty(self).map_err(Into::into)
    }

    pub fn from_toml(s: &str) -> Result<Self, WorkspaceError> {
        toml::from_str(s).map_err(Into::into)
    }
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Keypair;

    #[test]
    fn config_toml_round_trip() {
        let kp = Keypair::generate();
        let config = WorkspaceConfig::new(kp.public());
        let toml_str = config.to_toml().unwrap();
        let back = WorkspaceConfig::from_toml(&toml_str).unwrap();
        assert_eq!(config.id, back.id);
        assert_eq!(config.schema_version, back.schema_version);
        assert_eq!(
            config.workspace_key.as_bytes(),
            back.workspace_key.as_bytes()
        );
    }

    #[test]
    fn config_carries_current_schema_version() {
        let kp = Keypair::generate();
        let config = WorkspaceConfig::new(kp.public());
        assert_eq!(config.schema_version, SCHEMA_VERSION);
    }
}
