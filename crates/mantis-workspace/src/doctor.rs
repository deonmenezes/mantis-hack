//! Diagnostic report for `mantis doctor`.

use camino::Utf8Path;
use serde::{Deserialize, Serialize};

use crate::config::CONFIG_FILENAME;
use crate::error::WorkspaceError;
use crate::keystore::KeyStore;
use crate::workspace::Workspace;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub workspace_root: String,
    pub workspace_exists: bool,
    pub workspace_id: Option<String>,
    pub fingerprint: Option<String>,
    pub created_at_unix: Option<u64>,
    pub operator_count: usize,
    pub keystore_backend: String,
    pub keystore_available: bool,
    pub schema_version: Option<u32>,
}

impl DoctorReport {
    pub fn is_healthy(&self) -> bool {
        self.workspace_exists && self.keystore_available
    }
}

pub fn run(
    workspace_root: &Utf8Path,
    keystore: &dyn KeyStore,
) -> Result<DoctorReport, WorkspaceError> {
    let workspace_exists = workspace_root.join(CONFIG_FILENAME).exists();
    let keystore_available = keystore.is_available();
    let keystore_backend = keystore.backend_name().to_owned();

    if !workspace_exists {
        return Ok(DoctorReport {
            workspace_root: workspace_root.to_string(),
            workspace_exists: false,
            workspace_id: None,
            fingerprint: None,
            created_at_unix: None,
            operator_count: 0,
            keystore_backend,
            keystore_available,
            schema_version: None,
        });
    }

    let workspace = Workspace::open(workspace_root, keystore)?;
    let operators = workspace.list_operators()?;

    Ok(DoctorReport {
        workspace_root: workspace_root.to_string(),
        workspace_exists: true,
        workspace_id: Some(workspace.id().to_string()),
        fingerprint: Some(workspace.fingerprint()),
        created_at_unix: Some(workspace.config().created_at_unix),
        operator_count: operators.len(),
        keystore_backend,
        keystore_available,
        schema_version: Some(workspace.config().schema_version),
    })
}
