//! Engagement hibernation (Phase 4 M4.1).
//!
//! Serializes per-engagement runtime state to a single JSON blob on
//! disk so the daemon can terminate the engagement's worker, free
//! its in-memory resources, and reconstitute the engagement later
//! from the snapshot.
//!
//! Phase 4 M4.1 ships the snapshot/restore primitives and the
//! local-disk backend. Cloud backends (Modal, Daytona, Vercel
//! Sandbox) land in M4.1b/c/d alongside their respective adapters.

use std::path::Path;

use camino::Utf8Path;
use mantis_core::EngagementId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HibernationError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("snapshot for {0} not found")]
    NotFound(String),

    #[error("snapshot version {got} not supported (max {max})")]
    UnsupportedVersion { got: u32, max: u32 },
}

pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
pub const SNAPSHOT_SCHEMA_MAX: u32 = 1;

/// Snapshot of an engagement's runtime state. The runtime types are
/// stored as opaque JSON blobs so this crate doesn't have to depend
/// on every runtime crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_version: u32,
    pub engagement_id: EngagementId,
    pub captured_at_unix: u64,
    /// Last event seq number persisted to the event store before
    /// hibernation. On restore, the daemon replays events from this
    /// seq forward to ensure the in-memory state matches disk.
    pub last_event_seq: u64,
    /// Engagement state (Draft/Authorized/Active/Paused/Completed/Archived).
    pub state: String,
    /// Per-component opaque JSON payloads. Each component
    /// (planner, posteriors, operator_model, etc.) serializes
    /// itself into this map.
    pub components: serde_json::Map<String, serde_json::Value>,
}

impl Snapshot {
    pub fn new(engagement_id: EngagementId, state: impl Into<String>) -> Self {
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            engagement_id,
            captured_at_unix: 0,
            last_event_seq: 0,
            state: state.into(),
            components: serde_json::Map::new(),
        }
    }

    /// Add a component payload to the snapshot. Returns self for
    /// chaining.
    pub fn with_component<S: Serialize>(
        mut self,
        key: &str,
        value: &S,
    ) -> Result<Self, HibernationError> {
        let v = serde_json::to_value(value)?;
        self.components.insert(key.to_owned(), v);
        Ok(self)
    }

    /// Extract a component payload by key.
    pub fn component<D: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<D>, HibernationError> {
        match self.components.get(key) {
            Some(v) => {
                let parsed: D = serde_json::from_value(v.clone())?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }
}

pub trait HibernationBackend: Send + Sync {
    fn store(&self, snapshot: &Snapshot) -> Result<(), HibernationError>;
    fn load(&self, engagement_id: EngagementId) -> Result<Snapshot, HibernationError>;
    fn delete(&self, engagement_id: EngagementId) -> Result<(), HibernationError>;
    fn list(&self) -> Result<Vec<EngagementId>, HibernationError>;
}

/// Local-disk hibernation backend. Snapshots land at
/// `<root>/<engagement_id>.json`.
#[derive(Debug)]
pub struct LocalDiskBackend {
    root: camino::Utf8PathBuf,
}

impl LocalDiskBackend {
    pub fn new(root: impl AsRef<Utf8Path>) -> Result<Self, HibernationError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(Path::new(root.as_str()))?;
        Ok(Self { root })
    }

    fn path_for(&self, id: EngagementId) -> camino::Utf8PathBuf {
        self.root.join(format!("{id}.json"))
    }
}

impl HibernationBackend for LocalDiskBackend {
    fn store(&self, snapshot: &Snapshot) -> Result<(), HibernationError> {
        let path = self.path_for(snapshot.engagement_id);
        let bytes = serde_json::to_vec_pretty(snapshot)?;
        std::fs::write(path.as_str(), bytes)?;
        Ok(())
    }

    fn load(&self, engagement_id: EngagementId) -> Result<Snapshot, HibernationError> {
        let path = self.path_for(engagement_id);
        if !path.exists() {
            return Err(HibernationError::NotFound(engagement_id.to_string()));
        }
        let bytes = std::fs::read(path.as_str())?;
        let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
        if snapshot.schema_version > SNAPSHOT_SCHEMA_MAX {
            return Err(HibernationError::UnsupportedVersion {
                got: snapshot.schema_version,
                max: SNAPSHOT_SCHEMA_MAX,
            });
        }
        Ok(snapshot)
    }

    fn delete(&self, engagement_id: EngagementId) -> Result<(), HibernationError> {
        let path = self.path_for(engagement_id);
        if !path.exists() {
            return Err(HibernationError::NotFound(engagement_id.to_string()));
        }
        std::fs::remove_file(path.as_str())?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<EngagementId>, HibernationError> {
        let mut ids = vec![];
        for entry in std::fs::read_dir(self.root.as_str())? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if let Ok(ulid) = stem.parse::<ulid::Ulid>() {
                ids.push(EngagementId(ulid));
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn eng_id() -> EngagementId {
        EngagementId(Ulid::new())
    }

    #[test]
    fn snapshot_round_trips_with_component() {
        let id = eng_id();
        let payload = serde_json::json!({"alpha": 1, "beta": 2});
        let snap = Snapshot::new(id, "Paused")
            .with_component("posteriors", &payload)
            .unwrap();
        let extracted: serde_json::Value = snap.component("posteriors").unwrap().unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn store_then_load_returns_same_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let backend = LocalDiskBackend::new(&root).unwrap();
        let id = eng_id();
        let snap = Snapshot::new(id, "Paused");
        backend.store(&snap).unwrap();
        let restored = backend.load(id).unwrap();
        assert_eq!(restored.engagement_id, id);
        assert_eq!(restored.state, "Paused");
    }

    #[test]
    fn load_missing_returns_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let backend = LocalDiskBackend::new(&root).unwrap();
        let err = backend.load(eng_id()).unwrap_err();
        assert!(matches!(err, HibernationError::NotFound(_)));
    }

    #[test]
    fn list_finds_stored_snapshots() {
        let tmp = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let backend = LocalDiskBackend::new(&root).unwrap();
        let a = eng_id();
        let b = eng_id();
        backend.store(&Snapshot::new(a, "Paused")).unwrap();
        backend.store(&Snapshot::new(b, "Paused")).unwrap();
        let ids = backend.list().unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&a));
        assert!(ids.contains(&b));
    }

    #[test]
    fn delete_removes_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let backend = LocalDiskBackend::new(&root).unwrap();
        let id = eng_id();
        backend.store(&Snapshot::new(id, "Paused")).unwrap();
        backend.delete(id).unwrap();
        assert!(backend.load(id).is_err());
    }

    #[test]
    fn rejects_future_schema_version() {
        let tmp = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let backend = LocalDiskBackend::new(&root).unwrap();
        let id = eng_id();
        let mut snap = Snapshot::new(id, "Paused");
        snap.schema_version = SNAPSHOT_SCHEMA_MAX + 1;
        backend.store(&snap).unwrap();
        let err = backend.load(id).unwrap_err();
        assert!(matches!(err, HibernationError::UnsupportedVersion { .. }));
    }
}
