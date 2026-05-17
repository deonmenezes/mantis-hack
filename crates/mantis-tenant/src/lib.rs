//! Multi-tenant namespace layer (Phase 5 M5.0).
//!
//! In single-tenant mode the daemon owns one workspace directory.
//! Multi-tenant deployments (per PRD §14.4 and §5.14) host
//! engagements for multiple clients on a single daemon. Each tenant
//! gets an isolated workspace path, distinct keychain service name
//! prefix, and a separate event-store column-family namespace.
//!
//! Phase 5 M5.0 ships the `Tenant` + `TenantStore` types plus the
//! path-derivation helpers. The daemon's `Engagement.Create` RPC
//! (Phase 5 M5.0b) will take a `tenant_id` argument; the daemon
//! routes the call through `TenantStore::resolve` to find the
//! correct backing workspace.

use std::collections::HashMap;
use std::sync::RwLock;

use camino::{Utf8Path, Utf8PathBuf};
use mantis_core::OperatorId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Error)]
pub enum TenantError {
    #[error("tenant {0} not found")]
    NotFound(String),

    #[error("tenant name {name:?} already in use")]
    NameTaken { name: String },

    #[error("internal lock poisoned")]
    Poisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub Ulid);

impl TenantId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: TenantId,
    pub name: String,
    pub owner_operator_id: OperatorId,
    pub created_at_unix: u64,
}

impl Tenant {
    /// Workspace path for this tenant inside the daemon root.
    pub fn workspace_path(&self, daemon_root: &Utf8Path) -> Utf8PathBuf {
        daemon_root.join("tenants").join(self.id.to_string())
    }

    /// Keychain service prefix for this tenant's secrets. Plugin
    /// secrets and per-engagement keys land under
    /// `mantis-tenant-<id>-...`.
    pub fn keychain_service_prefix(&self) -> String {
        format!("mantis-tenant-{}", self.id)
    }
}

#[derive(Debug, Default)]
pub struct TenantStore {
    inner: RwLock<HashMap<TenantId, Tenant>>,
}

impl TenantStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(
        &self,
        name: impl Into<String>,
        owner: OperatorId,
        now_unix: u64,
    ) -> Result<Tenant, TenantError> {
        let name = name.into();
        let mut guard = self.inner.write().map_err(|_| TenantError::Poisoned)?;
        if guard.values().any(|t| t.name == name) {
            return Err(TenantError::NameTaken { name });
        }
        let tenant = Tenant {
            id: TenantId::new(),
            name,
            owner_operator_id: owner,
            created_at_unix: now_unix,
        };
        guard.insert(tenant.id, tenant.clone());
        Ok(tenant)
    }

    pub fn get(&self, id: TenantId) -> Result<Option<Tenant>, TenantError> {
        let guard = self.inner.read().map_err(|_| TenantError::Poisoned)?;
        Ok(guard.get(&id).cloned())
    }

    pub fn list(&self) -> Result<Vec<Tenant>, TenantError> {
        let guard = self.inner.read().map_err(|_| TenantError::Poisoned)?;
        let mut tenants: Vec<_> = guard.values().cloned().collect();
        tenants.sort_by_key(|t| t.created_at_unix);
        Ok(tenants)
    }

    pub fn resolve_by_name(&self, name: &str) -> Result<Option<Tenant>, TenantError> {
        let guard = self.inner.read().map_err(|_| TenantError::Poisoned)?;
        Ok(guard.values().find(|t| t.name == name).cloned())
    }

    pub fn remove(&self, id: TenantId) -> Result<Tenant, TenantError> {
        self.inner
            .write()
            .map_err(|_| TenantError::Poisoned)?
            .remove(&id)
            .ok_or_else(|| TenantError::NotFound(id.to_string()))
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op_id() -> OperatorId {
        OperatorId(Ulid::new())
    }

    #[test]
    fn create_assigns_unique_id() {
        let store = TenantStore::new();
        let a = store.create("acme", op_id(), 0).unwrap();
        let b = store.create("globex", op_id(), 0).unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn duplicate_name_rejected() {
        let store = TenantStore::new();
        store.create("acme", op_id(), 0).unwrap();
        let err = store.create("acme", op_id(), 0).unwrap_err();
        assert!(matches!(err, TenantError::NameTaken { .. }));
    }

    #[test]
    fn resolve_by_name_finds_tenant() {
        let store = TenantStore::new();
        let created = store.create("acme", op_id(), 0).unwrap();
        let found = store.resolve_by_name("acme").unwrap().unwrap();
        assert_eq!(found.id, created.id);
        assert!(store.resolve_by_name("nope").unwrap().is_none());
    }

    #[test]
    fn workspace_path_isolates_tenants() {
        let store = TenantStore::new();
        let a = store.create("acme", op_id(), 0).unwrap();
        let b = store.create("globex", op_id(), 0).unwrap();
        let root = Utf8PathBuf::from("/var/lib/mantis");
        assert_ne!(a.workspace_path(&root), b.workspace_path(&root));
        assert!(a
            .workspace_path(&root)
            .starts_with("/var/lib/mantis/tenants/"));
    }

    #[test]
    fn keychain_prefix_uses_tenant_id() {
        let store = TenantStore::new();
        let t = store.create("acme", op_id(), 0).unwrap();
        let prefix = t.keychain_service_prefix();
        assert!(prefix.starts_with("mantis-tenant-"));
        assert!(prefix.contains(&t.id.to_string()));
    }

    #[test]
    fn list_sorted_by_created_at() {
        let store = TenantStore::new();
        store.create("late", op_id(), 1000).unwrap();
        store.create("early", op_id(), 100).unwrap();
        store.create("middle", op_id(), 500).unwrap();
        let list = store.list().unwrap();
        let names: Vec<_> = list.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["early", "middle", "late"]);
    }

    #[test]
    fn remove_uninstalls() {
        let store = TenantStore::new();
        let t = store.create("acme", op_id(), 0).unwrap();
        let removed = store.remove(t.id).unwrap();
        assert_eq!(removed.id, t.id);
        assert!(store.is_empty());
        assert!(store.get(t.id).unwrap().is_none());
    }

    #[test]
    fn remove_missing_errors() {
        let store = TenantStore::new();
        let err = store.remove(TenantId::new()).unwrap_err();
        assert!(matches!(err, TenantError::NotFound(_)));
    }
}
