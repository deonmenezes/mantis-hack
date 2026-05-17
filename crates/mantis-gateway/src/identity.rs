//! Operator ↔ platform-identity bindings.

use std::collections::HashMap;
use std::sync::RwLock;

use mantis_core::OperatorId;
use serde::{Deserialize, Serialize};

use crate::platform::PlatformId;
use crate::GatewayError;

/// Pairs a Mantis [`OperatorId`] with an identifier on a specific
/// messaging platform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityBinding {
    pub operator: OperatorId,
    pub platform: PlatformId,
    /// Platform-specific identifier (Telegram chat_id, Signal phone
    /// number hash, Slack user_id, etc.).
    pub remote_id: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Default)]
pub struct IdentityStore {
    inner: RwLock<HashMap<(OperatorId, PlatformId), IdentityBinding>>,
}

impl IdentityStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(&self, binding: IdentityBinding) -> Result<(), GatewayError> {
        self.inner
            .write()
            .map_err(|_| GatewayError::Poisoned)?
            .insert((binding.operator, binding.platform), binding);
        Ok(())
    }

    pub fn get(
        &self,
        operator: OperatorId,
        platform: PlatformId,
    ) -> Result<Option<IdentityBinding>, GatewayError> {
        let guard = self.inner.read().map_err(|_| GatewayError::Poisoned)?;
        Ok(guard.get(&(operator, platform)).cloned())
    }

    pub fn list_for_operator(
        &self,
        operator: OperatorId,
    ) -> Result<Vec<IdentityBinding>, GatewayError> {
        let guard = self.inner.read().map_err(|_| GatewayError::Poisoned)?;
        Ok(guard
            .values()
            .filter(|b| b.operator == operator)
            .cloned()
            .collect())
    }

    pub fn remove(&self, operator: OperatorId, platform: PlatformId) -> Result<(), GatewayError> {
        self.inner
            .write()
            .map_err(|_| GatewayError::Poisoned)?
            .remove(&(operator, platform))
            .ok_or_else(|| {
                GatewayError::IdentityNotFound(format!("{operator:?}/{}", platform.name()))
            })
            .map(|_| ())
    }
}
