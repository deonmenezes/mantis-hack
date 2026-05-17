//! Operator identities within a workspace.
//!
//! An operator has an Ed25519 keypair. The public half is written to
//! `operators/<id>/identity.pub` (hex). The secret half lives in the
//! keystore under service `mantis-operator-<id>`, account `signing-key`.
//! A profile JSON sits alongside the public key at
//! `operators/<id>/profile.json`.

use camino::Utf8Path;
use mantis_core::OperatorId;
use serde::{Deserialize, Serialize};
use tracing::info;
use ulid::Ulid;

use crate::config::now_unix;
use crate::error::WorkspaceError;
use crate::key::{Keypair, PublicKey};
use crate::keystore::KeyStore;

pub const PROFILE_FILENAME: &str = "profile.json";
pub const IDENTITY_PUB_FILENAME: &str = "identity.pub";
pub const PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorProfile {
    pub id: OperatorId,
    pub name: String,
    pub schema_version: u32,
    pub created_at_unix: u64,
    pub public_key: PublicKey,
}

impl OperatorProfile {
    pub fn new(name: String, public_key: PublicKey) -> Self {
        Self {
            id: OperatorId(Ulid::new()),
            name,
            schema_version: PROFILE_SCHEMA_VERSION,
            created_at_unix: now_unix(),
            public_key,
        }
    }

    pub fn fingerprint(&self) -> String {
        self.public_key.fingerprint()
    }
}

/// Display-friendly summary of an operator.
#[derive(Debug, Clone)]
pub struct OperatorInfo {
    pub id: OperatorId,
    pub name: String,
    pub fingerprint: String,
    pub created_at_unix: u64,
}

impl From<OperatorProfile> for OperatorInfo {
    fn from(p: OperatorProfile) -> Self {
        let fingerprint = p.fingerprint();
        Self {
            id: p.id,
            name: p.name,
            fingerprint,
            created_at_unix: p.created_at_unix,
        }
    }
}

pub fn operator_keystore_service(operator_id: OperatorId) -> String {
    format!("mantis-operator-{}", operator_id.0)
}

pub(crate) fn write_operator(
    operators_dir: &Utf8Path,
    profile: &OperatorProfile,
    keypair: &Keypair,
    keystore: &dyn KeyStore,
) -> Result<(), WorkspaceError> {
    let dir = operators_dir.join(profile.id.0.to_string());
    std::fs::create_dir_all(&dir)?;

    let profile_json = serde_json::to_string_pretty(profile)?;
    std::fs::write(dir.join(PROFILE_FILENAME), profile_json)?;

    let pubkey_hex = hex::encode(profile.public_key.as_bytes());
    std::fs::write(dir.join(IDENTITY_PUB_FILENAME), pubkey_hex)?;

    keystore.put(
        &operator_keystore_service(profile.id),
        "signing-key",
        keypair.secret_bytes().as_ref(),
    )?;

    info!(operator_id = %profile.id, name = %profile.name, "operator created");
    Ok(())
}

pub(crate) fn list_operators_in_dir(
    operators_dir: &Utf8Path,
) -> Result<Vec<OperatorProfile>, WorkspaceError> {
    if !operators_dir.exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for entry in std::fs::read_dir(operators_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let profile_path = path.join(PROFILE_FILENAME);
        if !profile_path.exists() {
            continue;
        }
        let s = std::fs::read_to_string(&profile_path)?;
        let profile: OperatorProfile = serde_json::from_str(&s)?;
        out.push(profile);
    }
    out.sort_by_key(|p| p.created_at_unix);
    Ok(out)
}
