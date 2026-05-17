//! [`Workspace`] is the unlocked, in-memory representation of a workspace
//! directory plus its workspace signing key.

use camino::{Utf8Path, Utf8PathBuf};
use ed25519_dalek::Signature;
use mantis_core::{OperatorId, WorkspaceId};
use tracing::info;

use crate::config::{WorkspaceConfig, CONFIG_FILENAME};
use crate::error::WorkspaceError;
use crate::key::{verify, Keypair, PublicKey};
use crate::keystore::KeyStore;
use crate::operator::{
    list_operators_in_dir, operator_keystore_service, write_operator, OperatorInfo, OperatorProfile,
};

pub const OPERATORS_DIRNAME: &str = "operators";
pub const ENGAGEMENTS_DIRNAME: &str = "engagements";
pub const PLAYBOOKS_DIRNAME: &str = "playbooks";
pub const PRIMITIVES_DIRNAME: &str = "primitives";
pub const TRAJECTORIES_DIRNAME: &str = "trajectories";

const KEYSTORE_ACCOUNT: &str = "signing-key";

pub struct Workspace {
    root: Utf8PathBuf,
    config: WorkspaceConfig,
    keypair: Keypair,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Workspace")
            .field("root", &self.root)
            .field("id", &self.config.id)
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Workspace {
    /// Create a fresh workspace at `root`. The directory is created if it
    /// does not exist. Returns an error if the workspace is already
    /// initialized.
    pub fn init(root: &Utf8Path, keystore: &dyn KeyStore) -> Result<Self, WorkspaceError> {
        if root.join(CONFIG_FILENAME).exists() {
            return Err(WorkspaceError::AlreadyInitialized {
                path: root.to_string(),
            });
        }

        std::fs::create_dir_all(root)?;
        for sub in [
            OPERATORS_DIRNAME,
            ENGAGEMENTS_DIRNAME,
            PLAYBOOKS_DIRNAME,
            PRIMITIVES_DIRNAME,
            TRAJECTORIES_DIRNAME,
        ] {
            std::fs::create_dir_all(root.join(sub))?;
        }

        let keypair = Keypair::generate();
        let config = WorkspaceConfig::new(keypair.public());

        std::fs::write(root.join(CONFIG_FILENAME), config.to_toml()?)?;
        keystore.put(
            &workspace_keystore_service(config.id),
            KEYSTORE_ACCOUNT,
            keypair.secret_bytes().as_ref(),
        )?;

        info!(workspace_id = %config.id, root = %root, "workspace initialized");
        Ok(Self {
            root: root.to_path_buf(),
            config,
            keypair,
        })
    }

    /// Open an existing workspace at `root`. Loads the config from disk
    /// and the secret signing key from the keystore. Verifies that the
    /// keystore secret matches the public key recorded in the config.
    pub fn open(root: &Utf8Path, keystore: &dyn KeyStore) -> Result<Self, WorkspaceError> {
        let config_path = root.join(CONFIG_FILENAME);
        if !config_path.exists() {
            return Err(WorkspaceError::NotFound {
                path: root.to_string(),
            });
        }

        let config_str = std::fs::read_to_string(&config_path)?;
        let config = WorkspaceConfig::from_toml(&config_str)?;

        let secret_bytes =
            keystore.get(&workspace_keystore_service(config.id), KEYSTORE_ACCOUNT)?;
        if secret_bytes.len() != 32 {
            return Err(WorkspaceError::MalformedKey);
        }
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&secret_bytes);
        let keypair = Keypair::from_secret_bytes(&secret_array);

        if keypair.public().as_bytes() != config.workspace_key.as_bytes() {
            return Err(WorkspaceError::KeyMismatch);
        }

        Ok(Self {
            root: root.to_path_buf(),
            config,
            keypair,
        })
    }

    pub fn root(&self) -> &Utf8Path {
        &self.root
    }

    pub fn id(&self) -> WorkspaceId {
        self.config.id
    }

    pub fn config(&self) -> &WorkspaceConfig {
        &self.config
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.config.workspace_key
    }

    pub fn fingerprint(&self) -> String {
        self.config.workspace_key.fingerprint()
    }

    pub fn sign(&self, context: &str, payload: &[u8]) -> Signature {
        self.keypair.sign(context, payload)
    }

    pub fn verify(&self, context: &str, payload: &[u8], sig: &Signature) -> bool {
        verify(self.public_key(), context, payload, sig)
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Create a new operator identity. The operator's secret key is
    /// stored in the keystore under `mantis-operator-<id>`.
    pub fn create_operator(
        &self,
        name: &str,
        keystore: &dyn KeyStore,
    ) -> Result<OperatorProfile, WorkspaceError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(WorkspaceError::OperatorNameEmpty);
        }
        let existing = list_operators_in_dir(&self.root.join(OPERATORS_DIRNAME))?;
        if existing.iter().any(|p| p.name == trimmed) {
            return Err(WorkspaceError::OperatorNameTaken {
                name: trimmed.to_owned(),
            });
        }
        let keypair = Keypair::generate();
        let profile = OperatorProfile::new(trimmed.to_owned(), keypair.public());
        write_operator(
            &self.root.join(OPERATORS_DIRNAME),
            &profile,
            &keypair,
            keystore,
        )?;
        Ok(profile)
    }

    pub fn list_operators(&self) -> Result<Vec<OperatorInfo>, WorkspaceError> {
        let profiles = list_operators_in_dir(&self.root.join(OPERATORS_DIRNAME))?;
        Ok(profiles.into_iter().map(OperatorInfo::from).collect())
    }

    /// Look up an operator's profile by ID.
    pub fn get_operator_profile(
        &self,
        operator_id: OperatorId,
    ) -> Result<OperatorProfile, WorkspaceError> {
        let profiles = list_operators_in_dir(&self.root.join(OPERATORS_DIRNAME))?;
        profiles
            .into_iter()
            .find(|p| p.id == operator_id)
            .ok_or_else(|| WorkspaceError::OperatorNotFound {
                id: operator_id.to_string(),
            })
    }

    /// Look up an operator's public key by ID. Used at engagement
    /// authorization time to verify the signed scope manifest.
    pub fn get_operator_public_key(
        &self,
        operator_id: OperatorId,
    ) -> Result<PublicKey, WorkspaceError> {
        self.get_operator_profile(operator_id).map(|p| p.public_key)
    }

    pub fn delete_operator(
        &self,
        operator_id: OperatorId,
        keystore: &dyn KeyStore,
    ) -> Result<(), WorkspaceError> {
        let dir = self
            .root
            .join(OPERATORS_DIRNAME)
            .join(operator_id.0.to_string());
        if !dir.exists() {
            return Err(WorkspaceError::OperatorNotFound {
                id: operator_id.to_string(),
            });
        }
        std::fs::remove_dir_all(&dir)?;
        // Best-effort keystore cleanup. If it fails (entry missing), that
        // is not a hard error — the filesystem state is the source of
        // truth for whether the operator exists.
        let _ = keystore.delete(&operator_keystore_service(operator_id), KEYSTORE_ACCOUNT);
        Ok(())
    }
}

pub fn workspace_keystore_service(workspace_id: WorkspaceId) -> String {
    format!("mantis-workspace-{}", workspace_id.0)
}
