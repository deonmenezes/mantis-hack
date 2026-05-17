//! Signed Merkle tree heads.
//!
//! A `SignedTreeHead` commits a `(workspace public key, engagement, leaf
//! count, root hash)` tuple. The canonical bytes fed to the signing
//! routine encode each field in fixed-width big-endian to avoid
//! ambiguity. The signer's domain context is `"tree"`.

use mantis_core::{EngagementId, Signer};
use serde::{Deserialize, Serialize};

pub const HEAD_SCHEMA_VERSION: u16 = 1;
pub const TREE_HEAD_CONTEXT: &str = "tree";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub schema_version: u16,
    pub engagement_id: String,
    pub leaf_count: u64,
    #[serde(with = "crate::hex32")]
    pub root: [u8; 32],
    #[serde(with = "crate::hex64")]
    pub signature: [u8; 64],
}

impl SignedTreeHead {
    pub fn create(
        signer: &dyn Signer,
        engagement_id: EngagementId,
        leaf_count: u64,
        root: [u8; 32],
    ) -> Self {
        let engagement_id_str = engagement_id.to_string();
        let canonical =
            canonical_head_bytes(HEAD_SCHEMA_VERSION, &engagement_id_str, leaf_count, &root);
        let signature = signer.sign(TREE_HEAD_CONTEXT, &canonical);
        Self {
            schema_version: HEAD_SCHEMA_VERSION,
            engagement_id: engagement_id_str,
            leaf_count,
            root,
            signature,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_head_bytes(
            self.schema_version,
            &self.engagement_id,
            self.leaf_count,
            &self.root,
        )
    }
}

pub(crate) fn canonical_head_bytes(
    schema_version: u16,
    engagement_id: &str,
    leaf_count: u64,
    root: &[u8; 32],
) -> Vec<u8> {
    let eng_bytes = engagement_id.as_bytes();
    let mut buf = Vec::with_capacity(2 + 4 + eng_bytes.len() + 8 + 32);
    buf.extend_from_slice(&schema_version.to_be_bytes());
    let len: u32 = eng_bytes
        .len()
        .try_into()
        .expect("engagement id fits in u32 bytes");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(eng_bytes);
    buf.extend_from_slice(&leaf_count.to_be_bytes());
    buf.extend_from_slice(root);
    buf
}
