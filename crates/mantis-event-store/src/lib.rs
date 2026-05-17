//! Append-only event log with a per-engagement Merkle evidence chain.
//!
//! Phase 0 milestone M0.2 delivers:
//!
//! - [`EventStore`] backed by RocksDB. One DB per workspace; two column
//!   families (`events`, `meta`); engagement-ID-prefixed keys.
//! - Per-engagement Merkle tree using BLAKE3 with CT-style construction.
//!   Domain-separated leaf and internal-node hashes.
//! - [`SignedTreeHead`] commits `(engagement, leaf_count, root)` and is
//!   signed via the [`mantis_core::Signer`] trait so the event store
//!   does not depend on the keychain crate directly.
//! - [`InclusionProof`] that an external party can verify with the
//!   `mantis-verify` binary using only the workspace public key and
//!   `blake3` + `ed25519-dalek`.
//!
//! The append-only invariant is enforced by the API surface: no
//! mutation or delete methods exist. Tampering with on-disk records is
//! caught by mismatched root hashes during the next replay or
//! inclusion-proof generation.

pub mod error;
pub mod event;
pub mod head;
pub mod merkle;
pub mod store;

pub use crate::error::EventStoreError;
pub use crate::event::{Event, EventKind, EVENT_SCHEMA_VERSION};
pub use crate::head::{SignedTreeHead, HEAD_SCHEMA_VERSION, TREE_HEAD_CONTEXT};
pub use crate::merkle::{
    inclusion_path, leaf_hash, merkle_root, node_hash, verify_inclusion, LEAF_DOMAIN, NODE_DOMAIN,
};
pub use crate::store::{EventStore, HexHash, InclusionProof};

pub(crate) mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

pub(crate) mod hex64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}
