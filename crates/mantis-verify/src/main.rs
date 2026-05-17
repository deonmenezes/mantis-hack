//! `mantis-verify` — standalone inclusion-proof verifier.
//!
//! Takes a JSON inclusion proof plus a workspace public key (hex) and
//! prints `OK` or `FAIL: <reason>`. Has no Mantis-side dependencies
//! beyond serde, blake3, and ed25519-dalek so an external party can
//! audit the implementation in isolation.

use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const SIGN_DOMAIN_PREFIX: &[u8] = b"Mantis-v1:";
const TREE_HEAD_CONTEXT: &[u8] = b"tree";
const NODE_DOMAIN: &[u8] = b"\x01";

/// Verify a Mantis inclusion proof.
#[derive(Parser, Debug)]
#[command(name = "mantis-verify", version, about)]
struct Cli {
    /// Path to a JSON file containing the inclusion proof.
    #[arg(long)]
    proof: String,
    /// Workspace public key (32-byte hex).
    #[arg(long)]
    public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InclusionProof {
    engagement_id: String,
    leaf_index: u64,
    leaf_count: u64,
    #[serde(with = "hex_32")]
    leaf_hash: [u8; 32],
    path: Vec<HexHash>,
    signed_head: SignedTreeHead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedTreeHead {
    schema_version: u16,
    engagement_id: String,
    leaf_count: u64,
    #[serde(with = "hex_32")]
    root: [u8; 32],
    #[serde(with = "hex_64")]
    signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HexHash(#[serde(with = "hex_32")] [u8; 32]);

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("FAIL: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let proof_bytes = std::fs::read(&cli.proof).context("read proof file")?;
    let proof: InclusionProof = serde_json::from_slice(&proof_bytes).context("parse proof JSON")?;

    let pk_bytes_vec = hex::decode(cli.public_key.trim()).context("decode public key hex")?;
    if pk_bytes_vec.len() != 32 {
        bail!("public key must be 32 bytes, got {}", pk_bytes_vec.len());
    }
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&pk_bytes_vec);
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes).context("public key not on curve")?;

    verify_proof(&proof, &verifying_key)
}

fn verify_proof(proof: &InclusionProof, verifying_key: &VerifyingKey) -> Result<()> {
    if proof.signed_head.engagement_id != proof.engagement_id {
        bail!("engagement_id mismatch between proof and signed head");
    }
    if proof.signed_head.leaf_count != proof.leaf_count {
        bail!("leaf_count mismatch between proof and signed head");
    }
    if proof.leaf_index >= proof.leaf_count {
        bail!(
            "leaf_index {} out of range for leaf_count {}",
            proof.leaf_index,
            proof.leaf_count
        );
    }

    let head_canonical = canonical_signed_head(&proof.signed_head);
    let signed_bytes = domain_separate(TREE_HEAD_CONTEXT, &head_canonical);
    let signature = Signature::from_bytes(&proof.signed_head.signature);
    verifying_key
        .verify(&signed_bytes, &signature)
        .context("tree head signature does not verify against public key")?;

    let recomputed_root = recompute_root(
        proof.leaf_index,
        proof.leaf_count,
        proof.leaf_hash,
        &proof.path,
    );
    if recomputed_root != proof.signed_head.root {
        bail!("auth path does not reconstruct the signed root");
    }

    Ok(())
}

fn canonical_signed_head(head: &SignedTreeHead) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + head.engagement_id.len() + 8 + 32);
    buf.extend_from_slice(&head.schema_version.to_be_bytes());
    let eng_bytes = head.engagement_id.as_bytes();
    buf.extend_from_slice(&(eng_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(eng_bytes);
    buf.extend_from_slice(&head.leaf_count.to_be_bytes());
    buf.extend_from_slice(&head.root);
    buf
}

fn domain_separate(context: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SIGN_DOMAIN_PREFIX.len() + context.len() + 1 + payload.len());
    buf.extend_from_slice(SIGN_DOMAIN_PREFIX);
    buf.extend_from_slice(context);
    buf.push(b':');
    buf.extend_from_slice(payload);
    buf
}

fn recompute_root(
    leaf_index: u64,
    leaf_count: u64,
    leaf_hash: [u8; 32],
    path: &[HexHash],
) -> [u8; 32] {
    let mut hash = leaf_hash;
    let mut index = leaf_index;
    let mut level_size = leaf_count;
    let mut path_iter = path.iter();

    while level_size > 1 {
        let sibling_index = index ^ 1;
        if sibling_index < level_size {
            let sibling = path_iter.next().map(|h| h.0).unwrap_or_else(|| [0u8; 32]);
            hash = if index & 1 == 0 {
                node_hash(&hash, &sibling)
            } else {
                node_hash(&sibling, &hash)
            };
        }
        index /= 2;
        level_size = level_size.div_ceil(2);
    }
    hash
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

// LEAF_DOMAIN is the leading byte for Merkle leaf hashes — the producer
// already applies it inside the tree, so the verifier consumes the
// hashed leaf directly from the proof rather than recomputing it.

mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}
