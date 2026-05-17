//! BLAKE3-based binary Merkle tree.
//!
//! CT-style (RFC 9162) construction:
//!
//! - Leaves are hashed as `BLAKE3(0x00 || payload)`.
//! - Internal nodes are hashed as `BLAKE3(0x01 || left || right)`.
//! - At each level, an odd trailing node is promoted to the next level
//!   unchanged (rather than duplicated).
//!
//! The leading domain-separator byte prevents second-preimage attacks
//! that swap an internal node for a leaf.

pub const LEAF_DOMAIN: &[u8] = b"\x00";
pub const NODE_DOMAIN: &[u8] = b"\x01";

/// Hash an opaque payload as a Merkle leaf.
#[must_use]
pub fn leaf_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Combine two child hashes into a parent.
#[must_use]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Compute the Merkle root of a slice of leaves.
///
/// Empty input returns all-zero (used as the sentinel root for an
/// engagement with no events yet).
#[must_use]
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(layer.len().div_ceil(2));
        let mut chunks = layer.chunks_exact(2);
        for pair in &mut chunks {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        if let Some(odd) = chunks.remainder().first() {
            next.push(*odd);
        }
        layer = next;
    }
    layer[0]
}

/// Build the inclusion path (sibling hashes, bottom-up) for `leaf_index`
/// in a tree of `leaves`. The returned path skips levels where the
/// current node is the odd trailing element (no sibling exists at that
/// level).
#[must_use]
pub fn inclusion_path(leaves: &[[u8; 32]], leaf_index: u64) -> Vec<[u8; 32]> {
    let mut path = vec![];
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    let mut index = leaf_index as usize;

    while layer.len() > 1 {
        let sibling = index ^ 1;
        if sibling < layer.len() {
            path.push(layer[sibling]);
        }
        // Compute the next layer.
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(layer.len().div_ceil(2));
        let mut chunks = layer.chunks_exact(2);
        for pair in &mut chunks {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        if let Some(odd) = chunks.remainder().first() {
            next.push(*odd);
        }
        layer = next;
        index /= 2;
    }
    path
}

/// Verify an inclusion path against a known root. The verifier walks
/// the path bottom-up, choosing left/right combinator based on the
/// parity of the current index at each level. Odd trailing nodes are
/// promoted without consuming a path element, matching the producer in
/// [`inclusion_path`].
#[must_use]
pub fn verify_inclusion(
    leaf_hash: [u8; 32],
    leaf_index: u64,
    leaf_count: u64,
    path: &[[u8; 32]],
    expected_root: [u8; 32],
) -> bool {
    if leaf_index >= leaf_count {
        return false;
    }
    let mut hash = leaf_hash;
    let mut index = leaf_index;
    let mut level_size = leaf_count;
    let mut path_iter = path.iter();

    while level_size > 1 {
        let sibling_index = index ^ 1;
        if sibling_index < level_size {
            let Some(sibling) = path_iter.next() else {
                return false;
            };
            hash = if index & 1 == 0 {
                node_hash(&hash, sibling)
            } else {
                node_hash(sibling, &hash)
            };
        }
        // else: current node is odd trailing — promote unchanged.
        index /= 2;
        level_size = level_size.div_ceil(2);
    }
    // Path must be fully consumed.
    if path_iter.next().is_some() {
        return false;
    }
    hash == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| leaf_hash(&[i as u8])).collect()
    }

    #[test]
    fn empty_root_is_zero() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_is_leaf() {
        let leaf = leaf_hash(b"a");
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn two_leaves_root_is_node_hash() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        assert_eq!(merkle_root(&[a, b]), node_hash(&a, &b));
    }

    #[test]
    fn root_changes_on_any_leaf_modification() {
        let l1 = make_leaves(8);
        let r1 = merkle_root(&l1);

        for i in 0..l1.len() {
            let mut l2 = l1.clone();
            l2[i] = leaf_hash(b"tampered");
            let r2 = merkle_root(&l2);
            assert_ne!(r1, r2, "modifying leaf {i} did not change root");
        }
    }

    #[test]
    fn inclusion_proof_round_trip_for_every_index() {
        for size in [1usize, 2, 3, 4, 5, 7, 8, 9, 16, 17] {
            let leaves = make_leaves(size);
            let root = merkle_root(&leaves);
            for i in 0..size {
                let path = inclusion_path(&leaves, i as u64);
                assert!(
                    verify_inclusion(leaves[i], i as u64, size as u64, &path, root),
                    "size {size} index {i} did not verify",
                );
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let leaves = make_leaves(8);
        let root = merkle_root(&leaves);
        let path = inclusion_path(&leaves, 3);
        let wrong_leaf = leaf_hash(b"not the real leaf");
        assert!(!verify_inclusion(wrong_leaf, 3, 8, &path, root));
    }

    #[test]
    fn inclusion_proof_rejects_wrong_index() {
        let leaves = make_leaves(8);
        let root = merkle_root(&leaves);
        let path = inclusion_path(&leaves, 3);
        assert!(!verify_inclusion(leaves[3], 5, 8, &path, root));
    }

    #[test]
    fn inclusion_proof_rejects_truncated_path() {
        let leaves = make_leaves(8);
        let root = merkle_root(&leaves);
        let mut path = inclusion_path(&leaves, 3);
        path.pop();
        assert!(!verify_inclusion(leaves[3], 3, 8, &path, root));
    }

    #[test]
    fn inclusion_proof_rejects_oversized_path() {
        let leaves = make_leaves(8);
        let root = merkle_root(&leaves);
        let mut path = inclusion_path(&leaves, 3);
        path.push([0xff; 32]);
        assert!(!verify_inclusion(leaves[3], 3, 8, &path, root));
    }
}
