# ADR-0007: Merkle evidence chain and signed tree heads

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M0.2

## Context

PRD §6.5 requires every observation to be hashed into a per-engagement
Merkle tree, the tree head signed by the workspace key on every append,
and inclusion proofs verifiable by an external party using only the
report, the workspace public key, and a reference Merkle verifier. The
verifier must be standalone — no Mantis-side dependencies in its
build graph.

ADR-0002 already committed to: append-only event log, deterministic
replay, schema-versioned events, BLAKE3 as the hash function. This ADR
nails down the remaining choices needed for M0.2: tree shape,
domain-separation strategy, signed-head canonical bytes, and the
inclusion-proof on-wire format.

## Decision

### Tree shape

CT-style binary Merkle tree (RFC 9162):

- **Leaf hash:** `BLAKE3(0x00 || canonical_event_bytes)`.
- **Internal node hash:** `BLAKE3(0x01 || left || right)`.
- **Odd trailing node** at any level is promoted to the next level
  unchanged. Not duplicated (avoids the
  [CVE-2012-2459](https://nvd.nist.gov/vuln/detail/CVE-2012-2459)-class
  duplicate-leaf attack that affected Bitcoin's tree).

The leading domain-separator byte (`0x00` vs `0x01`) prevents a
second-preimage attack that substitutes an internal node for a leaf.

### Canonical event bytes

Event payloads use `serde_json` with a `#[serde(tag = "kind")]`
discriminator on `EventKind`. Field order on a struct is declaration
order; the discriminator tag ensures variant identity is explicit. No
`HashMap` appears anywhere in the event schema, so the encoding is
deterministic across Rust releases.

The leaf hash is computed over `serde_json::to_vec(&event)`, the same
bytes that are persisted to RocksDB. Tampering with the on-disk event
changes its leaf hash, which changes the Merkle root, which invalidates
the next signed tree head check.

### Signed tree head

Each append produces a fresh `SignedTreeHead`:

```rust
struct SignedTreeHead {
    schema_version: u16,
    engagement_id: String,    // ULID
    leaf_count: u64,
    root: [u8; 32],
    signature: [u8; 64],      // Ed25519 over canonical bytes
}
```

The signed payload is `Mantis-v1:tree:` + canonical bytes:

```text
schema_version_u16_be || engagement_id_length_u32_be || engagement_id_utf8
                     || leaf_count_u64_be || root_32_bytes
```

Fixed-width big-endian fields make the encoding canonical without
relying on serde to do anything clever. The length-prefixed engagement
ID accommodates future ID format changes without ambiguity.

Domain separation context is `tree` (per ADR-0006). The full sign input
is `"Mantis-v1:tree:" || canonical_bytes`. This prevents a tree-head
signature from being replayed as a scope-manifest signature even if the
canonical bytes happen to collide with a scope payload.

### Inclusion proof

```rust
struct InclusionProof {
    engagement_id: String,
    leaf_index: u64,
    leaf_count: u64,
    leaf_hash: [u8; 32],
    path: Vec<[u8; 32]>,       // bottom-up sibling hashes
    signed_head: SignedTreeHead,
}
```

The path skips levels where the current node is the odd trailing
element (no sibling exists). The verifier walks the path bottom-up,
selecting left/right combinator based on the parity of the index at
each level, and decrementing the level size by `ceil_div(level_size, 2)`
each step. The recomputed top hash must equal the signed head's root,
the signed head's signature must verify against the supplied public
key, and `leaf_index < leaf_count`.

### Storage layout

- RocksDB instance at `$workspace/events.rocksdb`.
- Column family `events`: key =
  `engagement_ulid (16 bytes) || seq (u64 big-endian)`; value =
  canonical event bytes.
- Column family `meta`: key =
  `engagement_ulid (16 bytes) || tag (1 byte)`.
  - tag `0x01` → serialized `SignedTreeHead`.
  - tag `0x02` → cached event count, u64 big-endian.

The cached event count is an optimization. It is rebuildable by
iterating the `events` CF and counting keys with the engagement
prefix; if the cached value disagrees with the on-disk count,
`read_leaves` returns `EventStoreError::Invariant` and refuses to
proceed.

Appends serialize per engagement via a process-wide mutex in Phase 0.
This is sufficient because engagements are single-threaded inside
their experiment loop. Phase 1 will replace the global lock with a
per-engagement lock.

### Standalone verifier

`mantis-verify` is a separate workspace crate with no dependency on
any other Mantis crate. Its full external dependency set is:
`anyhow`, `blake3`, `clap`, `ed25519-dalek`, `hex`, `serde`,
`serde_json`. The algorithm — domain-separated tree-head signing,
CT-style auth-path reconstruction, leaf-index bounds check — is
re-implemented from scratch rather than re-exported from
`mantis-event-store`. This ensures the verifier is an independent
audit target, not just a thin wrapper around producer code.

## Alternatives considered

1. **CBOR or bincode for canonical event encoding.** Both more compact
   than JSON. Rejected for Phase 0 because JSON is debuggable by eye
   and the size difference is small. Phase 1 may revisit if event
   throughput becomes the bottleneck — the schema version on every
   event makes the migration mechanical.

2. **Duplicate-the-odd-leaf at each level.** Bitcoin's approach.
   Rejected due to CVE-2012-2459 (duplicate trees produce the same
   root, breaking the injectivity guarantee). CT's promote-unchanged
   rule is the established fix.

3. **Sparse Merkle tree keyed by content hash.** More flexible (allows
   set membership rather than ordered list membership). Rejected
   because engagement events are inherently ordered; we want sequence
   numbers to be part of the proof.

4. **External signer.** Considered for hardware-backed signing of tree
   heads on high-value engagements. Deferred — the `Signer` trait in
   `mantis-core` accepts any implementation, so a future
   `HardwareSigner` is a drop-in.

5. **Cache intermediate node hashes** instead of recomputing the root
   from leaves on each append. Rejected for Phase 0 because the
   current implementation is O(N) per append and N is bounded by
   engagement event count — for the foreseeable future, well under
   the threshold where the constant factor matters. Phase 1 adds a
   streaming hash-cache.

## Consequences

- **+** Evidence chains are independently verifiable. The
  `mantis-verify` binary produces `OK` or `FAIL: <reason>` against any
  exported proof.
- **+** Tampering with on-disk events is detected on the next replay
  or inclusion-proof generation. Property tests (`leaf_hash` differs
  for every modified leaf) confirm this.
- **+** Per-engagement isolation: each engagement's tree is
  independent. An engagement's root tells you nothing about another's.
- **−** O(N) work per append (full leaf scan + Merkle root recompute).
  At 10k events per engagement, an append takes a few milliseconds.
  Phase 1 optimization moves this to O(log N) via incremental hashing.
- **−** The Merkle algorithm is reimplemented in two places
  (`mantis-event-store::merkle` and `mantis-verify`). They are
  cross-checked by tests, but a future change to one without the
  other is a property-test failure waiting to happen. ADR-0008 may
  formalize the cross-check.

## Verification

- 12 unit tests in `mantis-event-store::merkle` exercise empty/single/
  even/odd tree sizes, root tamper-detection, and inclusion-proof
  round-trips for every leaf index in trees of size 1..17.
- 11 integration tests in `mantis-event-store/tests/integration.rs`
  exercise the full append/replay/head/proof flow plus persistence
  across `EventStore::open` and per-engagement isolation.
- 3 of those integration tests shell out to the compiled
  `mantis-verify` binary:
  - `mantis_verify_binary_accepts_valid_proof` — confirms the
    standalone verifier accepts a proof produced by the event store.
  - `mantis_verify_binary_rejects_wrong_public_key` — confirms the
    signature check rejects substituted keys.
  - `mantis_verify_binary_rejects_tampered_proof` — confirms a
    flipped bit in the leaf hash defeats the Merkle reconstruction.
