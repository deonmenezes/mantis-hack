# ADR-0002: Event sourcing semantics and replay invariants

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M0.0 (decision); M0.2 (implementation)

## Context

PRD §6.3.1 mandates that all state changes are event-sourced and that
the daemon must reconstruct any past state by replay. PRD §6.5
additionally requires that the event log be tamper-evident: every
observation hashed into a per-engagement Merkle tree, the tree head
signed by the workspace key, and inclusion proofs verifiable by an
external party with only the public key and a reference verifier.

These two requirements interact: replay must be deterministic *and*
the persisted log must be append-only and integrity-checked. We need
to decide the semantics up front, before M0.2 lands the storage layer,
because the wrong choice here is expensive to undo later.

## Decision

### Append-only and replay

1. **Every state change is an `Event` appended to a per-engagement log.**
   Engagement state is never written directly; it is derived from the
   sequence of events.

2. **Events are immutable.** The storage layer (`mantis-event-store`,
   M0.2) enforces this. Reads return decoded events; there is no
   write-update path. Attempting to modify a historical event is a
   programming error.

3. **Replay is deterministic.** Given the same sequence of events, the
   derived state is bit-identical across processes and platforms. This
   means:
   - Event variants do not carry references to non-deterministic state
     (system time, randomness, network latency) unless that state is
     itself part of the event payload.
   - Floating-point fields are forbidden in events. If a real-valued
     quantity is needed, use a fixed-point representation with a
     documented scale.

4. **Event schema versioning.** Every event variant carries a
   `schema_version: u16`. Replay code is a `match` over `(variant,
   version)`. Adding a new field with a sensible default does not bump
   the version (it is non-breaking). Removing or changing the type of a
   field bumps the version; old code rejects events at the higher
   version, new code handles both.

5. **Time.** Events carry two timestamps: `wall_clock: SystemTime`
   (when the event was created on the writing host) and
   `monotonic_offset_ns: u64` (offset from the daemon's start instant).
   Replay reproduces `wall_clock` from the event payload. Replay does
   not depend on `monotonic_offset_ns` for correctness; it is for
   tracing and debugging only.

### Merkle evidence chain

6. **Every observation is hashed and entered into a per-engagement
   Merkle tree.** Hash function: BLAKE3. The tree is a binary Merkle
   tree with the standard balanced-tree layout; the implementation
   target is in M0.2.

7. **Tree head signing.** After every append (batched at small
   intervals for throughput), the tree root is signed by the workspace
   key (Ed25519) with a domain-separation prefix `"Mantis-v1:tree:"`
   prepended to the root bytes before signing. The signed head is
   persisted alongside the tree.

8. **Inclusion proofs.** A standard Merkle inclusion proof is a
   sequence of sibling hashes plus a leaf index. The exported proof
   bundle includes: the leaf hash, the proof path, the signed tree
   head, and the workspace public key. An external verifier needs only
   these and a reference Merkle verifier to confirm an observation was
   present in the engagement's evidence chain (PRD §6.5.5).

9. **Tamper detection.** Modifying any historical event invalidates
   every subsequent tree head signature. The event store does not need
   to prevent tampering; it only needs to make tampering immediately
   detectable. This is sufficient for the PRD's requirement.

### Crash recovery

10. **Atomic appends.** Each event-store append is a single atomic
    operation at the storage layer (a RocksDB write batch in M0.2's
    implementation). Either the event and its Merkle update both land,
    or neither does. There is no partial-append state to recover from.

11. **Restart replays from the last consistent log position.** On
    daemon start, each engagement's log is read in order until either
    EOF or the first record whose signed tree head fails to verify.
    Any records past the failure point are truncated and an alert is
    logged.

### What is *not* event-sourced

12. **In-memory caches** (decoded scope evaluators, live MCTS state in
    Phase 1, etc.) are derived from events on demand. They are not
    persisted. Persisting derived state would create a second source
    of truth and break replay.

13. **Plugin and primitive registries** are content-addressed by OCI
    digest. The registry index is event-sourced (the act of pulling a
    plugin is an event); the plugin bytes are not (they are
    content-addressed blobs on disk).

## Alternatives considered

- **State snapshots with a write-ahead log.** Common in databases.
  Faster startup, more complex code, harder to make replay deterministic.
  Rejected: PRD's replay requirement is the dominant constraint, and
  startup time at the scale we care about is already bounded by RocksDB
  open, not by replay.
- **Hash chain instead of Merkle tree.** Cheaper to build, but
  inclusion proofs require streaming the entire chain. Rejected:
  PRD §6.5.3 calls for inclusion proofs per cited observation.
- **External signing service.** Considered for high-value engagements.
  Deferred to a future ADR; the workspace-key-local model is sufficient
  for Phase 0.

## Consequences

- **+** Replay is a debugging superpower: any past state is reachable
  by replaying its event log.
- **+** Evidence chains are cryptographically verifiable by anyone with
  the workspace public key.
- **+** Forensic mode (PRD §12) is a natural consequence of append-only
  storage: open the event log read-only and replay.
- **−** Schema migrations are awkward. We can never delete or rename
  fields, only deprecate. Mitigation: keep event variants small and
  parsimonious; resist the temptation to put rich derived data in
  events.
- **−** Determinism rules out floating point in events. Mitigation:
  fixed-point representations for posteriors and rates; convert at the
  display boundary.

## Verification

- M0.2 acceptance criteria include: append→replay round-trip of 100k
  events, tampering detection via signed tree heads, inclusion proofs
  verified by an external `mantis-verify` binary.
- Property tests in `mantis-event-store/tests/` will assert: appended
  events are byte-identical on replay; any single-byte modification of
  a historical entry causes tree-head signature verification to fail;
  inclusion proofs verify against the signed head.
