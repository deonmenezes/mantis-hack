# ADR-0012: Claim verification model

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M1.1

## Context

PRD §5.6 requires every hypothesis whose posterior crosses the
confidence threshold to be promoted to a Claim and then **verified
independently**. The verifier must:

- Run in a fresh actor with no shared state with the primitive
  (§5.6.2).
- Receive only the reproducer + metadata, not the original
  observation trail (§5.6.3).
- Cause failed claims to be retained-for-debug and excluded from
  reports (§5.6.5).
- Record every verification result, including failure traces,
  immutably in the event log (§5.6.6).

This ADR pins the verifier model for Phase 1.

## Decision

### Claim type

```rust
struct Claim {
    primitive_id: String,
    vuln_class: String,
    surface: SurfaceSnapshot,
    evidence: Vec<EvidenceItem>,
    reproducer: Reproducer,
    state: ClaimState,
}

enum ClaimState {
    Pending,
    Verified { verifier_id: String },
    Rejected { reason: String },
    Retained { reason: String },
}
```

`SurfaceSnapshot` is a deterministically-serializable cut-down of
`Surface`. Carrying it on the claim lets the verifier reproduce the
request without needing access to the original
`mantis-scanner-http::Surface` (which holds reqwest-internal state).

### State machine

- New claim starts in `Pending`.
- Verifier writes one of `Verified`, `Rejected`, or `Retained`.
- Only `Verified` claims are emitted in reports (PRD §5.6.5).
- `Rejected` and `Retained` claims stay in the event log for
  post-mortem and as learning signal for the Bayesian update
  layer (M1.4).

### Verifier trait

```rust
#[async_trait]
trait Verifier: Send + Sync {
    fn id(&self) -> &'static str;
    fn vuln_class(&self) -> &'static str;
    async fn verify(&self, claim: &Claim, client: &Client) -> Result<ClaimState, ClaimError>;
}
```

Per-vuln-class implementations. M1.1 ships
`MissingSecurityHeadersVerifier`. Each new primitive (M1.2+) lands
with its matching verifier.

### Dispatch

```rust
async fn verify_claim(claim: &Claim, client: &Client) -> Result<ClaimState, ClaimError>;
```

Selects a verifier from a hardcoded catalog keyed on
`claim.vuln_class`. Unknown classes return `ClaimError::NoVerifier`.

### Independence

The verifier:

- Receives only the [`Claim`] — no reference to the primitive
  that produced it, no access to the original response body.
- Constructs its own request using `claim.surface` data.
- Compares against `claim.evidence` only by item-kind and detail,
  not by trusting the primitive's interpretation.

This is the property that catches a buggy primitive: if the
primitive's `Confirmed` rests on a misread response, the
verifier's independent re-read produces a `Rejected` state and
the claim never reaches a report.

### Retained vs Rejected

Two distinct failure modes:

- **Rejected** — the verifier ran cleanly and concluded the
  evidence is gone (e.g. a header that was missing is now
  present). This is a *learning signal* — the primitive was
  wrong, or the target changed between primitive and verifier in
  a way that invalidates the claim.
- **Retained** — the verifier hit a non-deterministic error
  (timeout, 5xx, connection refused). The claim is kept for
  human review but not auto-reported.

The distinction matters because Phase 2's Bayesian update layer
will treat Rejected as "primitive miss" but exclude Retained from
the success/failure ratio.

## Alternatives considered

1. **Reuse the primitive code** as the verifier. Much simpler
   but defeats the independence requirement. Rejected.
2. **Shell out to `curl` to run the reproducer**. Maximally
   independent (different binary, different TLS stack, different
   parser). Considered for Phase 2; deferred for Phase 1 because
   `reqwest` already produces deterministic-enough behavior and
   avoids the subprocess management cost.
3. **Run the verifier in a microVM**. PRD §6.4.2 mentions this
   for live verification. Phase 1 keeps verifier in-process;
   sandboxing lands in Phase 2 with the WASM plugin runtime.
4. **Embed the verifier inside the [`Primitive`] trait**.
   Couples the two concerns. Rejected.

## Consequences

- **+** Adding a new primitive forces adding a verifier — they
  ship together. The catalog dispatch fails loudly if a verifier
  is missing.
- **+** Claims carry their full audit trail (primitive_id,
  evidence, reproducer, verifier outcome) in one
  serialize-able struct.
- **+** Bayesian learning has a clean signal: count
  `Confirmed+Verified` vs `Confirmed+Rejected` per
  (stack, vuln_class).
- **−** The dispatch catalog is hardcoded today. Phase 2's plugin
  registry will replace it with dynamic loading.
- **−** No event-log integration yet. The daemon's
  `Engagement.RunPrimitive` RPC (M1.2) will be the first caller
  to record `ClaimVerified` / `ClaimRejected` events.

## Verification

5 integration tests in `mantis-claim` cover:

- Verifier confirms claim when headers are still missing
  (Verified).
- Verifier rejects claim when a previously-missing header is now
  present (Rejected).
- Partial header presence still rejects (Rejected — any-present
  means reject).
- Network error to bad address produces Retained.
- Unknown `vuln_class` returns `ClaimError::NoVerifier`.
