# ADR-0011: Primitive trait and Phase 1 entry

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M1.0

## Context

Phase 0 closed with the scanner discovering surfaces and the
hypothesis catalog proposing falsifiable statements about each
surface. Phase 1's central new capability is going from
"hypothesis" to "claim": running a targeted check that produces a
verdict plus a reproducer the operator can hand to a disclosure
program (PRD §5.6 / §5.7).

This ADR pins the [`Primitive`] trait that every check implements,
the verdict types, and the first concrete primitive
(`MissingSecurityHeaders`).

## Decision

### Primitive trait

```rust
#[async_trait]
pub trait Primitive: Send + Sync {
    fn id(&self) -> &'static str;
    fn vuln_class(&self) -> &'static str;
    fn matches_surface(&self, surface: &Surface) -> bool;
    async fn execute(
        &self,
        surface: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError>;
}
```

- `id` — globally unique identifier of the form
  `vuln_class.specific-name` (e.g.
  `info-disclosure.missing-security-headers`).
- `vuln_class` — broad bucket (e.g. `info-disclosure`, `xss`,
  `idor`, `sqli`). Used for grouping in reports.
- `matches_surface` — cheap pre-check (no I/O) the planner uses to
  filter primitives before scheduling them.
- `execute` — runs the check against the surface and returns the
  verdict. Takes a pre-configured `reqwest::Client` so the caller
  controls proxying.

### Verdict type

```rust
enum PrimitiveResult {
    Confirmed {
        evidence: Vec<EvidenceItem>,
        reproducer: Reproducer,
    },
    Denied { reason: String },
    Inconclusive { reason: String },
}
```

- `Confirmed` means the check is satisfied. The verifier in M1.1
  re-runs the reproducer in an isolated sandbox; only verifier-
  confirmed claims become reportable findings (PRD §5.6.2).
- `Denied` is an explicit refutation, useful as a learning signal
  for the Bayesian update layer (PRD §5.4.2).
- `Inconclusive` is for cases the primitive can't decide
  (network failure, unexpected response shape). The planner may
  retry with different parameters.

### Reproducer dialects

Phase 1 ships two:

- `curl` — one-liner that demonstrates the issue.
- `raw_http` — Burp/Caido-pasteable raw HTTP/1.1 request.

`python` is an Option that lands in M1.1. Rust, Burp session
files, and shell scripts follow (PRD §5.7.10).

### First primitive: `MissingSecurityHeaders`

Detects absence of:

- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options` (XFO)
- `X-Content-Type-Options` (XCTO)

Pre-check: surface has status 2xx or 3xx (errors and redirects are
exempt). On Confirmed, evidence is one `missing-header` item per
absent header.

Chosen as the first primitive because:

- High signal — almost every disclosure program accepts these
  findings as low-severity.
- No need for payload mutation or response analysis — pure header
  presence/absence.
- Demonstrates the full Primitive → Reproducer flow without the
  ethical complexity of real exploitation.

## Alternatives considered

1. **Open redirect** as first primitive. More dramatic
   demonstration but requires payload mutation logic (the
   `?next=` parameter, the various redirect URL forms) that's
   better introduced once two primitives prove the trait shape.
   Deferred to M1.1.
2. **Make Primitive synchronous.** Simpler trait, but every real
   primitive does I/O. Rejected for honesty: async-trait adds
   tiny overhead and `reqwest` is async anyway.
3. **Bundle the reproducer inside `EvidenceItem`.** Considered
   for compactness. Rejected because the reproducer is a
   first-class object: reports embed it verbatim, verifiers
   re-run it, exports include all dialects. It belongs at the
   top level of the result.

## Consequences

- **+** Adding a new primitive is one file. Tests live with the
  primitive. The catalog is just a list.
- **+** The verifier (M1.1) takes the existing reproducer and
  re-runs it; no new types required.
- **+** Static dispatch on `&dyn Primitive` keeps the catalog
  lookup tiny (vtable per primitive).
- **−** Primitives that need state (e.g. credential-stuffing with
  a wordlist) don't fit neatly. The trait stays pure for Phase 1;
  stateful primitives may need a sibling `StatefulPrimitive`
  trait in Phase 2.
- **−** No type-unified preconditions yet (PRD §5.7.2). Phase 1
  primitives carry their own `matches_surface`; type unification
  comes once the catalog is large enough to warrant it.

## Verification

- 5 integration tests in `mantis-primitive` cover:
  - all four headers missing → Confirmed
  - all four present → Denied
  - subset missing → Confirmed with correct evidence subset
  - `matches_surface` filters correctly (2xx/3xx vs 4xx/5xx)
  - `id` and `vuln_class` match expectations

## Phase 1 entry status

With this ADR accepted:

- Phase 1 M1.0 milestone is complete (Primitive trait + first
  primitive).
- M1.1 — verifier that re-runs reproducers independently.
- M1.2 — three more primitives (open-redirect, missing-cors-on-credentialed,
  basic-clickjacking).
- M1.3 — MCTS planner using the existing static priors.
- M1.4 — Bayesian update layer over the priors.
- M1.5 — Markdown reports with Merkle proofs.
