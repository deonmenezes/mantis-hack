# Mantis internal docs

This directory holds documents that govern how Mantis is built, not
documents that describe Mantis to the outside world. User-facing
documentation lives elsewhere (TBD).

## Architectural Decision Records

ADRs capture decisions and the reasoning behind them. Each ADR is dated
and immutable once accepted; supersession is recorded as a new ADR that
references the old one.

| ID | Status | Title |
|---|---|---|
| [ADR-0001](./adr-0001-workspace-structure.md) | Accepted | Cargo workspace structure and crate boundaries |
| [ADR-0002](./adr-0002-event-sourcing-semantics.md) | Accepted | Event sourcing semantics and replay invariants |
| [ADR-0003](./adr-0003-scope-dsl-grammar.md) | Accepted | Scope DSL grammar |
| [ADR-0004](./adr-0004-egress-proxy-threat-model.md) | Accepted | Egress proxy threat model |
| [ADR-0005](./adr-0005-grpc-api-versioning.md) | Accepted | gRPC API versioning policy |
| [ADR-0006](./adr-0006-workspace-key-management.md) | Accepted | Workspace key management |
| [ADR-0007](./adr-0007-merkle-evidence-chain.md) | Accepted | Merkle evidence chain and signed tree heads |
| [ADR-0008](./adr-0008-scanner-hypothesis-pipeline.md) | Accepted | Scanner + hypothesis pipeline |
| [ADR-0009](./adr-0009-engagement-runtime.md) | Accepted | Engagement runtime + scanner integration |
| [ADR-0010](./adr-0010-phase-0-closeout.md) | Accepted | Phase 0 closeout |
| [ADR-0011](./adr-0011-primitive-trait.md) | Accepted | Primitive trait and Phase 1 entry |
| [ADR-0012](./adr-0012-claim-verification.md) | Accepted | Claim verification model |
| [ADR-0013](./adr-0013-report-format.md) | Accepted | Markdown report format |
| [ADR-0014](./adr-0014-primitive-catalog-growth.md) | Accepted | Primitive catalog growth strategy |
| [ADR-0015](./adr-0015-mcts-planner.md) | Accepted | MCTS planner with UCB1 selection |
| [ADR-0016](./adr-0016-bayesian-posterior.md) | Accepted | Bayesian posterior update over static priors |

## Phase 0 plan

The milestone-by-milestone plan lives in `mantis-phase0-plan.md` at the
repository's parent directory (the original planning artifact). When the
plan is moved into the repo, it lands at `docs/internal/phase0-plan.md`.

## How to add an ADR

1. Copy `adr-template.md` (TBD) to `adr-XXXX-short-title.md`.
2. Fill in **Status** (`Proposed`), **Date**, **Context**, **Decision**,
   **Consequences**.
3. Open a PR. ADRs require at least one reviewer for status to move from
   `Proposed` to `Accepted`.
4. Once accepted, ADRs are immutable. If circumstances change, write a
   new ADR that supersedes the old one and update the old one's status
   to `Superseded by ADR-XXXX`.
