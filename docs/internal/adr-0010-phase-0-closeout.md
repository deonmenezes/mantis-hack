# ADR-0010: Phase 0 closeout

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M0.6 (Phase 0 final)

## Context

Phase 0 (PRD §15) committed to six milestones over three months:

- M0.0 — Foundations: workspace, CI, scaffolds.
- M0.1 — Workspace, keys, identities.
- M0.2 — Event store + Merkle evidence chain.
- M0.3 — Scope DSL + egress proxy (the security spine).
- M0.4 — Daemon + gRPC + functional CLI.
- M0.5 — HTTP scanner + rule-based hypothesis generator.
- M0.6 — Hibernation, hardening, perf baselines.

This ADR records the actual delivery state at Phase 0 close.

## Decision (what shipped in Phase 0)

### Code

| Crate | Role | LOC (approx) |
|---|---|---|
| `mantis-core` | Shared types + Signer trait | ~150 |
| `mantis-workspace` | Workspace, Ed25519 keys, Keychain | ~800 |
| `mantis-event-store` | RocksDB + Merkle + signed tree heads | ~800 |
| `mantis-scope` | Scope DSL, signing, evaluation, budget | ~1000 |
| `mantis-egress` | Scope-enforcing forward proxy | ~600 |
| `mantis-scanner-http` | HTTP probe scanner | ~350 |
| `mantis-hypothesis` | Rule catalog (12 rules) | ~350 |
| `mantis-proto` | tonic-generated gRPC types | (generated) |
| `mantis-daemon` | Server library + binary | ~600 |
| `mantis-cli` | `mantis` binary | ~450 |
| `mantis-verify` | Standalone proof verifier | ~250 |

### Verification

- **117 tests passing** (unit + integration), green across the
  workspace.
- `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings` both clean.
- CI matrix: Linux + macOS + Windows on `cargo build` / `clippy` /
  `test` / `cargo-deny` (per ADR-0001).

### Working end-to-end demo

```bash
mantis workspace init
mantis operator create alice
mantis daemon &
mantis engagement create demo
# build a signed scope JSON via mantis-scope::SignedScope::create
mantis engagement authorize <id> --scope signed-scope.json
mantis engagement start <id>        # spawns per-engagement egress proxy
mantis engagement scan <id> --target https://api.example.com/v1/users
mantis engagement export <id> > engagement.jsonl
mantis-verify --proof inclusion-proof.json --public-key <hex>  # OK
```

### Security spine integration (M0.6)

ADR-0009's deferred work landed in this milestone:

- `Engagement.Authorize` derives the `ScopeEvaluator` and
  `BudgetTracker` from the signed manifest and persists them in a
  per-engagement `EngagementRuntime` map.
- `Engagement.Start` binds an `EgressProxy` on a random localhost
  port (`127.0.0.1:0`) and spawns its serve task. The bound URL is
  stored in the engagement's runtime state.
- `Engagement.Scan` constructs the scanner with `ProbeConfig::proxy
  = Some(<engagement_proxy_url>)`, so every HTTPS probe issues a
  CONNECT through the scope-enforcing proxy.
- `Engagement.Pause` aborts the proxy task via `ProxyHandle::drop`.

### Architectural decision records

Phase 0 produced 10 ADRs:

1. ADR-0001 — Cargo workspace structure
2. ADR-0002 — Event sourcing semantics & replay invariants
3. ADR-0003 — Scope DSL grammar
4. ADR-0004 — Egress proxy threat model
5. ADR-0005 — gRPC API versioning policy
6. ADR-0006 — Workspace key management
7. ADR-0007 — Merkle evidence chain
8. ADR-0008 — Scanner + hypothesis pipeline
9. ADR-0009 — Engagement runtime + scanner integration
10. ADR-0010 — Phase 0 closeout (this document)

## What was DEFERRED out of Phase 0

The original Phase 0 plan included items that are now Phase-1 work:

- **Plain HTTP forwarding in the egress proxy.** The proxy currently
  only handles HTTPS CONNECT. Plain-HTTP forwarding (rewriting
  `Host:` headers, replaying requests) lands early in Phase 1 so
  the scanner can hit non-TLS targets.
- **Content-discovery scanner with wordlist + soft-404 clustering.**
  Phase 1.
- **Hibernation snapshot/restore.** Phase 4 (per PRD §15 phase 4
  scope), or earlier if continuous-monitoring becomes a Phase 1
  priority.
- **Performance baselines against NFR-6.1 targets.** Phase 0 did
  not measure throughput at the NFR-6.1.4 50k req/s target —
  premature for a single-probe scanner. Measurement infrastructure
  (criterion benchmarks) is Phase 1.
- **Cross-platform CI keychain tests.** All M0.1 tests use
  `InMemoryKeyStore` because real Keychain tests are interactive on
  macOS. Phase 1 adds Linux Secret Service CI coverage via
  gnome-keyring in a Docker test image.

## What is unbuilt (Phases 1–5)

PRD §15 phases 1–5 remain entirely unbuilt:

- **Phase 1** — MCTS planner with Bayesian posteriors, primitive
  catalog covering OWASP Top 10, verifier with property oracles,
  reproducer export (cURL/Python/Burp), Markdown reports with
  Merkle proofs.
- **Phase 2** — WASM plugin runtime with capability enforcement,
  LLM-backed synthesizer with record-replay sandbox, grammar fuzzer,
  TUI launch, all five report formats.
- **Phase 3** — Playbook distiller, cross-engagement memory,
  operator model, trajectory compression, evolutionary tuner.
- **Phase 4** — Continuous monitoring with cron + diff reports,
  hibernation manager with cloud backends, operator gateway across
  three messaging platforms, Web UI launch.
- **Phase 5** — Multi-tenant deployment, all seven messaging
  platforms, all five hibernation backends, Kubernetes operator,
  public plugin registry.

The PRD scopes Phases 1–5 to 15 calendar months for a small team.
At Phase-0-actual velocity (one milestone per focused day-equivalent
of work) the same scope is roughly 100–150 working days of
implementation effort. No realistic shortcut compresses that into a
single session.

## Phase 1 entry criteria

Before starting Phase 1, the following must hold:

1. All Phase 0 ADRs accepted (this includes ADR-0010 itself —
   transitively satisfied by adopting this document).
2. Manual red-team pass on the egress proxy. Phase 0 has property
   tests for the obvious bypasses (suffix attack, malformed
   CONNECT, budget exhaustion) but has not been hammered with
   adversarial tooling yet. A 30-minute red-team session with
   `nuclei` / `gobuster` / a custom prober against a tight-scope
   engagement is the minimum.
3. One full engagement run end-to-end on a real disclosure-program
   target (with explicit authorization). The current 117 tests use
   localhost mocks; a real target validates the integration in
   ways tests cannot.

## Consequences

- **+** Phase 0 ships a working, tested, ADR-documented foundation
  that Phase 1 components plug into without rework.
- **+** The security spine (egress proxy + scope evaluator + signed
  scope manifests + Merkle evidence chain) is in place and
  property-tested.
- **+** Every deferred Phase 0 item has a documented home in a
  later phase.
- **−** No real-world engagement has run yet. Localhost-mock
  testing is necessary but not sufficient. Phase 1's first task is
  the criterion #3 above.
- **−** Plain HTTP scanning is blocked until the proxy gets
  plain-HTTP forwarding. Phase 1 cleanup item #1.

## Verification

- 117 tests pass (`cargo test --workspace`).
- `cargo fmt --check` and `cargo clippy --workspace --all-targets
  -- -D warnings` both clean.
- All 10 Phase 0 ADRs merged, indexed in
  `docs/internal/README.md`.
