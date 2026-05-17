# Mantis — Phase 0 Implementation Plan

**Source of truth:** Mantis PRD v0.1 (Phase 0, §15)
**Status:** Planning. No code yet.
**Plan owner:** Deon
**Target duration:** 3 months / 6 milestones

---

## 1. Phase 0 scope (verbatim from PRD §15)

> - Daemon process, event store, scope DSL, egress proxy.
> - One native scanner (HTTP probing + content discovery).
> - CLI only.
> - Local-disk workspace.
> - No LLM integration; rule-based hypothesis generator.

**Phase 0 is explicitly NOT:** MCTS, Bayesian posteriors, primitive catalog, verifier, reproducer export, reports, WASM plugins, LLM synthesizer, TUI, web UI, operator gateway, multi-tenancy, hibernation cloud backends. Anything in those buckets is out — write it down, do not build it.

**Phase 0 ships when:** an operator can create a signed engagement, run the HTTP scanner against an in-scope target, see hypotheses generated and recorded, and have every observation appended to a Merkle-anchored event log on local disk. No exploits. No reports beyond raw event export.

---

## 2. Repository strategy

**Recommendation: new single-repo Cargo workspace, separate from `mantishack`.**

`mantishack` is the marketing/docs site; mixing daemon code there would couple two release cadences and confuse contributors. The PRD also references a `bountyhunter` repo — clarify with yourself whether that's the intended daemon home or legacy. If reusing `bountyhunter`, treat the existing contents as legacy and put the workspace under a fresh top-level directory.

```
mantis-daemon/                   # new repo (or new top-level dir in bountyhunter)
├── Cargo.toml                   # workspace manifest
├── rust-toolchain.toml          # pin stable + minimum version
├── deny.toml                    # cargo-deny config
├── .github/workflows/           # CI matrix
├── crates/
│   ├── mantis-core/             # shared types, errors, traits
│   ├── mantis-proto/            # protobuf + tonic build
│   ├── mantis-workspace/        # paths, keychain, key mgmt
│   ├── mantis-event-store/      # RocksDB + Merkle log
│   ├── mantis-scope/            # scope DSL: parse, sign, verify, evaluate
│   ├── mantis-egress/           # scope-enforcing TCP proxy
│   ├── mantis-scanner-http/     # HTTP probing + content discovery
│   ├── mantis-hypothesis/       # rule-based generator
│   ├── mantis-daemon/           # binary: tonic server, engagement loop
│   └── mantis-cli/              # binary: clap CLI, tonic client
├── proto/                       # .proto files
├── docs/internal/               # ADRs, design notes
└── tests/                       # cross-crate integration tests
```

**Rationale for the split:**
- `mantis-core` keeps shared types in one place so circular deps never appear.
- `mantis-egress` is the security-critical crate; keeping it isolated means it can be audited and fuzzed independently and depended on by anything that touches the network.
- Two binary crates (`daemon`, `cli`) match PRD §9.1 — the CLI is a gRPC client, the daemon is the server.
- `mantis-proto` exists separately so non-Rust clients (future TUI, web, gateway) can consume the same .proto files without pulling daemon source.

---

## 3. Tech stack and dependency choices

| Concern | Choice | Why | Cite |
|---|---|---|---|
| Async runtime | `tokio` 1.x, multi-thread | Standard, mature, matches PRD §7.2 | PRD §7.2 |
| io_uring | **Deferred.** Use plain tokio in Phase 0; add `tokio-uring` in Phase 1 once perf testing motivates it | Premature optimization; uring complicates async model | PRD §7.2 says "with `tokio-uring` on Linux" — that's an end-state, not a Phase 0 gate |
| Event store backend | `rocksdb` (rust-rocksdb crate) | Hard-named in PRD §7.1 | PRD §7.1 |
| Graph store | **Deferred** (Phase 1+) | Not needed until MCTS / capability graph | PRD §7.1 names Kuzu — defer |
| Signing | `ed25519-dalek` v2 | Hard-named in PRD §5.2.2 | PRD §5.2.2 |
| At-rest encryption | `age` (rage crate) for workspace key wrap | Standard, audited, passphrase-based | PRD §6.4.3 — workspace keys encrypted |
| OS keychain | `keyring` crate | Cross-platform (macOS Keychain, Windows Credential Manager, Linux Secret Service) | PRD §6.4.4 |
| Serialization | `serde` + `serde_yaml` (scope) + `serde_json` (events) | Standard | PRD §5.2.1 says YAML manifests |
| RPC | `tonic` 0.12 + `prost` | gRPC mandated by PRD §9.5 | PRD §9.5 |
| HTTP client (scanner) | `reqwest` with `rustls`, **routed through the egress proxy** | Pure-Rust TLS, no openssl headaches on Windows | PRD §6.7.1 cross-platform |
| HTTP server (probing helpers, future) | `hyper` 1.x | Lower-level when needed | — |
| CLI | `clap` v4 derive | Standard | — |
| Observability | `tracing` + `tracing-subscriber` + `tracing-opentelemetry` + `opentelemetry-otlp` | OTel spans are NFR-6.6.1 from day one | PRD §6.6 |
| Metrics | `metrics` + `metrics-exporter-prometheus` | Prom format is NFR-6.6.4 | PRD §6.6.4 |
| Error model | `thiserror` for library crates, `anyhow` only inside binaries | — | — |
| Paths | `camino` `Utf8Path*` | Saves us from non-UTF8 path edge cases on Windows | — |
| Hashing for Merkle | `blake3` (Merkle tree primitive) | Fast, modern, parallelizable; PRD doesn't pin a hash function | — |
| Test framework | built-in + `insta` (snapshot) + `proptest` (egress invariants) + `criterion` (perf later) | Property tests for egress are non-negotiable | — |
| Build hygiene | `cargo-deny`, `cargo-audit`, `clippy --deny warnings`, `rustfmt` | Standard | — |

**Deferred-with-rationale (do NOT add in Phase 0):**
- `wasmtime` — Phase 2 plugin runtime.
- Any LLM SDK — Phase 2.
- `ratatui` — Phase 2 TUI.
- Any web framework — Phase 4 web UI.
- `typst` — Phase 1 reports.
- Headless browser (chromiumoxide / fantoccini) — needed for FR-5.3.5 in Phase 1 crawling, not Phase 0.

---

## 4. Module-by-module Phase 0 surface area

For each crate, what it exposes at end of Phase 0 — no more, no less.

### `mantis-core`
- `EngagementId`, `OperatorId`, `WorkspaceId` newtypes.
- `Engagement { id, scope_manifest_hash, expiry, budget, state }`.
- `EngagementState` enum: `Draft | Authorized | Active | Paused | Completed | Archived`.
- `Observation`, `Hypothesis`, `Surface`, `Target` structs.
- `Event` enum — every state-mutating event in the system.
- `MantisError` root error.
- No I/O, no async.

### `mantis-workspace`
- `Workspace::open(path) -> Result<Workspace>`.
- Creates layout from PRD §7.3.
- `Workspace::generate_key()` — Ed25519 keypair, age-wrapped on disk, keychain-backed where available.
- `Workspace::sign(bytes) -> Signature`.
- Operator profile load/save (JSON, Phase 0 keeps it trivial).

### `mantis-event-store`
- `EventStore::append(engagement_id, event) -> EventId`.
- `EventStore::replay(engagement_id) -> Stream<Event>`.
- `EventStore::merkle_head(engagement_id) -> SignedTreeHead`.
- `EventStore::inclusion_proof(observation_hash) -> MerkleProof`.
- Backed by one RocksDB instance per workspace, column-family per engagement.
- Tree-head signing happens on every append, batched at small intervals for throughput.

### `mantis-scope`
- `ScopeManifest` struct (YAML <-> serde).
- `SignedScope::verify(public_key) -> Result<ScopeManifest>`.
- `ScopeEvaluator::evaluate(host, port, path?) -> InScope | OutOfScope { reason }`.
- `BudgetEnvelope` and `BudgetTracker` (request count, bytes, wall clock, request rate).
- Pure logic, no I/O.

### `mantis-egress`
- `EgressProxy::new(scope, budget, event_log) -> Self`.
- Listens on a Unix socket (or named pipe on Windows).
- Speaks HTTP/1.1 and HTTP/2 forward-proxy CONNECT semantics; for Phase 0, HTTP/1.1 only is acceptable.
- **At connect time**: parse host:port from CONNECT request; consult ScopeEvaluator; refuse with 403 if out-of-scope; record decision to event log.
- **Per-request**: increment budget tracker; refuse if exhausted.
- The scanner (`reqwest`) is configured to use this proxy. No other component talks to the network.
- This crate is the single security boundary. Property-test it aggressively.

### `mantis-scanner-http`
- `HttpProbeScanner` — given a list of hosts, returns surface records (host, port, scheme, status, server header, tech fingerprint).
- `ContentDiscoveryScanner` — given live hosts + wordlist, returns discovered paths with response-shape clustering for soft-404 suppression.
- Uses `reqwest::Client` configured to route through the egress proxy.
- Writes observations to event store. Never speaks to the network directly.

### `mantis-hypothesis`
- `RuleBasedGenerator::generate(surface) -> Vec<Hypothesis>`.
- Phase 0 rule set: small built-in catalog of `(surface_pattern, vuln_class)` rules, each producing a `Hypothesis` with a static prior. No Bayesian update logic here (that's Phase 1).
- Literal-string dedup of generated hypotheses (semantic dedup is Phase 1).

### `mantis-proto`
- `proto/engagement.proto`, `proto/scanner.proto`, `proto/event.proto`.
- `build.rs` invokes `tonic-build`.
- RPCs needed for Phase 0:
  - `Engagement.Create / Authorize / Start / Pause / Resume / Hibernate / Status`.
  - `Engagement.Subscribe` (server-streaming) for live events.
  - `Scope.Get / Update`.
  - `Claim.List` (returns empty list in Phase 0 — keeps API stable).

### `mantis-daemon`
- Binary. Starts tonic server bound to localhost-only by default (NFR-6.4.6: no inbound by default).
- Owns the workspace, event store, and egress proxy instances.
- Engagement loop: on `Start`, spawn scanner pipeline, stream events.
- Graceful shutdown drains in-flight observations and flushes Merkle head.

### `mantis-cli`
- Binary. Phase 0 subcommands (subset of PRD §9.1):
  - `mantis daemon` — exec the daemon binary or attach to it.
  - `mantis engagement create <name>`
  - `mantis engagement authorize <id> --scope <file> --key <operator-key>`
  - `mantis engagement start <id>`
  - `mantis engagement pause <id>`
  - `mantis engagement status <id>`
  - `mantis scope <id>`
  - `mantis doctor`
  - `mantis export <id>` — dumps the event log as JSONL + a Merkle proof bundle (stand-in for reports).
- All other CLI commands from §9.1 return `unimplemented (Phase 0)` so the surface is discoverable.

---

## 5. Cross-cutting decisions to make once, up front

These are the easy-to-get-wrong-later choices. Decide before M0.1.

1. **Event schema versioning.** Every `Event` variant carries `schema_version: u16`. Replay code matches on version. Adding a new field is a non-breaking version bump; removing a field is breaking. Write this rule into `mantis-core`'s docs.
2. **Time source.** Use `std::time::SystemTime` for wall clock at event-append, `tokio::time::Instant` for everything else. Never mix. Events store both, so replay can recover original wall time.
3. **ID generation.** ULID for all entity IDs (sortable, no central authority needed). One crate-wide helper.
4. **Workspace path resolution.** `$MANTIS_HOME` overrides `~/.mantis`. Resolve once at daemon start, log the result.
5. **Error vs panic.** Panics are for invariant violations only (bugs). Every I/O, every external input is `Result`. Clippy lint `unwrap_used` denied in library crates, allowed in tests and binaries.
6. **Logging keys.** Every log line has `engagement_id`, `operator_id`, and `trace_id` when available. Use `tracing::Span::current().record(...)` from the entry points.
7. **Default ports.** Daemon listens on a Unix socket at `$MANTIS_HOME/daemon.sock`. No TCP by default. The CLI client and the egress proxy use named sockets too. (Windows: named pipes; `interprocess` crate abstracts this.)
8. **Signing convention.** All signed payloads use a `Mantis-v1:<context>:` domain-separation prefix before signing. Prevents cross-protocol attacks if the same key signs different artifact types.

---

## 6. Milestones

Six milestones, ~2 weeks each. Each milestone ends with a **demoable artifact** and explicit acceptance criteria. If a milestone slips, the next one's scope reduces — the cut list is in §7.

### M0.0 — Scaffolding & CI (week 1)
- Cargo workspace created, all crate skeletons compile and pass `cargo test` (empty tests).
- CI matrix: Linux x86_64, Linux ARM64, macOS ARM64, macOS x86_64, Windows x86_64. `cargo check`, `clippy`, `fmt`, `deny`, `audit`, `test`. (Per NFR-6.7.1.)
- `tracing` + OTel exporter wired in `mantis-daemon`; spans visible in a local Jaeger.
- ADR-0001 written: "Why a Cargo workspace, why these crates."
- ADR-0002 written: "Event sourcing semantics and replay invariants."

**Done when:** PR merges to main and CI is green across the matrix. A `mantis --help` prints `unimplemented` for every subcommand.

### M0.1 — Workspace, keys, identities (week 2)
- `mantis-workspace` complete: open/create workspace, generate/load Ed25519 keypair, age-wrap on disk, keychain integration on macOS + Linux (Windows can fall back to age + passphrase).
- Operator identity created via `mantis operator create`; profile JSON stored.
- `mantis doctor` reports workspace path, key fingerprint, OS keychain status.

**Done when:** A fresh workspace can be created on all five platforms; key round-trips through encrypt/decrypt; `doctor` is green.

### M0.2 — Event store + Merkle log (weeks 3–4)
- RocksDB integration in `mantis-event-store`. One DB per workspace, one column family per engagement.
- Append-only API; replay API.
- Per-engagement Merkle tree using BLAKE3. Signed tree head written on every append (batched for throughput, fsync'd at flush boundaries).
- Inclusion-proof generator + standalone verifier binary (`mantis-verify`) that takes a proof + public key and prints `OK | FAIL`.
- Property tests: append→replay round-trip; appending corrupted state fails; tree head signature catches mid-stream tampering.

**Done when:** 100k events append → replay round-trip in under 5s on a developer laptop; inclusion proofs verify; external verifier works against an exported proof bundle. (NFR-6.5.5.)

### M0.3 — Scope DSL + Egress proxy (weeks 5–6) — **the security milestone**
- `mantis-scope`: YAML manifest schema; Ed25519 signing/verification with domain separation; ScopeEvaluator with glob and CIDR support; BudgetEnvelope + BudgetTracker.
- `mantis-egress`: Unix-socket / named-pipe HTTP forward proxy; CONNECT semantics; scope evaluation before TCP dial; budget decrement per request; event-log writes for every allow/deny decision.
- Property tests asserting: (a) no out-of-scope host is ever dialed, regardless of proxy input; (b) budget exhaustion stops further requests within the next event-loop tick; (c) malformed CONNECT requests are rejected; (d) DNS rebinding can't bypass scope (resolve before dial; pass resolved IP to scope check).
- Manual red-team pass: try to bypass scope. Document attempts and outcomes.

**Done when:** Property tests pass; manual red-team pass produces zero successful out-of-scope dials; `mantis budget` shows live consumption.

### M0.4 — Daemon, gRPC, CLI wiring (weeks 7–8)
- `mantis-proto` complete for the Phase 0 RPC subset.
- `mantis-daemon` boots, opens workspace, loads engagements, serves tonic over Unix socket.
- `mantis-cli` implements the Phase 0 subcommand list (§4, `mantis-cli` bullet).
- `Engagement.Subscribe` streams live events to the CLI; `mantis engagement status <id> --follow` works.
- Pause/resume/hibernate (local snapshot only — defer cloud backends to Phase 4).

**Done when:** End-to-end flow works: create workspace → create engagement → load signed scope → start → see events stream to terminal → pause → resume → status reflects everything correctly.

### M0.5 — HTTP scanner + rule-based hypothesis generator (weeks 9–10)
- `mantis-scanner-http`: probe (status, server header, TLS cert, basic Wappalyzer-style fingerprint via response signatures), content discovery (wordlist-driven with response-shape clustering for soft-404 — basic histogram approach is fine for Phase 0).
- All HTTP traffic routes through `mantis-egress`. Verify in tests that the scanner cannot construct a `reqwest::Client` that bypasses the proxy.
- `mantis-hypothesis`: rule catalog with ~20 starter rules covering obvious cases (form input → XSS hypothesis; numeric path segment → IDOR; `?id=` → SQLi; etc.). Each hypothesis is recorded as an event.

**Done when:** Running an engagement against `httpbin.org` (or a local docker target) produces a populated event log with surfaces, fingerprints, and hypotheses; `mantis export <id>` produces a JSONL bundle that an external script can replay.

### M0.6 — Hardening, hibernation v1, internal docs (weeks 11–12)
- Engagement expiry enforcement at egress (FR-5.1.4).
- Local-disk hibernation: serialize live engagement state, terminate workers, restore on demand (cloud backends are Phase 4; local-only is fine here).
- Crash recovery: kill -9 the daemon mid-engagement; on restart, replay events, resume from last consistent state.
- Internal docs: architecture overview, contributor guide, ADRs for every major decision, runbook for `mantis doctor` failures.
- Performance baselines captured (not optimized): time-to-first-event, throughput on probe, memory footprint per engagement.

**Done when:** Hibernation round-trips an active engagement losslessly (NFR-6.3.3); crash recovery works; baseline metrics recorded for Phase 1 to optimize against.

---

## 7. Cut list (if milestones slip)

Cut in this order — first item is the cheapest to defer:

1. Soft-404 response-shape clustering (replace with literal-404-only in M0.5).
2. Windows keychain integration (M0.1) — age + passphrase is sufficient for Phase 0; Windows users get a passphrase prompt.
3. Hibernation (M0.6) — pause/resume is enough; defer hibernation snapshot/restore to early Phase 1.
4. `mantis export <id>` JSONL bundle (M0.5) — operators can read the event store directly during Phase 0 if needed.
5. ARM64 Linux CI target (M0.0) — keep x86_64 Linux, both macOS, and Windows; add ARM64 in Phase 1.

Do **not** cut: the egress proxy, Merkle log, or signed scope manifests. Those are the security spine of the whole product — cutting any of them means Phase 1 builds on sand.

---

## 8. Phase-0-specific risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Egress proxy has a bypass | Medium | Critical | M0.3 property tests + manual red-team pass before M0.4 starts. Treat any bypass as a Phase 0 blocker, not a backlog item. |
| RocksDB build issues on Windows | High | Medium | Test on Windows CI from M0.0. Prebuilt binaries via `librocksdb-sys` features. Have `sled`/`redb` ready as a fallback ADR (don't switch unless RocksDB is genuinely blocked). |
| Cross-platform IPC (Unix socket vs named pipe) divergence | Medium | Low | Use `interprocess` crate abstraction; integration test on all platforms in M0.4. |
| Event-store performance below baseline | Medium | Medium | Defer optimization. Capture baseline in M0.6; optimize in Phase 1 with `tokio-uring` + batching tuning. NFR-6.1.4 (50k req/s) is **not a Phase 0 gate**. |
| Scope DSL ambiguity (paths vs hosts, glob semantics) | Medium | Medium | Write the formal grammar in M0.3's ADR before implementing. Reference examples from PortSwigger/HackerOne scope manifests. |
| Drift between PRD and implementation | Medium | Medium | Every milestone's PR description links the PRD sections it implements. Discrepancies become PRD updates or ADR entries, not silent deviations. |

---

## 9. Definition of Done for Phase 0

All of the following must be true on the day Phase 0 closes:

1. A new operator on any of the five supported platforms can install the daemon and CLI from a release artifact and run `mantis doctor` green.
2. They can create an engagement, load a signed scope manifest, run the HTTP scanner against an in-scope target, and watch hypotheses populate.
3. Every observation is in the event log; every event-log read produces a valid Merkle inclusion proof; the external `mantis-verify` binary confirms the proof against the workspace public key.
4. The egress proxy has been red-teamed at least once with documented attack attempts and zero confirmed bypasses.
5. The daemon can be killed at any point and restarted without state loss.
6. Engagement pause / resume works end-to-end.
7. Every Phase 0 ADR is merged and linked from `docs/internal/README.md`.
8. CI is green on the full platform matrix.

If any of those are false, Phase 0 isn't done. Don't start Phase 1 with debt in the security spine.

---

## 10. Immediate next actions (this week)

1. Decide repo home: new `mantis-daemon` repo, or new top-level directory inside `bountyhunter`. (Sub-question: are there assets in `bountyhunter` worth carrying forward?)
2. Write ADR-0001 (workspace structure) and ADR-0002 (event sourcing semantics) as part of M0.0. Both should be ≤2 pages; the goal is forcing the decision, not producing documentation.
3. Scaffold the Cargo workspace and CI matrix. Target: green CI on all platforms by end of week, with empty crates.
4. Draft the scope DSL grammar in a markdown ADR — even before any code in `mantis-scope`. It's the most under-specified part of the PRD and getting it wrong costs the most.

---

**End of plan.**
