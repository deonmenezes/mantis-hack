# ADR-0001: Cargo workspace structure and crate boundaries

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M0.0

## Context

The Mantis daemon is one statically-linked binary (NFR-6.7.1), but
internally it is a collection of distinct subsystems: workspace and key
management, event sourcing, scope DSL, egress proxy, scanners, hypothesis
generation, gRPC server, and a CLI client. Putting all of these in a
single crate would conflate concerns, slow incremental compilation, and
make the security-critical subsystems (egress, scope, event store)
indistinguishable from the rest.

The PRD also names a separate egress proxy (§5.2.3) that is the single
network boundary for the entire system. That boundary needs to be a
distinct crate so it can be audited and fuzzed independently and so any
other crate can be reviewed for direct network access by checking its
dependency graph.

## Decision

A Cargo workspace with ten crates:

| Crate | Kind | Purpose | Phase 0 milestone |
|---|---|---|---|
| `mantis-core` | lib | Shared types, errors, pure logic. No I/O, no async. | M0.0 |
| `mantis-proto` | lib | Generated protobuf + tonic types. | M0.4 |
| `mantis-workspace` | lib | Workspace layout, paths, key management, keychain. | M0.1 |
| `mantis-event-store` | lib | RocksDB-backed event log + Merkle evidence chain. | M0.2 |
| `mantis-scope` | lib | Scope DSL: parse, sign, verify, evaluate. | M0.3 |
| `mantis-egress` | lib | Scope-enforcing forward proxy. The single network boundary. | M0.3 |
| `mantis-scanner-http` | lib | HTTP probing + content discovery. | M0.5 |
| `mantis-hypothesis` | lib | Rule-based hypothesis generator. | M0.5 |
| `mantis-daemon` | bin | Daemon process (`mantis-daemon`). | M0.4 |
| `mantis-cli` | bin | CLI client (`mantis`). | M0.4 |

Cross-crate rules:

1. **`mantis-core` is the dependency floor.** No I/O, no async, no
   crates with a runtime. Everything else may depend on it; it depends
   on nothing in the workspace.
2. **Only `mantis-egress` may speak to the network.** Scanners and any
   future plugin runtime route through it. CI lints (planned for M0.4)
   will assert that no other crate transitively depends on `reqwest`,
   `hyper`, or `tokio::net` directly.
3. **`mantis-proto` is the API contract.** Future non-Rust clients
   (TUI, web, gateway) consume the same `.proto` files. The crate
   exists as a standalone artifact so it can be published independently
   if needed.
4. **Workspace-level lints.** `unsafe_code = "forbid"` at the workspace
   level. Individual crates may opt in via local `#[allow]` only with
   an accompanying ADR explaining why.
5. **Edition 2021, MSRV 1.85.** Edition 2024 was deferred until at
   least one external dependency requires it; the language features
   we need are all available in 2021.

## Alternatives considered

- **Single crate with `mod` boundaries.** Faster initial setup but
  rapidly becomes painful: every change recompiles everything, and the
  egress boundary is a convention rather than a build-time fact.
- **Two-crate split (`mantis-lib`, `mantis-bin`).** Common in smaller
  Rust projects. Insufficient for our case because the security boundary
  matters and we want multiple binaries (daemon + cli) without sharing a
  single library surface.
- **Many tiny crates (~20+).** Considered, rejected. The cost of crate
  metadata, version coordination, and slower dependency resolution
  outweighs the modularity gain for crates that exist only to separate
  one function from another.

## Consequences

- **+** Clear security boundary: `mantis-egress` is the only crate that
  appears in egress audits.
- **+** Incremental compilation is much faster: changing a scanner does
  not recompile the event store.
- **+** Tests are scoped per crate; failures point at a specific
  subsystem.
- **−** Cross-crate refactors cost more than within a single crate.
  Mitigation: keep `mantis-core` lean and stable so most refactors don't
  cross crate boundaries.
- **−** New contributors face a layout to learn before they can land a
  change. Mitigation: the README and this ADR are the entry points.

## Verification

The decision is verified at the end of M0.0 by:

- `cargo build --workspace` succeeds.
- `cargo test --workspace` passes (≥13 tests as of this ADR).
- `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- Each crate's `Cargo.toml` declares only the deps it needs.
- No crate other than `mantis-egress` depends on a network-capable crate
  (manually verified in M0.0; enforced by CI lint in M0.4).
