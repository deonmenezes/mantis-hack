# Mantis

Daemon-driven, evidence-grade automated security research platform.

**Status:** Phase 0 — scaffold only. The PRD lives in `docs/internal/prd.md`
(or see the project repo). Nothing here is functional yet. This commit
scaffolds the Cargo workspace, CI matrix, and architectural decision
records for Phase 0 milestone M0.0.

## Quick start

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Workspace layout

```
crates/
├── mantis-core/             # shared types, errors, traits (no I/O)
├── mantis-proto/            # protobuf + tonic-generated types
├── mantis-workspace/        # workspace paths, key management, keychain
├── mantis-event-store/      # RocksDB-backed event log + Merkle evidence
├── mantis-scope/            # scope DSL: parse, sign, verify, evaluate
├── mantis-egress/           # scope-enforcing TCP/HTTP egress proxy
├── mantis-scanner-http/     # HTTP probing + content discovery
├── mantis-hypothesis/       # rule-based hypothesis generator
├── mantis-daemon/           # binary: tonic server, engagement loop
└── mantis-cli/              # binary: CLI client (`mantis`)
```

The security-critical crate is `mantis-egress` — it is the single network
boundary. All HTTP traffic from any other component routes through it.
This is enforced at the proxy socket layer, not advisorially.

## Roadmap

Phase 0 closes when:

1. An operator can create a workspace, generate signing keys, and load a
   signed engagement scope manifest.
2. The HTTP scanner runs against an in-scope target and writes
   observations to the event store.
3. The event store produces Merkle inclusion proofs that an external
   verifier accepts.
4. The egress proxy has been red-teamed at least once with zero confirmed
   out-of-scope dials.
5. CI is green on Linux x86_64, macOS ARM64, macOS x86_64, and Windows
   x86_64.

See `docs/internal/` for the milestone plan and ADRs.

## License

Dual-licensed under Apache-2.0 OR MIT.
