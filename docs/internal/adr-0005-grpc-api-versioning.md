# ADR-0005: gRPC API versioning policy

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M0.4

## Context

PRD §9.5 makes the daemon's gRPC API the authoritative interface
between the daemon and every client (CLI, future TUI, web UI,
operator gateway, third-party integrations). The protobuf definitions
have to be versioned in a way that allows additive evolution without
breaking older clients in the field.

## Decision

### Package namespacing

All RPC services and messages live under `package mantis.v1;` in the
`.proto` files. Breaking changes require a new package
`mantis.v2;` with both versions served by the daemon during the
overlap window.

### Backwards-compatible changes (no version bump)

- Adding a new optional field with a tag the producer fills in.
- Adding a new RPC to an existing service.
- Adding a new enum variant where the consumer treats unknown
  variants as `UNSPECIFIED`.
- Adding a new service.

### Breaking changes (require `mantis.v2`)

- Removing or renaming a field, RPC, message, service, or enum
  variant.
- Changing the type of a field.
- Changing the cardinality of a field (singular → repeated or vice
  versa).
- Changing the wire-level meaning of a value.

### Transport

Phase 0 binds the daemon to TCP on `127.0.0.1:50451` by default. The
CLI's `--daemon` flag (or `MANTIS_DAEMON` env var) overrides. M0.6
will add a Unix-domain-socket option for stronger isolation on
multi-user systems.

The daemon also writes its bound endpoint to
`$workspace/daemon.endpoint` (text `http://host:port`) for
discoverability.

### Schema versioning vs. API versioning

- The protobuf `package mantis.v1` is the **API version** — bumped
  only on breaking wire changes.
- The `mantis_proto::SCHEMA_VERSION` constant tracks the **API
  shape version** within a major. Bumped on each non-breaking
  change for telemetry / debug purposes; clients don't gate on it.

### Build-time dependency: `protoc`

`tonic-build` requires `protoc` to be available at build time. CI
installs it via `apt-get install protobuf-compiler` on Linux,
`brew install protobuf` on macOS, and Chocolatey or scoop on Windows.
The proto compiler is **not** a runtime dependency — once the Rust
types are generated, the daemon and CLI binaries are
self-contained.

## Alternatives considered

1. **Single-major-version-forever.** Tempting for simplicity.
   Rejected because the PRD describes many surface areas across 18
   months; some breaking change will be necessary. Better to have
   the lever defined up front.
2. **Vendored `protox` instead of `protoc`.** Removes the build-time
   binary dependency. Rejected for Phase 0 because `protoc` is
   well-known to operators and protox is less battle-tested. M0.6
   may revisit.
3. **JSON-over-HTTP instead of gRPC.** Simpler to inspect, lower
   tooling overhead. Rejected because the PRD §9.5 names gRPC and
   because tonic's streaming support is needed for
   `Engagement.Subscribe` and `Trace.Subscribe` (Phase 1).

## Consequences

- **+** Clients written against `mantis.v1` keep working as the API
  grows, until and unless a deliberate v2 cutover happens.
- **+** Non-Rust clients (Python, Go, web TS) can codegen from the
  same `.proto` files; the wire format is the contract.
- **−** Two protoc-build artifacts must coexist during a v1→v2
  cutover. The daemon serves both, the CLI picks one based on its
  protobuf dependency. Operational complexity at cutover time.
- **−** `protoc` becomes a build-time dependency for the whole
  workspace, even crates that don't touch the proto. Mitigation:
  only `mantis-proto` depends on `tonic-build`; other crates pick up
  the generated types via `mantis-proto`.

## Verification

- The protoc dependency is documented in this ADR and (future
  work) in `docs/internal/contributor-guide.md`.
- Manual smoke test on macOS (2026-05-16):
  ```
  $ mantis workspace init
  $ mantis daemon &      # starts gRPC server on 127.0.0.1:50451
  $ mantis engagement create demo
  Engagement:
    id:           01KRRXJ59C3H1VY7B561SDS00X
    state:        draft
    events:       1
  $ mantis engagement start <id>
  Error: status: FailedPrecondition,
         message: "cannot transition Draft -> Active"
  ```
  Confirmed: the daemon enforces the engagement FSM at the gRPC
  layer; an illegal `Start` is rejected before any event lands in
  the log.
