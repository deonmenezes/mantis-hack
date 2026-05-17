# ADR-0009: Engagement runtime + scanner integration

**Status:** Accepted (with Phase 0 limitations documented)
**Date:** 2026-05-16
**Milestone:** M0.5b

## Context

The daemon now owns the engagement lifecycle (M0.4) and the scanner +
hypothesis generator exist as standalone crates (M0.5). M0.5b bridges
them: the daemon's `Engagement.Scan` RPC drives the scanner over a
list of URL targets, runs the hypothesis catalog over every surface,
and persists the resulting events to the engagement's append-only
log. The companion `Engagement.Export` RPC streams the full event log
back as JSONL for offline review.

## Decision

### Scan RPC

```proto
rpc Scan(ScanRequest) returns (ScanResponse);
message ScanRequest {
  string id = 1;
  repeated string targets = 2;
}
message ScanResponse {
  string id = 1;
  uint32 surfaces_recorded = 2;
  uint32 hypotheses_recorded = 3;
}
```

Daemon handler:

1. Parse `id` as ULID.
2. Read engagement state; reject with `FailedPrecondition` unless
   `Active`.
3. Parse each target as a `ProbeTarget`. Reject with
   `InvalidArgument` on the first malformed URL.
4. Construct an `HttpProbeScanner` (no proxy — see "Phase 0
   limitation" below).
5. For each target: probe → write `SurfaceDiscovered` → run
   hypothesis catalog → write one `HypothesisGenerated` per match.
6. Update the in-memory event count from the persistent count.
7. Return totals.

A failed probe (timeout, DNS, refused connection) is logged at WARN
and skipped; the rest of the scan continues. This matches the
scanner crate's `probe_all` contract.

### Export RPC

```proto
rpc Export(ExportRequest) returns (ExportResponse);
message ExportRequest { string id = 1; }
message ExportResponse { bytes jsonl = 1; }
```

Replays every event for the engagement and concatenates
`serde_json::to_vec(&event) + "\n"`. The result is suitable for
piping to `jq`, loading into a notebook, or feeding the future
`mantis-verify` companion that derives inclusion proofs from the
exported stream.

### CLI

```
$ mantis engagement scan <id> --target https://api.example.com/ --target https://api.example.com/v1
Scan complete.
  surfaces:   2
  hypotheses: 5

$ mantis engagement export <id> > engagement.jsonl
```

## Phase 0 limitation (security gap, scheduled for M0.6)

**The scanner inside `Engagement.Scan` does NOT currently route
through the egress proxy.** That means the scope manifest's
host/port restrictions are not enforced at scan time on this code
path. Specifically:

- A scan request with a target outside the engagement's scope will
  still hit the network (as long as the target resolves and is
  reachable).
- The hostname is validated when the URL is parsed, but no
  `ScopeEvaluator::evaluate` call is made.

This is documented as **acceptable for Phase 0 demo** because:

- The scope evaluator and egress proxy are themselves shipped,
  property-tested, and security-reviewed (ADRs 0003, 0004).
- Production engagements run the scanner OUTSIDE the daemon, through
  the CLI's `mantis engagement scan` against a daemon that has the
  egress proxy bound on its own port; the CLI calls the daemon, the
  daemon calls the scanner, the scanner is configured with the
  proxy URL. M0.6 wires this up properly.
- The current path is sufficient to demonstrate the full
  surface→hypothesis flow against a controlled-environment target
  (httpbin, etc.) without TLS-cert pain.

**M0.6 closing the gap:**

1. On `Engagement.Authorize`, the daemon derives the `ScopeEvaluator`
   and `BudgetTracker` from the signed manifest and persists them in
   the engagement state.
2. On `Engagement.Start`, the daemon binds an `EgressProxy` on a
   random localhost port, spawns its `serve()` task, and stores the
   bound URL in the engagement state.
3. On `Engagement.Scan`, the scanner is constructed with
   `ProbeConfig::proxy = Some(<bound URL>)`. Every probe routes
   through the proxy, which enforces scope at the socket layer.
4. On `Engagement.Pause` / `Complete`, the proxy task is aborted.
5. Tests assert: scan with a target outside scope is rejected at the
   proxy layer, not (only) at the URL parser. Tampering with the
   scope evaluator after Start cannot bypass enforcement.

## Alternatives considered

1. **Block M0.5b on M0.6 (no scan until full proxy integration).**
   Cleaner from a security standpoint. Rejected because the visible
   end-to-end flow (`scan` + `export`) is the milestone deliverable;
   shipping it without the proxy fully wired is acceptable as long
   as the gap is explicit, time-boxed, and documented.
2. **Run the scanner in a separate process** spawned by the daemon.
   Easier isolation, harder to share state. Deferred — single-process
   model is simpler for Phase 0.
3. **Make `Engagement.Scan` a streaming RPC** that emits each
   surface as it's discovered. More responsive UX, more complex
   error handling. Phase 1 will revisit when the planner exists.

## Consequences

- **+** The full demo flow now works end-to-end:
  `workspace init` → `daemon` → `engagement create` →
  `engagement scan --target ...` → `engagement export` → JSONL on
  disk that downstream tools can consume.
- **+** The `HypothesisGenerated` event carries enough context that
  a reviewer can map every hypothesis back to its source surface.
- **−** The egress-proxy gap is a real Phase-0 limitation operators
  need to be aware of. The CLI prints a warning when scanning
  without a proxy configured in production mode (planned for M0.6).
- **−** The current handler is per-call synchronous-async (awaits
  every probe before responding). Long target lists make the RPC
  hang. Phase 1 introduces a streaming response with per-target
  progress.

## Verification

- Daemon compiles with all M0.5b changes (`cargo build
  --workspace`).
- Existing 117 tests still pass (`cargo test --workspace`).
- Manual integration test deferred to M0.6 once the proxy is wired
  in — at that point the full property guarantee (no out-of-scope
  scan ever produces a SurfaceDiscovered event) becomes testable.
