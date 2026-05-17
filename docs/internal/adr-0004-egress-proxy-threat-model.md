# ADR-0004: Egress proxy threat model and bypass guarantees

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M0.3

## Context

PRD §5.2.3 makes the egress proxy the single network boundary in
Mantis: every component that wants to touch the network does so
through it, and out-of-scope connections are refused at the socket
layer. The proxy is the security spine of the entire product — every
later milestone assumes its guarantees. This ADR pins what those
guarantees are, the attack model they protect against, and the
attacks that remain out of scope for Phase 0.

## Decision

### Guarantees (Phase 0)

The proxy guarantees the following for any in-scope-only engagement:

1. **No out-of-scope TCP dial.** If the [`ScopeEvaluator`] returns
   `OutOfScope` for the requested `(hostname, port, https)`, no
   `connect()` syscall is invoked for that request.
2. **DNS-rebinding resistance for a single connection.** Resolution
   happens exactly once per CONNECT, and the resulting IP is the one
   the proxy dials. Subsequent DNS changes for the same hostname do
   not affect an active connection.
3. **Budget enforcement before dial.** `BudgetTracker::try_acquire_request`
   is called *before* the upstream `connect()`. Exhaustion produces an
   HTTP 429 and no upstream dial.
4. **Every decision is logged.** Every allow and deny appends a
   `ScopeDecisionLogged` event to the engagement event log
   (signed-tree-head updated as a side effect — see ADR-0007).
5. **Malformed requests do not bypass scope.** A request that fails
   the parser is rejected with 400 *before* any scope or budget
   check is consulted, and no upstream dial occurs.
6. **Plain HTTP is refused in Phase 0.** Only CONNECT is supported;
   other methods are rejected by the parser. (Phase 0 demos use
   HTTPS targets; plain-HTTP forwarding is a later milestone.)

### Threat model

Adversary capabilities the design protects against:

- **DNS resolver compromise / on-path rebinding.** Mitigation:
  resolve once, pin the IP for the connection lifetime; scope check
  on hostname (not IP), so even a malicious resolver swapping IPs
  cannot bypass the named-host scope.
- **Hostname suffix attack** (`evil.example.com.attacker.tld`).
  Mitigation: per-label glob in the host pattern matcher (see
  ADR-0003), enforced by the unit test
  `suffix_attack_hostname_rejected`.
- **Malformed proxy request.** Mitigation: `httparse` validates the
  HTTP/1.1 request before scope is consulted. Anything that
  doesn't parse is 400, no dial.
- **Budget bypass via concurrent requests.** Mitigation:
  `BudgetTracker` uses `AtomicU64::fetch_add` with a CAS-style
  un-decrement on overflow. A race-condition test would assert
  this; for Phase 0 we rely on the atomic semantics. ADR revision
  in M0.6 may add property tests.

Adversary capabilities **not** addressed in Phase 0:

- **TLS man-in-the-middle of the tunnel.** CONNECT is opaque after
  the 200 response; the proxy does not decrypt, modify, or inspect
  the tunneled bytes. This is by design — the scanner does its own
  TLS, and the proxy is the network boundary, not a content
  inspector.
- **Local side-channels.** A compromised local process that owns
  the same workspace key bypasses the proxy by signing its own
  scope manifests. Mitigation requires per-component sandboxing
  (WASM plugin runtime in Phase 2, microVM isolation for live
  exploits — neither is part of M0.3).
- **TOCTOU between DNS resolve and TCP dial.** The OS resolver may
  cache an answer for milliseconds before our dial; if the resolver
  is malicious, it could return an in-scope IP for the resolve and
  then have routing redirect the dial elsewhere. We don't defend
  against routing-layer attacks. A future ADR may add per-IP scope
  checks (a strict subset of the named-host scope) when the
  operator wants this level of paranoia.
- **Plain HTTP / WebSocket / gRPC / HTTP/2.** The Phase 0 proxy
  speaks HTTP/1.1 CONNECT only. Other protocols return 400 at the
  parser level, so the boundary holds, but functionality is
  restricted.
- **Listener-port exposure to other local users.** The proxy binds
  to `127.0.0.1:0` by default; a different local user (different
  UID) cannot reach it on most platforms, but on Windows there is
  no UID-based isolation by default. Operators on Windows
  multi-user systems should bind to a Unix-domain-equivalent
  named pipe (planned as a configuration option in M0.6).

### Where the proxy DOES NOT enforce

The proxy is one boundary. The following are explicitly someone
else's job:

- **Per-engagement isolation in storage.** The event store and the
  scope evaluator are scoped to a single engagement at proxy
  construction time. Running multiple engagements concurrently
  requires multiple proxy instances. The daemon (M0.4) wires this
  up; the proxy itself is single-engagement.
- **Workspace key custody.** ADR-0006 handles this.
- **TLS server-certificate validation.** That's the scanner's job.
  The proxy connects to the IP the scanner asked for via CONNECT;
  validating the certificate presented over the tunnel is the
  scanner's concern.
- **Rate limiting beyond the budget envelope.** Coarse rate limit
  is part of `BudgetEnvelope`. Fine-grained TCP-level shaping or
  exponential backoff on errors is not part of Phase 0.

### Verification

12 tests in `mantis-egress` exercise:

- 6 unit tests on the CONNECT parser (IPv4, IPv6, malformed, missing
  port, non-CONNECT methods).
- 6 integration tests against a real in-process echo server:
  - `in_scope_connect_to_localhost_target_succeeds` — confirms a
    successful tunnel and that the bytes flow end-to-end.
  - `out_of_scope_host_returns_403` — confirms 403 and that the
    event log records the deny.
  - `malformed_request_returns_400` — confirms parser-level
    rejection.
  - `budget_exhaustion_returns_429` — confirms 429 after exhausting
    a 1-request budget.
  - `suffix_attack_hostname_rejected` — confirms per-label glob
    integration.
  - `http_protocol_disallowed_when_only_https_in_scope` — confirms
    the protocol axis of the scope evaluator is honored.

A manual red-team pass against the proxy is part of the M0.6 cut
list — at minimum, run `nuclei` and `gobuster` against an instance
configured with a deliberately tight scope and confirm no
out-of-scope dials in the event log.

## Alternatives considered

1. **Full HTTP/2 forward proxy.** Higher implementation cost; not
   needed for Phase 0 because scanners speak HTTP/1.1. Deferred.
2. **WireGuard / SOCKS5 frontend** instead of HTTP CONNECT. Strictly
   more general. Rejected for Phase 0 because tooling (curl,
   reqwest) speaks HTTP CONNECT natively without additional setup,
   and the security analysis is simpler.
3. **Kernel-level egress filtering via nftables/pf.** Effective on
   Linux/BSD. Rejected because Mantis must run cross-platform
   (Windows + macOS via the same binary). Userspace proxy is the
   portable answer.

## Consequences

- **+** A single, auditable, sub-200-LOC parser and
  ~250-LOC proxy core form the entire network surface of the
  Mantis daemon. Any future component can be checked for direct
  network access by looking at its dependency graph; if it doesn't
  depend on `mantis-egress`, it cannot reach the network.
- **+** Bypass-resistance is testable. Adding a new property test
  is one function in `tests/integration.rs`.
- **−** The proxy is a per-connection async task. At very high
  fanout (>10k concurrent connections) the proxy's overhead
  becomes visible. Phase 1 perf work may move it to `tokio-uring`
  on Linux.
- **−** Plain HTTP forwarding is not yet supported, so engagements
  against plain-HTTP targets cannot run in Phase 0. Operators must
  scope to HTTPS only until the M0.5+ plain-HTTP path lands.
