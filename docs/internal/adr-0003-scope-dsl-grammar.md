# ADR-0003: Scope DSL grammar

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M0.3

## Context

PRD §5.2 mandates a signed scope manifest declaring include/exclude
patterns for hosts, paths, ports, and protocols. PRD §5.2.3 requires
the egress proxy to enforce scope at the socket layer, after DNS
resolution but before TCP dial. The grammar of the manifest is the
most under-specified part of the PRD — it has to be nailed down
before the egress proxy can rely on it.

This ADR pins the grammar, the canonical signing input, and the
evaluation semantics. Once accepted it is immutable; later additions
require a `schema_version` bump.

## Decision

### YAML schema (`schema_version: 1`)

```yaml
schema_version: 1
engagement_id: 01HXXXXXXXXXXXXXXXXXXXXXXX        # ULID
authorized_by: 01HYYYYYYYYYYYYYYYYYYYYYY1        # operator ULID
expires_at_unix: 1900000000                       # UTC seconds since epoch
budget:
  max_requests: 100000
  max_egress_bytes: 1073741824                   # 1 GiB
  max_wall_clock_seconds: 86400                  # 1 day
  max_requests_per_second: 50
include:
  hosts: ["api.example.com", "*.example.com"]
  ports: [443, "8000-9000"]
  paths: ["/api/**"]
  protocols: [https]
exclude:
  paths: ["/admin/**", "/internal/**"]
  hosts: ["staging.example.com"]
```

`exclude` is optional and defaults to all-empty.

### Field semantics

- **`hosts`** — list of host patterns. Wildcards: `*` matches any
  characters within a single DNS label; `?` matches one character.
  Wildcards do not span dots. A bare `*` matches anything. Pattern
  matching is anchored — the entire host must match.

- **`ports`** — list of `u16` ports or `"low-high"` inclusive ranges.
  Mixed in the same list.

- **`paths`** — list of glob patterns evaluated against the request
  path. `*` matches any characters except `/`. `**` matches across
  separators.

- **`protocols`** — list of `http` or `https`. Future schema versions
  may add `ws`, `wss`, `grpc`, etc.

- **`expires_at_unix`** — seconds since epoch. The egress proxy
  refuses requests at or after this timestamp.

- **`budget`** — see ADR-0007 / `BudgetEnvelope`. Hard limits enforced
  by the egress proxy.

### Evaluation rule

Given a `ScopeQuery { host, port, path?, protocol }`:

```
in_scope iff
    (include.hosts is empty OR any host pattern matches)
  AND (include.ports is empty OR any port matcher matches)
  AND (path missing OR include.paths is empty OR any path pattern matches)
  AND (include.protocols is empty OR protocol is in include.protocols)
  AND (exclude.hosts does not match host)
  AND (exclude.ports does not match port)
  AND (path missing OR exclude.paths does not match path)
  AND (exclude.protocols does not contain protocol)
```

Empty `include` axis means "match any value on this axis". This lets
callers omit axes they don't care about — e.g. only set hosts and
protocols if ports and paths don't matter. Empty `exclude` axis
matches nothing (no exclusion). This asymmetry is deliberate.

### Canonical signing input

The manifest YAML is the persisted form, but YAML allows multiple
equivalent encodings of the same data. The canonical input to the
signing routine is `serde_json::to_vec(&manifest)`, which is
deterministic for the schemas we use (no `HashMap` anywhere — all
maps are flat structs with declared field order).

Domain separation context: `"scope"`. The full sign input is
`b"Mantis-v1:scope:" || serde_json::to_vec(&manifest)`.

### DNS resolution is the producer's job

A scope manifest names *hosts*, not *IP addresses*. DNS resolution
happens at egress-proxy connect time. The proxy is responsible for:

1. Resolving the requested hostname to an IP.
2. Storing the resolved IP in the connection metadata.
3. Performing the dial against that IP.

The scope evaluator only consumes the requested hostname. It does
not see IPs. This means DNS rebinding cannot bypass scope: the
hostname-to-IP mapping at dial time is captured by the proxy and
re-checked on every subsequent connection. Future ADRs (M0.3 egress
proxy threat model, ADR-0004) document this in detail.

## Alternatives considered

1. **Bash-like glob with separator-spanning `*`.** Rejected for the
   host axis because of the suffix-attack class: a producer who wrote
   `*.example.com` would unintentionally match
   `evil.example.com.attacker.tld`. Per-label `*` semantics avoid
   this.

2. **Regular expressions instead of globs.** Rejected. Globs are
   simpler to write correctly and harder to introduce
   ReDoS-attackable patterns. Few real engagements need regex
   features; if one does, schema v2 can add a `host_regex` field.

3. **CIDR-based scope.** Considered for engagements scoped to
   networks rather than hosts. Rejected for v1 since most authorized
   engagements are named by host. v2 can add `cidrs: [...]` once the
   need is concrete.

4. **One field per axis instead of `include` / `exclude`
   sub-objects.** E.g. `include_hosts`, `exclude_hosts`. Considered.
   Rejected because `include` / `exclude` grouping makes the
   semantics obvious from the YAML shape and makes empty exclude
   sections trivial.

5. **Allow signed manifests to extend other signed manifests.**
   Tempting for shared engagement templates. Rejected for v1 —
   resolution order and trust delegation get complex fast, and we
   have no concrete need.

## Consequences

- **+** Producers and verifiers agree on a single deterministic
  signing input regardless of YAML formatting.
- **+** Per-label host glob avoids the suffix-attack class entirely.
- **+** Future schema additions are explicit via `schema_version`,
  and `MANIFEST_SCHEMA_MAX` guards against unknown future versions.
- **−** Per-label glob is slightly less flexible than a free-form
  glob; some patterns become more verbose (`a.b.example.com` instead
  of `**.example.com`). Mitigation: document the common patterns in
  the operator-facing scope guide (Phase 4 web UI's docs section).
- **−** No support yet for IP-CIDR scope or per-method (GET vs POST)
  scope. Both are likely v2 additions.

## Verification

- 33 unit tests in `mantis-scope` exercise port range parsing, host
  pattern matching (including the suffix-attack rejection),
  manifest YAML round-trip, signature round-trip (and tamper
  rejection), evaluator decisions on every include/exclude axis,
  exclude-overrides-include semantics, and budget tracking.
- Specific tamper tests include
  `signed::tests::tampered_manifest_fails_verify` and
  `signed::tests::wrong_public_key_fails_verify`.
- The egress proxy's threat-model ADR (ADR-0004, M0.3) will add
  property tests that hammer the evaluator with adversarial inputs
  and assert no out-of-scope decision is ever returned as
  `InScope`.
