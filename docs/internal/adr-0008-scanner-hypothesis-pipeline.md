# ADR-0008: Scanner + hypothesis pipeline

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M0.5

## Context

PRD §5.3 / §5.4 describe the reconnaissance + hypothesis-generation
loop: scanners discover surfaces, a generator proposes falsifiable
hypotheses with priors, and the planner picks experiments based on
those hypotheses. M0.5 ships the first two pieces in their Phase-0
form (no MCTS planner yet, no Bayesian update — those land in
Phase 1).

## Decision

### Scanner architecture

`mantis-scanner-http` provides:

- [`HttpProbeScanner::probe(target)`] — one HTTP GET against a
  target, captures status, Server header, Content-Length, and a
  small tech-hint vector. Writes one [`EventKind::SurfaceDiscovered`]
  event per probe.
- [`HttpProbeScanner::probe_all(targets)`] — sequential probe over
  a list; per-target errors are logged and skipped (the loop
  continues so a single dead target does not abort the run).

The scanner uses `reqwest` configured with:

- `rustls-tls` (no openssl dependency on any platform).
- `Policy::none()` for redirects (we want to record the immediate
  response, not the chased-to destination).
- `danger_accept_invalid_certs(true)` (engagements routinely target
  self-signed and expired-cert services; the operator is responsible
  for cert handling).
- Optional proxy URL — when set, every request CONNECTs through the
  Mantis egress proxy. In production this is always set; in tests
  it's typically `None` so the scanner can hit a localhost mock
  directly (the egress proxy's Phase-0 CONNECT-only path doesn't
  yet handle plain HTTP — see ADR-0004's deferred work).

### Hypothesis generator

`mantis-hypothesis::generate(surface)` runs the surface through a
catalog of pure functions, each of shape `fn(&Surface) -> Option<HypothesisData>`.
Adding a new rule is appending one entry to `RULES`. The Phase 0
catalog has 12 rules covering:

- Server-header pattern matches (nginx, Apache, IIS).
- Sensitive path patterns (admin, dashboard, API, login).
- Status-code branches (401, 403, 5xx).
- Content-type signals (HTML→XSS, JSON→IDOR).
- Header disclosure (X-Powered-By, etc.).

Each rule emits a [`HypothesisData`] with:

- `vuln_class` — short tag for grouping (e.g. `idor`, `xss-reflected`,
  `broken-access-control`).
- `summary` — human-readable, includes the URL.
- `prior_pp10k` — prior probability in parts per 10,000 (basis
  points). Static for Phase 0; ADR-0002's no-floats-in-events rule
  is the reason for the integer encoding.

### Why static priors

Phase 0 priors are derived from "common patterns in disclosed
reports" rather than measurement. They are a placeholder for the
real Bayesian posteriors that M0.5b will introduce. Once a workspace
has run a few engagements, the planner will fit per-class hit-rate
distributions and overwrite the static priors on a per-workspace
basis (PRD §5.4.2).

### Event variants added

```rust
EventKind::SurfaceDiscovered {
    host: String,
    port: u16,
    scheme: String,
    path: String,
    status: u16,
    server: Option<String>,
    content_length: Option<u64>,
    tech_hints: Vec<String>,
}
EventKind::HypothesisGenerated {
    surface_id: String,     // ULID-ish; produced by event index
    vuln_class: String,
    summary: String,
    prior: u32,             // parts per 10,000
}
```

These are non-breaking additions (per ADR-0002 schema-versioning
rules); existing consumers ignore unknown variants.

## Alternatives considered

1. **Use `hyper` directly instead of reqwest.** Smaller dep tree,
   more control. Rejected: reqwest's proxy support is what we need;
   reinventing it would be a substantial M0.5b cost for no
   visible benefit yet.

2. **Async-parallel probing via `tokio::spawn` per target.** Faster
   for large target lists. Rejected for Phase 0: the egress proxy's
   budget tracker enforces request rate as a hard limit, and
   sequential probing makes the rate easy to reason about. Phase 1
   adds concurrent probing with the budget tracker as the throttle.

3. **Yaml-defined rule catalog** instead of in-code rules. Easier
   to add rules without recompiling. Rejected for Phase 0: every
   new rule needs unit tests, which is awkward to express in YAML.
   M0.6+ may revisit if the rule count grows past ~50.

4. **Generate hypotheses inside the scanner.** Couples two concerns
   that benefit from separation. Rejected: the scanner produces
   surfaces, the hypothesis crate consumes surfaces. The planner
   (Phase 1) will sit between them.

## Consequences

- **+** Scanner produces real events with real fingerprint data
  that downstream code (planner, reports) can act on.
- **+** Hypothesis catalog is unit-tested per rule — adding a rule
  forces adding a test.
- **+** Static priors are honest about being placeholders. The
  Bayesian layer in M0.5b will plug in without changing the event
  schema (the `prior` field is already an integer).
- **−** The scanner currently bypasses the egress proxy in tests
  (and in any production setup where the operator doesn't pass a
  proxy URL). The type system doesn't enforce proxy-required.
  Mitigation: M0.6 hardening pass adds a `ProductionMode` flag that
  refuses to construct a scanner without a proxy URL.
- **−** No content-discovery scanner yet (the directory-bust /
  wordlist case from PRD §5.3.4). That's M0.5b.
- **−** No response-shape clustering (the soft-404 case from
  PRD §5.3.4). That's M0.5b too.

## Verification

- 4 integration tests in `mantis-scanner-http` exercise the probe
  flow against a fake HTTP server, including the
  "skip-broken-targets" property.
- 7 unit tests in `mantis-hypothesis` exercise each major rule
  branch and the prior-ordering invariant.
- Manual exercise via `mantis daemon` + a future
  `mantis engagement scan` subcommand (M0.5b ships the latter).
