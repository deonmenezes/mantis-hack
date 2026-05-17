# ADR-0016: Bayesian posterior update over static priors

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M1.4

## Context

The hypothesis catalog (ADR-0008) and the planner (ADR-0015) both
use static priors that come from "common in disclosed reports" rules
of thumb. PRD §5.4.2 mandates that those static priors get overlaid
by per-workspace empirical posteriors derived from real outcomes,
and that per-engagement evidence updates them online. M1.4 ships
the posterior layer without yet wiring it into the planner.

## Decision

### Beta posterior model

Each `(stack_fingerprint, vuln_class)` bucket holds a Beta(α, β)
distribution. α = successes + 1 (one virtual success prior), β =
failures + 1. Mean is α/(α+β); the credible interval is provided
via a Wilson-style normal approximation good enough for operator
display.

### Outcome encoding

- `Confirmed + Verified` → success (α += 1).
- `Confirmed + Rejected` → failure (β += 1).
- `Denied` → failure (β += 1).
- `Retained` (verifier inconclusive) → **excluded** from posterior
  updates. Retained outcomes aren't a clean signal; including them
  biases the posterior with non-deterministic noise. Per ADR-0012,
  Retained claims are kept for review but don't drive learning.

### Blending with static priors

Until a bucket has seen [`BLEND_THRESHOLD_OBSERVATIONS`] (= 10)
real outcomes, the planner-facing prior is a linear interpolation:

```
weight_posterior = observations / 10
weight_static    = 1 - weight_posterior
blended_pp10k    = round((posterior.mean() * weight_posterior
                          + static_pp10k/10000 * weight_static) * 10000)
```

This avoids the brand-new-bucket cold start where Beta(1, 1) = 0.5
would override sensible static priors like 100 (1%) for
information disclosure on a random surface.

### Storage

A `Posteriors` struct wraps `HashMap<(String, String),
BetaPosterior>` behind a `RwLock`. The store exposes:

- `posterior_for(stack, vuln_class)` — read.
- `record_outcome(stack, vuln_class, success: bool)` — write.
- `blended_prior(stack, vuln_class, static_pp10k)` — what the
  planner should use.
- `snapshot()` / `restore()` — for hibernation.

Persistence to disk lands in M1.7 (daemon integration). For Phase 1
M1.4 the store is in-memory and dies with the daemon.

### Integration with the planner

The planner (ADR-0015) accepts `prior_pp10k: u32` in
`register_action`. The daemon (M1.7) will compute the prior as:

```rust
let static_pp10k = hypothesis.prior_pp10k;
let stack = surface.tech_hints.first()
    .map(|s| s.as_str())
    .unwrap_or("unknown");
let prior = posteriors.blended_prior(stack, &hypothesis.vuln_class, static_pp10k);
planner.register_action(surface_key, primitive_id, prior);
```

The planner stays oblivious to the Bayesian machinery — it just
accepts whatever prior the caller computes.

## Alternatives considered

1. **Per-engagement posteriors only** (no workspace-level
   aggregation). Simpler but loses the "learn across engagements"
   PRD requirement. Rejected.
2. **Per-primitive posteriors** instead of per-vuln-class. Finer
   resolution but breaks when new primitives ship for an existing
   vuln class. Rejected.
3. **Full Beta-quantile credible interval** instead of the Wilson
   approximation. More accurate but adds a special-function
   dependency (`statrs` or hand-written `betainc`). The Wilson
   approximation is within ~3% of the true Beta interval for
   reasonable observation counts; the operator-display use case
   doesn't need more.
4. **Exponential decay** of old observations. Useful when target
   behavior changes mid-engagement. Deferred — Phase 3's
   evolutionary tuner is the right home for time-dependent
   reweighting.

## Consequences

- **+** Per-(stack, vuln_class) learning: a workspace that runs
  many engagements against nginx-fronted APIs will develop a
  realistic posterior for "info-disclosure on nginx" and the
  planner will deprioritize it once it's measurably uncommon.
- **+** Cold-start safety: brand-new buckets defer to the static
  prior until they've earned the right to override.
- **+** Independent of the planner — the posterior layer can be
  used elsewhere (the operator model in Phase 3 will key on the
  same buckets for "which claims this operator follows up on").
- **−** In-memory only for Phase 1. Daemon restart loses the
  posteriors. M1.7 fixes this.
- **−** No cross-workspace pooling (a fleet of operators can't
  share posteriors). PRD §5.11 promises this via cross-engagement
  memory — separate ADR in Phase 3.

## Verification

12 unit tests in `mantis-posterior`:

- Uniform Beta(1, 1) has mean 0.5.
- Success/failure shift mean appropriately.
- 100 successes → mean > 0.95.
- 50 successes + 50 failures → mean ≈ 0.5 (±5%).
- Observation count excludes the +1/+1 virtual prior.
- Credible interval brackets the mean.
- `blend_pp10k` uses static prior when no observations.
- `blend_pp10k` ignores static prior at threshold.
- `blend_pp10k` interpolates correctly mid-range.
- Store round-trip preserves per-bucket values.
- Snapshot + restore round-trip preserves all buckets.
- Separate keys are independent.
