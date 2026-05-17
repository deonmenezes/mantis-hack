# ADR-0015: MCTS planner (Phase 1 M1.3)

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M1.3

## Context

PRD §5.5 mandates Monte Carlo Tree Search over the attack graph
with UCB1 selection over Bayesian posteriors. Phase 0 shipped the
surface discovery + hypothesis catalog + primitive catalog; M1.3
adds the planner that decides *which primitive to run next against
which surface*. Without a planner, the daemon's `Engagement.Scan`
runs every primitive against every surface in catalog order — a
fixed-policy strategy that wastes budget on unlikely hits and
misses high-value ones.

## Decision

### Two-level tree

For Phase 1, the search tree has exactly two levels under root:

```
                root
                /  \
       surface-A   surface-B   ...
        /    \       /    \
   prim-X prim-Y  prim-X prim-Z   (leaves = (surface, primitive))
```

Each leaf is an `(surface_key, primitive_id)` pair the planner can
emit as the next action. Phase 2's chain-exploit work will push
the tree deeper (each chain step becomes a level), so the
representation is general enough to extend.

### Selection: UCB1

Standard UCB1 with `c = sqrt(2)` (configurable):

```
score(child) = mean_reward(child) + c * sqrt(ln(N) / n)
```

Where `N` is the sum of all children's visit counts at this level
(matching the textbook formulation where total pulls includes
prior-as-virtual-visits) and `n` is the child's own visit count.

Unvisited children return `f64::INFINITY` so they're picked
before any visited arm.

### Prior-as-virtual-visit

Each leaf starts with `(visits = 1, total_reward = prior_pp10k /
10_000)`. One virtual observation breaks the all-arms-infinite tie
among brand-new actions, but is light enough that UCB1's
exploration term still kicks in after a handful of real outcomes.
Stronger virtual priors (e.g. 10 virtual visits) drowned out
exploration in property tests; the single virtual visit lands the
right balance.

Higher prior arms get picked first when all else is equal — proven
by the `higher_prior_arm_explored_first` integration test.

### Reward model

`record_outcome(action_id, reward)` takes `reward in [0, 1]`. By
convention:

- `1.0` if the verifier confirmed the resulting claim.
- `0.0` if the verifier rejected or the primitive returned Denied.
- The daemon may use intermediate values for Retained (e.g. 0.2)
  to encode partial-credit signal — Phase 1 sticks with binary
  Confirmed/Not-Confirmed.

Reward is backpropagated through three nodes: the leaf, its surface
parent, and the root.

### Action registration

`register_action(surface_key, primitive_id, prior_pp10k)` is
idempotent on `(surface_key, primitive_id)` — re-registering the
same pair returns the same `ActionId` without resetting visits.
The daemon registers actions when:

- A new surface is discovered (one action per applicable primitive).
- A new primitive ships (re-register actions for existing surfaces).

### What's deferred

- **Bayesian posterior update (M1.4)** — the static priors from
  the hypothesis catalog will be replaced by per-(stack,
  vuln_class) Beta posteriors derived from historical outcomes.
  The planner already accepts arbitrary `prior_pp10k`, so M1.4 is
  a "feed updated priors to register_action" change with no tree
  structure changes.
- **RAVE (Phase 2)** — cross-arm credit assignment when two arms
  test related vulnerabilities on related surfaces.
- **Progressive widening (Phase 2)** — when the action space grows
  past hundreds of arms per surface, we'll expand children
  gradually based on parent visits.
- **Information gain optimization (Phase 2)** — the current
  reward is a flat 0/1 success rate. Phase 2 weights by request
  cost so high-cost-but-low-success primitives are penalized.

### Caller responsibilities

The planner is pure data — it does not run primitives, does not
talk to the network, does not access the event store. The daemon
(M1.7) drives the loop:

```rust
loop {
    let Some(action) = planner.next_action() else { break };
    let claim = run_primitive(action.primitive_id, action.surface_key).await?;
    let reward = match verify_claim(&claim).await? {
        ClaimState::Verified { .. } => 1.0,
        _ => 0.0,
    };
    planner.record_outcome(action.id, reward);
    if budget.exhausted() { break }
}
```

## Alternatives considered

1. **Pure Thompson sampling.** Mentioned in PRD §10.1 for surface
   prioritization. Considered. Rejected because UCB1's per-arm
   confidence-interval semantics give the operator a clear
   "this arm is being explored" story; Thompson's sampling is
   harder to introspect.
2. **Single-level multi-armed bandit** (no surface level).
   Simpler. Rejected because grouping by surface lets us run
   "give every surface a fair shot" easily (the root → surface
   selection is itself UCB1) and matches PRD's tree shape.
3. **Three-level tree** (surface → vuln_class → primitive).
   Could give better cross-primitive sharing within a class.
   Deferred — Phase 1 M1.4's Bayesian layer is keyed on (stack,
   vuln_class) so the class signal lives there.

## Consequences

- **+** Daemon can now use `planner.next_action()` instead of
  iterating the primitive catalog. Budget burns on the most
  promising leaves first.
- **+** Property-tested: the planner converges visit count to the
  highest-reward arm given different true reward rates
  (`planner_concentrates_on_high_reward_arm`).
- **+** Prior-aware: a high-prior arm gets explored first, all
  else equal (`higher_prior_arm_explored_first`).
- **−** The planner does no persistence yet. A daemon restart
  loses the search tree. Phase 2 will serialize the tree (via
  the `serde` derives on `NodeId` / `ActionId`) into the event
  store so engagements resume their search where they paused.
- **−** UCB1 with virtual-visits-as-prior is a workable
  approximation but not a Bayesian update. The Beta posterior
  approach in M1.4 is strictly better — it updates the prior
  with each observation in closed form. The planner accepts
  whatever priors the caller supplies, so M1.4 is a feeder
  change, not a planner rewrite.

## Verification

7 tests in `mantis-planner`:

- Empty planner returns None.
- `register_action` is idempotent and stable.
- UCB1 explores other arms after one does poorly.
- Planner concentrates visits on the highest-reward arm given
  three arms with true rates 0.8 / 0.4 / 0.1 (300 iterations,
  deterministic xorshift PRNG for reward sampling).
- Planner gives every surface at least one visit (the surface-
  level UCB1 doesn't starve any surface).
- The emitted `Action` carries the surface_key and primitive_id
  as references the caller can use directly.
- Higher-prior arm is explored first when both arms are
  otherwise identical.

Plus 4 unit tests in `ucb1.rs` (unvisited = infinite, exploit
dominates at c=0, reward ordering, visit ordering).
