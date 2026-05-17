# ADR-0014: Primitive catalog growth strategy

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M1.2

## Context

The primitive catalog will grow from 2 (Phase 1 M1.2) to 50+ over
the rest of the project. ADR-0011 pinned the trait shape; this ADR
pins the *process* for adding new primitives without the catalog
becoming a maintenance burden.

## Decision

### One primitive, one file, one verifier

Each new primitive lands as:

1. A single file at
   `crates/mantis-primitive/src/primitives/<name>.rs` containing
   the `impl Primitive`.
2. A matching verifier at
   `crates/mantis-claim/src/verifiers/<name>.rs` (typically same
   name).
3. The verifier registered in `verify_claim`'s dispatch match.
4. Integration tests in the respective `tests/integration.rs`.
5. One severity-table entry in `mantis-report/src/severity.rs`
   (if a new `vuln_class` is introduced).

The dispatch is currently a hand-coded `match` keyed on
`vuln_class`. Once the catalog passes ~20 entries, we'll switch
to a `LazyLock` registry keyed by `id`. Hardcoded match is
sufficient and forces the compiler to flag missing verifiers.

### Bundle, don't share

Each primitive's verifier is a sibling of the primitive, not a
shared utility. Even if two primitives could share a verifier,
keeping them separate:

- Forces the verifier to be genuinely independent of the
  primitive (the property ADR-0012 requires).
- Lets the verifier evolve independently when the primitive's
  payload shape changes.
- Keeps the dispatch match exhaustive — adding a primitive that
  forgets its verifier produces an `Err::NoVerifier` at runtime
  rather than silently doing the wrong thing.

### Naming

- Primitive id: `<vuln_class>.<specific-name>`, e.g.
  `info-disclosure.missing-security-headers`,
  `open-redirect.query-param`.
- Verifier id: `verifier.<primitive_id>`.
- Vuln class is the short tag used everywhere (rule catalog,
  severity table, report grouping).

### Phase 1 M1.2 deliverables

| Primitive | Verifier | Severity | Status |
|---|---|---|---|
| `info-disclosure.missing-security-headers` | `verifier.info-disclosure.missing-security-headers` | Low | done (M1.0) |
| `open-redirect.query-param` | `verifier.open-redirect.query-param` | Medium | done (M1.2) |
| `clickjacking.frame-ancestors` | TBD | Low | M1.2b |
| `cors.wildcard-with-credentials` | TBD | Medium | M1.2c |
| `idor.numeric-id-enumeration` | TBD | High | M1.2d |
| `xss-reflected.query-param-mirror` | TBD | Medium | M1.2e |
| `sqli.error-based` | TBD | Critical | M1.3 |

## Consequences

- **+** Catalog grows linearly with effort. No central registry to
  update beyond the dispatch match.
- **+** A new primitive cannot ship without its verifier — the
  dispatch is exhaustively matched.
- **−** The hand-coded dispatch will become unwieldy past ~20
  entries. The migration to a `LazyLock` registry is mechanical
  but needs to happen.

## Verification

- 3 new tests in `mantis-primitive/tests/integration.rs` for the
  open-redirect primitive (Confirmed on redirecting server,
  Denied on non-redirecting server, `matches_surface` filtering).
- The verifier dispatch in `mantis-claim` covers both
  `info-disclosure` and `open-redirect` and returns
  `Err::NoVerifier` for unknown classes (already tested in M1.1).
