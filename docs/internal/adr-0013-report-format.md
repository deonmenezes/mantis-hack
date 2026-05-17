# ADR-0013: Report format (Markdown)

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M1.5

## Context

PRD §5.9 requires reports in six formats: Markdown, PDF (Typst),
HackerOne JSON, Bugcrowd JSON, SARIF, OpenVEX. Phase 1 ships
Markdown — the operator-facing baseline — and defers the other
five to later milestones.

## Decision

### Crate layout

`mantis-report` is a no-I/O library crate. `Report::to_markdown()`
takes a `ReportMetadata` plus a slice of `Claim`s and returns a
`String`. The caller (CLI, daemon, future report-export RPC)
decides where the bytes go.

### Report structure

```markdown
# Mantis Engagement Report
- Engagement: <id>
- Name: <name>
- Operator: <name>
- Generated at: <unix ts>
- Workspace fingerprint: <hex>

## Summary
- Verified findings: N
- Rejected by verifier: M
- Retained (verifier inconclusive): K

## Findings

### Finding 1: <Pretty Class Name> on <url>
- Vulnerability class: <class>
- Primitive: <primitive_id>
- Severity: <Critical|High|Medium|Low|Informational>
- Verified by: <verifier_id>

**Evidence**
- `<kind>`: <detail>
- ...

**Reproducer (cURL)**
```bash
<curl one-liner>
```

**Reproducer (raw HTTP)**
```http
<HTTP/1.1 request>
```

**Reproducer (Python)**  (when present)
```python
<requests snippet>
```

---

(more findings, severity-descending order)

## Appendix: claims not reported
### Rejected by verifier (M)
- <primitive> on <url> — <reason>

### Retained (verifier inconclusive, K)
- <primitive> on <url> — <reason>
```

### Severity table (Phase 1 placeholder)

```
sqli, rce, deserialization                 → Critical
auth-bypass, broken-access-control,
  idor, ssrf, xxe                          → High
xss-reflected, xss-stored, open-redirect,
  csrf, weak-auth                          → Medium
info-disclosure, missing-security-headers,
  clickjacking                             → Low
api-enumeration, *-recon                   → Informational
unknown vuln_class                         → Informational
```

Phase 2 swaps this for CVSS v4 vectors authored per primitive.

### What appears where

- **`Verified` claims** become numbered findings, sorted by
  severity descending (within a severity, original event order).
- **`Rejected` claims** go in the appendix with the verifier's
  reject reason — they're visible for transparency but explicitly
  not reportable per ADR-0012.
- **`Retained` claims** go in the appendix with the verifier's
  inconclusive reason — operators decide whether to chase them.
- **`Pending` claims** are silently omitted. A `Pending` claim in
  a generated report indicates a daemon bug (the report ran
  before the verifier did) but does not corrupt the output.

### Merkle proof embedding

Phase 1 does not yet embed inclusion proofs in the Markdown body.
The proof bytes are too long to inline as Markdown without
inviting copy-paste corruption, and the daemon's
`Engagement.Export` JSONL already carries them. M1.6 adds an
appendix section listing one Merkle proof per finding, formatted
as Base64-wrapped 76-column lines, plus instructions to verify
with the standalone `mantis-verify` binary.

## Alternatives considered

1. **Inline Merkle proofs in every finding.** Heavyweight and
   noisy; the proofs are megabytes for long engagements. Rejected
   — keep the Markdown human-readable.
2. **Use a templating engine** (Tera, Askama) instead of `write!`.
   Tempting for the larger formats (PDF/SARIF) but overkill for
   Markdown. Phase 1 inlines the format; later milestones may
   refactor to templates if the format diverges per disclosure
   program.
3. **CVSS v4 calculation in Phase 1.** Would require per-primitive
   CVSS vector authoring before any finding renders. Rejected —
   the severity table is a serviceable placeholder; the structure
   that consumes severity (sort + display) is the same shape
   either way.

## Consequences

- **+** Operator can run an engagement and get a report-ready
  Markdown file. Closes the original M0.5 "export bundle" loop
  with much higher signal.
- **+** Severity table is one small file; adding a new vuln class
  is a one-line addition with a unit test.
- **+** No I/O in the crate — easily unit-testable, no special
  setup.
- **−** Five report formats from PRD §5.9.1 still unbuilt.
  Schedule:
  - M2.0 — PDF via Typst (operator-facing polish).
  - M2.1 — HackerOne JSON, Bugcrowd JSON (disclosure-program
    integrations).
  - M2.2 — SARIF (security-tooling interop).
  - M2.3 — OpenVEX (vulnerability exchange).
- **−** No Merkle proof in body yet. Appendix lands in M1.6.

## Verification

- 4 unit tests in `severity.rs`: rank ordering, known/unknown
  class mapping, Display.
- 6 integration tests in `mantis-report`:
  - Empty report renders sane "no findings" output.
  - Single verified claim produces all expected sections.
  - Findings sort by severity descending across mixed claims.
  - Rejected/Retained populate appendix with reasons.
  - Pending claims are silently omitted.
  - Metadata fields render in the header.
