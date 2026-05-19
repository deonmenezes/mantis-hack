---
description: One-shot Mantis pentest. `/mantishack target.com` runs the whole pipeline — discover, signup, enumerate, auth-diff, archive — with no flags.
allowed-tools: Bash, Read
argument-hint: target.com or https://app.example.com/
---

```
███╗   ███╗ █████╗ ███╗   ██╗████████╗██╗███████╗
████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝
██╔████╔██║███████║██╔██╗ ██║   ██║   ██║███████╗
██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██║╚════██║
██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝

    stalk · wait · strike · hold
    ethically hack and discover vulnerabilities in any software with the power of AI
```

# `/mantishack`

The simple-as-`/bob-hunt` command. Takes one positional argument and runs everything: auto-discover the target's auth stack, sign up an attacker + a victim, enumerate endpoints, run the auth-differential against every endpoint, archive findings under `./reports/<host>/`.

This is the Mantis equivalent of hacker-bob's `/bob-hunt target.com`.

## Authorization gate

**Before running**, ask the user:

> Do you have **explicit written authorization** to run offensive-security tests against `$ARGUMENTS`?

If the answer is anything other than a clear yes, refuse and stop. Do not proceed.

## Scope confirmation

Print the target and confirm. For a bare domain, mention Mantis will probe `https://<domain>/` by default; for an `http://localhost:N` target, Mantis will use plain HTTP. For a packaged-app path, refer the user to `mantis pentest` (the older single-pass path) — `mantis hack` is web-target only.

## Run

```bash
# Run the pipeline. Mantis auto-discovers Supabase config from the
# target's HTML; if found, it signs up attacker + victim accounts
# and runs the full auth-diff. Otherwise it runs an unauth-only diff.
mantis hack "$ARGUMENTS" --i-have-authorization
```

The command emits `[mantishack]` progress lines for each phase:

1. `phase 1/3: auto-discover` — fetches the target HTML + first few JS bundles, scans for `*.supabase.co` URLs and Supabase anon JWTs (`eyJhbGciOi…`).
2. `phase 2/3: signup + enumerate + auth-diff` — signs up an attacker + victim with disposable emails, runs the 100-candidate endpoint enumerator, replays each candidate under (unauth, attacker, victim) profiles, classifies divergence.
3. `phase 3/3: archive written under ./reports/<host>/AB-<id>/` — every finding gets its own markdown file plus a consolidated `vulnerability-report.md` and per-phase logs.

Stream the output as it runs.

## Overrides (rarely needed)

- `--supabase-signup URL` if the discovered URL is wrong.
- `--supabase-apikey KEY` if the anon key isn't in the page HTML.
- `--attacker-profile PATH --victim-profile PATH` to skip signup entirely with BYO `AuthProfile` JSON (matches `mantis-auth::AuthProfile`). Use this for non-Supabase targets.
- `--extra-path /api/...` to add target-specific paths on top of the built-in wordlist.
- `--max-candidates N` / `--max-endpoints-probed N` to widen or narrow the sweep. Default is 100/100.

## After it completes

Print the archive path Mantis emits and offer to:

- Open the README — `open ./reports/<host>/AB-<id>/README.md`
- Open the full vulnerability report — `open ./reports/<host>/AB-<id>/vulnerability-report.md`
- Re-render via the daemon's report tool for PDF / HackerOne / SARIF — `mantis engagement report <id> --format pdf`

## Refuse to run if

- No written authorization for the target.
- The target overlaps a public service the operator does not control (shared SaaS, public CDN).
- The user supplies an exploit primitive scope requesting destructive actions beyond the legitimate test boundary.

Mantis enforces scope cryptographically at the egress proxy when run through the daemon. The legal gate is yours.

---

## Mantis runtime notes

This command drives the Rust `mantis-daemon` over gRPC when it's running; falls back to in-process when the daemon is offline. Engagement state, event log, and scope enforcement live in the daemon — not in this CLI's process. To diagnose, run `mantis doctor`. The daemon binds `127.0.0.1:50451` by default.

The full chain is implemented in `crates/mantis-orchestrator` (Rust); the auto-discovery lives in `crates/mantis-orchestrator/src/discover.rs`; the auth-differential classifier is in `crates/mantis-auth-differential`; the per-target archive layout is in `crates/mantis-orchestrator/src/archive.rs`.
