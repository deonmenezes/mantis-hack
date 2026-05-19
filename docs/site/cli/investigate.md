# `mantis investigate`

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

Flexible variant of `mantis hack` that takes any subject — URL, file, or prompt — and **drives the full 7-phase FSM** with that subject as priority investigation context. Falls back to a read-only static investigation when no live target / no auth is present.

## Synopsis

```sh
mantis investigate <subject> [--i-have-authorization] [OPTIONS] [-- <claude args>...]
```

`<subject>` auto-classifies into one of three subject types, then the resolver decides whether to drive the FSM or run a read-only static investigation:

| Subject | Subject type | Target URL? | With `--i-have-authorization` | Without |
|---|---|---|---|---|
| `https://…` / `http://…` | **URL** | itself | **FSM** drives the engagement | hard-fails (refuses) |
| Path to an existing file | **File** | first URL found in the file body, if any | **FSM** with file as priority context | static read-only |
| Anything else | **Prompt** | first URL found in the prompt text, if any | **FSM** with the question as priority context | static read-only |

When the FSM fires, it is the same orchestrator role body and gates that `mantis hack` uses (RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT) — including the parallel hunter fan-out, the 3-round verifier cascade, and the `adjudication_plan_hash` binding. The only difference is that the operator's investigation seed is inlined as priority context in the system prompt: hunter briefs weight it, chain-builder searches for chains that confirm or refute it, the grader foregrounds findings that bear on it.

When the FSM does **not** fire (no target URL, or auth flag missing on a file/prompt with an embedded URL), `mantis investigate` falls back to a read-only mode that uses MCP read tools (`mantis_read_findings`, `mantis_read_chain_attempts`, …) + `Read` / `Grep` and the leaf utility tools, but issues no HTTP traffic and creates no engagement.

## Examples

### Investigate a specific URL (FSM)

```sh
mantis investigate https://app.example.com/api/users/42 --i-have-authorization
```

Drives the full FSM with that URL as the engagement target. RECON enumerates the surface, AUTH captures profiles, HUNT spawns hunters (at least one rooted at `/api/users/42`), CHAIN composes findings, the 3-round VERIFY cascade re-proves them, GRADE scores, REPORT renders.

### Audit a file that references a URL (FSM)

```sh
mantis investigate ./suspicious-finding.md --i-have-authorization
```

If the file mentions `https://app.example.com/…`, the FSM fires against that target with the file body inlined as priority context. Hunter briefs cross-reference the file's claims against the live surface.

### Static-only audit (no URL in file)

```sh
mantis investigate ./src/auth/session.ts
```

No target URL → static read-only pass: looks for hardcoded secrets, unsafe patterns, broken auth checks, missing input validation, SQL injection / SSRF / RCE primitives, mass-assignment risks. Reports ranked findings.

### Chase a hunch about an existing engagement

```sh
mantis investigate "the IDOR finding F-3 — does it actually compose into ATO via OAuth state confusion?"
```

No URL → static read-only path. The orchestrator reads `mantis_read_findings`, walks chain attempts, and reports whether the hypothesis holds.

### Investigate a hunch about a live target (FSM)

```sh
mantis investigate "F-3 looks like ATO via state confusion against https://oauth.example.com/callback" --i-have-authorization
```

URL is extracted from the prompt → FSM drives against `https://oauth.example.com/callback` with the hunch as priority context.

## Options

| Flag | Default | What |
|---|---|---|
| `--i-have-authorization` | required for URL only | Self-attestation. The legal gate. |
| `--daemon <url>` | `http://127.0.0.1:50451` | Daemon gRPC endpoint. Honors `MANTIS_DAEMON`. |
| `--claude-bin <path>` | _from PATH_ | Override the `claude` binary. Honors `MANTIS_CLAUDE_BIN`. |
| `--output-format text\|json` | `text` | `text` streams pretty events to stderr; `json` streams raw stream-json to stdout. |
| `-- <claude args>...` | — | Forwarded verbatim to the spawned `claude --print`. |

## What's available inside

The investigator system prompt enumerates every tool and agent:

**MCP tools** — all `mcp__mantis__*` tools registered with the daemon (read findings, scan, audit, fetch source, run foundry / halmos / anchor, score, dedupe, decode JWT, diff responses, summarize URL, extract secrets / forms / links, …).

**Sub-agents** spawnable via `Task`:

- `recon-agent`, `deep-recon-agent`, `surface-router-agent`
- `hunter-agent`, `hunter-evm-agent`, `hunter-svm-agent`, `hunter-move-agent`, `hunter-substrate-agent`, `hunter-cosmwasm-agent`
- `chain-builder`
- `brutalist-verifier`, `balanced-verifier`, `final-verifier`
- `evidence-agent`, `grader`, `report-writer`

**What it WON'T do:**

- Shell out to `mantis hack` / `mantis investigate` / `mantis pentest` (anti-recursion guard — `mantis` spawned the running `claude`).
- Issue offensive HTTP traffic in static mode (no target / no auth).
- Skip the FSM when a target + auth are both present — this is the point of `mantis investigate`, not the exception.

## Inside the REPL

The bare-`mantis` REPL accepts `/investigate <subject>` as a slash command. Typing a URL implicitly attaches `--i-have-authorization` (the in-session attestation), so:

```
mantis> /investigate https://app.example.com/api/users
```

dispatches to `mantis investigate https://app.example.com/api/users --i-have-authorization`.

## Run log

Every event the spawned `claude` emits is recorded to a pretty markdown ledger (`./logs.md` by default; override with `MANTIS_LOG_FILE`). See [`mantis prompt`](./prompt.md#run-log) for the schema.

## See also

- [`mantis hack`](./hack.md) — full FSM engagement
- [`mantis prompt`](./prompt.md) — one-shot ad-hoc prompt
- [`mantis goal`](./goal.md) — goal-directed multi-wave engagement
