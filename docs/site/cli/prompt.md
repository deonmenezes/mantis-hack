# `mantis prompt`

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

One-shot Claude-Code-style assistant invocation with the `mantis` MCP server already wired. No engagement, no scope manifest, no FSM — for ad-hoc questions, code summaries, recon-note triage, anything you'd otherwise pipe into `claude --print`.

## Synopsis

```sh
mantis prompt "<text>" [OPTIONS] [-- <claude args>...]
```

## What it does

1. **Pre-flight (parallel)** — checks daemon is up (best-effort), locates the `claude` CLI, verifies the `mantis` MCP server is registered, looks up `mantis-mcp` on PATH.
2. **Resolves the model** — uses the [model-resolution chain](./model.md#how-it-integrates-with-mantis-hack): CLI flag → `MANTIS_MODEL` → `.mantis.json` → `~/.Mantis/model` → claude default.
3. **Loads repo guidance** — if `MANTIS.md` exists in cwd (or any ancestor), its contents are appended to the system prompt so the agent sees your repo's scope / posture / do-not-touch list.
4. **Executes `claude --print`** with `--add-dir cwd` and the prompt you supplied. Stdio streams live.

The system prompt refuses to start an engagement without `mantis hack --i-have-authorization`, so this surface is safe for non-offensive questions.

## Options

| Flag | Default | What |
|---|---|---|
| `--daemon <url>` | `http://127.0.0.1:50451` | Daemon endpoint for MCP wiring. Honors `MANTIS_DAEMON`. |
| `--claude-bin <path>` | _from PATH_ | Override the `claude` binary. Honors `MANTIS_CLAUDE_BIN`. |
| `--output-format text\|json` | `text` | `text` streams pretty events to stderr. `json` streams raw `stream-json` events to stdout for scripting. |
| `-- <claude args>...` | — | Forwarded verbatim to the spawned `claude --print` process. |

## Examples

### Quick question

```sh
mantis prompt "summarize the last engagement's findings"
```

### Use a specific model just for this call

```sh
mantis prompt "explain the 3-round verifier cascade" -- --model claude-haiku-4-5-20251001
```

### Scripted JSON output

```sh
mantis prompt "list all auth profiles" --output-format json | jq '.message.content'
```

## See also

- [`mantis hack`](./hack.md) — full FSM engagement (requires `--i-have-authorization`)
- [`mantis status`](./status.md) — show current model / daemon / MCP state
- [`mantis model`](./model.md) — pick a model with Tab / Shift+Tab
