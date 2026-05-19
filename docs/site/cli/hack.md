# `mantis hack`

> **Authorized testing only.** Mantis refuses to run without `--i-have-authorization`. See [Responsible Use](../responsible-use.md).

<p align="center">
  <img src="../../assets/mascot/hero.png" alt="Mantis mascot" width="220" />
</p>

The full-pipeline pentest. Drives the same 7-phase FSM as `/mantishack` in Claude Code, but from the bare CLI.

## Synopsis

```sh
mantis hack <target> --i-have-authorization [OPTIONS] [-- <claude args>...]
```

## What it does, end-to-end

1. **Pre-flight** — checks daemon is up (spawns if down); locates the `claude` CLI; verifies the `mantis` MCP server is registered with claude.
2. **Dispatch** — execs `claude --print --output-format stream-json` with the inlined rich 7-phase orchestrator role prompt and an explicit anti-recursion clause.
3. **Stream** — every tool call, sub-agent spawn, and MCP call is pretty-printed live to your terminal.
4. **Report** — on completion, points you at `./mantishack-<engagement-id>/` for artifacts.

## Options

| Flag | Default | What |
|---|---|---|
| `--i-have-authorization` | _required_ | Self-attestation that you have written permission. The legal gate. |
| `--deep` | off | Deep-recon mode — broader script-heavy recon plus durable surface-lead promotion. |
| `--no-auth` | off | Skip AUTH phase; transition to HUNT with `auth_status: "unauthenticated"`. |
| `--egress <profile>` | `default` | Named operator-managed egress profile. |
| `--turbo` | off | Preset: implies `--deep` AND auto-selects Opus when no model preference exists. |
| `--print-prompt` | off | Dump the assembled system + user prompts and exit before launching `claude`. Useful for debugging prompt changes without spending tokens. |
| `--dry-run` | off | Run every pre-flight check (daemon up, claude on PATH, MCP registered, model resolved) and exit. Useful for CI smoke tests. |
| `--daemon <url>` | `http://127.0.0.1:50451` | Daemon gRPC endpoint. Honors `MANTIS_DAEMON` env. |
| `--claude-bin <path>` | _from PATH_ | Override the `claude` binary path. Honors `MANTIS_CLAUDE_BIN`. |
| `-- <claude args>...` | — | Forwarded verbatim to the spawned `claude --print` process. Useful for `--model claude-opus-4-7`. |

## Per-repo config

If `.mantis.json` exists in the current directory (or any ancestor), `mantis hack` reads it for default values of `model`, `deep`, `no_auth`, `egress`, and `daemon`. Explicit CLI flags always win. See [`mantis model`](./model.md) and `mantis init --project` for scaffolding.

If `MANTIS.md` exists alongside the config (or any ancestor), its contents are auto-loaded into the orchestrator's system prompt so spawned hunters see your repo's scope, do-not-touch list, and severity floor.

## Examples

### Standard run

```sh
mantis hack app.example.com --i-have-authorization
```

### Skip the signup phase (unauth-only)

```sh
mantis hack api.example.com --i-have-authorization --no-auth
```

### Deep recon

```sh
mantis hack app.example.com --i-have-authorization --deep
```

### Force a specific model

```sh
mantis hack app.example.com --i-have-authorization -- --model claude-opus-4-7
```

### Use a named egress profile

```sh
mantis hack app.example.com --i-have-authorization --egress eu-west-1
```

## Live output

You'll see something like this stream as the orchestrator works:

```
███╗   ███╗ █████╗ ███╗   ██╗████████╗██╗███████╗
████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝
…
[mantishack] target: https://app.example.com/
[mantishack] daemon: up
[mantishack] claude: /Users/you/.local/bin/claude
[mantishack] mcp:    `mantis` already registered with claude
[mantishack] orchestrator: inlined (15234 chars)
[mantishack] handing off to the orchestrator — RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT

[mantishack] · session init
[mantishack] → mcp__mantis__mantis_init_session(target_domain=app.example.com)
[mantishack]   ✓ result
[mantishack] → Task(type=recon-agent, background)
[mantishack]   ✓ result
[mantishack] · Recon complete. 12 surfaces discovered.
[mantishack] → Task(type=surface-router-agent)
[mantishack] → mcp__mantis__mantis_transition_phase(target_domain=app.example.com, →AUTH)
…
[mantishack] → mcp__mantis__mantis_start_next_wave
[mantishack] → Task(type=hunter-agent, background)
[mantishack] → Task(type=hunter-agent, background)
[mantishack] → Task(type=hunter-agent, background)
…
[mantishack] · session success (47 turns, $0.8423)
[mantishack] orchestrator returned cleanly.
```

## Anti-recursion guard

`mantis hack` invokes `claude`, which the user might assume could call `Bash(\`mantis hack ...\`)` and infinite-loop. The system prompt explicitly forbids this:

> "Do NOT shell out to `mantis hack`, `mantis pentest`, or any other `mantis` CLI command via `Bash`. The `mantis` binary spawned YOU; calling it again is an infinite loop. Use only `mcp__mantis__*` tools and `Task` spawns."

The `Skill` tool is also disabled via `--disallowed-tools Skill` to prevent skill-resolution from finding an outdated mantishack skill and shortcutting.

## When to use `mantis hack` vs alternatives

| Use case | Use |
|---|---|
| Full FSM end-to-end, one command, no flags | `mantis hack` |
| Daemon-driven one-shot, no LLM orchestrator | `mantis pentest` |
| Goal-directed, multi-wave until success criterion met | `mantis goal` |
| Legacy unauth-only auth-differential pipeline | `mantis find-auth-bugs` |
| Inside Claude Code, interactive | `/mantishack <target>` |

## See also

- [The 7-phase FSM](../concepts/fsm.md)
- [`mantis pentest`](./pentest.md)
- [`mantis goal`](./goal.md)
- [Responsible Use](../responsible-use.md)
