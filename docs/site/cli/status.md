# `mantis status`

> **Authorized testing only.** See [Responsible Use](../responsible-use.md).

Single-glance snapshot of your local Mantis setup. Use this when something looks off and you want to know — at a glance — whether the daemon is running, whether `claude` knows about the `mantis` MCP server, which model is active, and where the persisted state lives.

## Synopsis

```sh
mantis status [--output-format text|json] [--daemon <url>]
```

## Sample text output

```
Mantis session status

  daemon:
    endpoint:        http://127.0.0.1:50451
    up:              yes
    binary:          /Users/you/.local/bin/mantis-daemon
    pid:             71823

  claude:
    binary:          /Users/you/.local/bin/claude
    mantis MCP:      registered

  mantis-mcp:
    binary:          /Users/you/.local/bin/mantis-mcp

  model:
    effective:       claude-opus-4-7 (Opus 4.7)
    source:          .mantis.json
    env MANTIS_MODEL: (unset)
    .mantis.json:    claude-opus-4-7
    saved file:      (empty)

  ~/.Mantis:         /Users/you/.Mantis
  project config:    /Users/you/repos/foo/.mantis.json
```

## JSON output

```sh
mantis status --output-format json
```

Returns structured fields for scripting:

```json
{
  "daemon": {
    "endpoint": "http://127.0.0.1:50451",
    "up": true,
    "binary_on_path": "/Users/you/.local/bin/mantis-daemon",
    "pid": 71823,
    "pid_file": "/Users/you/.Mantis/daemon.pid",
    "log_file": "/Users/you/.Mantis/daemon.log"
  },
  "claude": {
    "binary_on_path": "/Users/you/.local/bin/claude",
    "mantis_mcp_registered": true
  },
  "mcp": { "binary_on_path": "/Users/you/.local/bin/mantis-mcp" },
  "model": {
    "effective": "claude-opus-4-7",
    "effective_source": ".mantis.json",
    "saved": null,
    "env": null,
    "project": "claude-opus-4-7",
    "file": "/Users/you/.Mantis/model",
    "resolution_order": [
      "cli --model flag",
      "MANTIS_MODEL env",
      ".mantis.json",
      "~/.Mantis/model",
      "claude default"
    ]
  },
  "mantis_home": "/Users/you/.Mantis",
  "project_config": "/Users/you/repos/foo/.mantis.json"
}
```

## When to use

- After `mantis init` to verify everything wired correctly.
- When `mantis hack` complains about a missing claude binary or MCP server.
- To confirm which model is going to be used before you run `mantis hack`.
- To audit which `.mantis.json` is in play when you have nested repos.

## See also

- [`mantis doctor`](../README.md) — deeper, recon-tool-aware diagnostic
- [`mantis init`](../README.md#install) — wire daemon + MCP + plugin
- [`mantis model`](./model.md) — pick the Claude model
