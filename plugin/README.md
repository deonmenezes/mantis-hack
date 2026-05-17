# Mantis AI-CLI plugin

This directory contains plugin manifests that wire Mantis into the
three major terminal AI CLIs:

| CLI | Manifest |
|---|---|
| Claude Code | `claude-code/.claude-plugin/plugin.json` |
| Codex CLI   | `codex/plugin.toml` |
| OpenCode    | `opencode/opencode.json` |

## One-line install

```sh
curl -fsSL https://raw.githubusercontent.com/deonmenezes/mantishack/main/install.sh | bash
```

The installer:
1. Builds `mantis-daemon` and `mantis` (Rust release) and installs
   them under `~/.local/bin`.
2. Detects which AI CLI(s) you have installed and copies the
   matching plugin manifest into the CLI's plugin directory.

## Slash commands installed

After the installer finishes, you'll have these slash commands in
your AI CLI:

- `/mantis-scan <target>` — kick off an authorized engagement
- `/mantis-status [id]` — engagement status
- `/mantis-claim <id>` — inspect a verified finding
- `/mantis-report <id>` — render a disclosure-ready report
- `/mantis-daemon` — start/stop the daemon

## One-line download for the AI CLIs themselves

You probably already have one, but for reference:

```sh
# Claude Code
curl -fsSL https://claude.ai/install.sh | bash

# Codex CLI (OpenAI)
npm install -g @openai/codex

# OpenCode
curl -fsSL https://opencode.ai/install | bash
```

After installing any of those, rerun the Mantis installer to wire
the plugin in.

## Authorization gate

Every Mantis slash command in every plugin re-verifies the user has
explicit authorization to test the named target before running.
Refuse to scan assets you don't control or haven't been
contractually authorized against.
