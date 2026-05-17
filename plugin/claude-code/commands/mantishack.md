---
description: One-shot end-to-end pentest. Drives every Mantis pipeline step (recon → hypothesis → MCTS → verify → synthesize → report) against a URL, domain, or packaged app (.apk, .ipa, .exe, .dmg, .app). Use when the user says `/mantishack <target>`.
---

You are invoking Mantis end-to-end against the target the user
named. This single command runs every step of the platform.

**Before running, do these two things in order:**

1. **Authorization check.** Ask the user:
   > Do you have **explicit written authorization** to run
   > offensive-security tests against `<target>`?
   If the answer is anything other than a clear yes, refuse and
   stop. Do not proceed.

2. **Scope confirmation.** Print the target and ask the user to
   confirm. For a packaged app, mention that Mantis will extract
   embedded URLs from the binary and pentest those URLs.

Once authorization is confirmed, run:

```sh
# Start the daemon if it isn't already running:
pgrep -x mantis-daemon >/dev/null || (mantis-daemon &)
sleep 1

# One-shot pentest:
mantis pentest "$TARGET" --i-have-authorization
```

The command:
- detects target type (web URL / domain / Android APK / iOS IPA /
  Windows exe / macOS dmg/app)
- creates an engagement with a unique ID
- auto-generates and authorizes a default scope manifest
- runs recon → hypothesis → MCTS planner → verifier →
  synthesizer (corpus + fuzzer + symbolic + LLM) →
  report rendering
- prints a summary table and writes artifacts under
  `./mantishack-<engagement-id>/`

**Stream the output as it runs.** Mantis emits `[mantishack]`
progress lines; relay each one to the user.

When the engagement completes, the daemon prints a summary table.
Offer to:
- render the report in PDF, HackerOne, Bugcrowd, SARIF, or OpenVEX:
  `mantis engagement report <id> --format pdf`
- export a reproducer:
  `mantis exploit <claim-id> --format python`

**Budget.** Default budget is 300 seconds wall-clock. Larger
targets need `--budget-seconds 900`. Warn the user before running
budgets over 30 minutes.

**LLM provider — no API key needed inside Claude Code.** The
pentest pipeline's corpus / fuzzer / symbolic engines do not
require any LLM credentials, so basic runs work out of the box.
The synthesizer's LLM path uses the `claude-cli` provider by
default when invoked from this plugin: it shells out to the local
`claude` CLI and reuses whatever Claude Code authentication the
user already has — there is no need to export
`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`. The user can confirm the
provider is reachable with:

```sh
mantis llm probe --provider claude-cli
```

If the user wants a different provider, set
`MANTIS_CLAUDE_CLI_BIN`, `MANTIS_CLAUDE_CLI_MODEL`, or pass
`--provider anthropic|openai` (which do require their respective
env-var keys).

**Refuse to run** if the user can't confirm authorization. Mantis
enforces scope cryptographically at the egress proxy, but the
legal gate is yours.
