<div align="center">

<img src="../assets/mascot/hero.png" alt="Mantis — the offensive-security mascot" width="640" />

# Mantis

### Ethically hack and discover vulnerabilities in any software with the power of AI.

**Daemon-driven, evidence-grade automated security research.**
`stalk · wait · strike · hold`

[Quickstart](./quickstart.md) · [The 7-phase FSM](./concepts/fsm.md) · [Install](./install/npm.md) · [Responsible Use](./responsible-use.md) · [GitHub](https://github.com/deonmenezes/mantishack)

</div>

---

> ## ⚠️  Authorized Testing Only
>
> Mantis is offensive-security tooling. Use it **only** against systems you own or have **explicit written authorization** to test.
>
> - Running Mantis against systems without permission is illegal in most jurisdictions.
> - Mantis enforces scope cryptographically at the egress proxy, but the **legal gate is yours**.
> - See the [Responsible Use](./responsible-use.md) page for the full policy.

---

## What is Mantis?

Mantis is a Rust daemon plus a Claude-Code-native MCP agent workflow that plans, executes, verifies, and reports authorized offensive-security engagements with **cryptographically-verifiable provenance**.

- **7-phase FSM** — every engagement walks `RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT`.
- **Parallel hunter sub-agents** — wave fan-out across attack surfaces; ≥3 hunters per wave even on a 1-surface target.
- **3-round verifier cascade** — brutalist (skeptic) → balanced (false-negative catcher) → final (fresh re-run), with a deterministic `adjudication_plan_hash` gate that any drift hard-refuses.
- **Cryptographic scope enforcement** — every outbound HTTP request goes through `mantis-egress`, a CONNECT proxy that verifies the destination against a signed scope manifest.
- **Signed Merkle event log** — every state change is a BLAKE3 leaf in a per-engagement Merkle tree, signed by an Ed25519 workspace key. Operators verify post-hoc with `mantis-verify`.

## Quick start

```sh
# 1. Install
npm  install -g mantishack
# or: bun add -g mantishack

# 2. Wire the daemon + MCP server
mantis init

# 3. Run an end-to-end pentest against an authorized target
mantis hack app.example.com --i-have-authorization
```

That single `mantis hack` invocation drives the full 7-phase FSM end-to-end, with parallel hunter sub-agents during HUNT, the 3-round verifier cascade, evidence packaging, grading, and report rendering.

## Documentation map

- **Get started**
  - [Quickstart](./quickstart.md)
  - [Installation](./install/npm.md) — npm, bun, yarn, pnpm, or build from source
- **Concepts**
  - [The 7-phase FSM](./concepts/fsm.md) — RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT
  - [Daemon architecture](./concepts/daemon.md)
  - [Sub-agents](./concepts/agents.md) — recon-agent, hunter-agent, chain-builder, verifier cascade, grader, report-writer
  - [Egress + scope enforcement](./concepts/egress.md)
- **CLI reference**
  - [`mantis hack`](./cli/hack.md) — one-shot full FSM
  - [`mantis pentest`](./cli/pentest.md) — daemon-driven one-shot
  - [`mantis goal`](./cli/goal.md) — goal-directed, multi-wave
  - [`mantis find-auth-bugs`](./cli/find-auth-bugs.md) — legacy auth-differential pipeline
- **Policy**
  - [Responsible Use](./responsible-use.md)
  - [Disclaimer](./disclaimer.md)

## Repository

Source, issue tracker, license: **https://github.com/deonmenezes/mantishack**

## License

Apache-2.0 OR MIT
