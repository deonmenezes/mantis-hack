<div align="center">

<img src="docs/assets/mascot/hero.png" alt="Mantis — offensive-security mascot" width="640" />

# Mantis

`stalk · wait · strike · hold`
**Ethically hack and discover vulnerabilities in any software with the power of AI.**

[Quickstart](docs/site/quickstart.md) ·
[Docs](docs/site/README.md) ·
[Responsible Use](docs/site/responsible-use.md) ·
[mantishack.com](https://mantishack.com)

</div>

---

> ## ⚠️  Authorized Testing Only
>
> **Mantis is offensive-security tooling. Use it only against systems you own or have explicit written authorization to test.**
>
> - Running Mantis against systems without permission is illegal in most jurisdictions.
> - Mantis enforces scope cryptographically at the egress proxy, but the **legal gate is yours**.
> - The CLI refuses to start without `--i-have-authorization`. Passing that flag is a self-attestation, not a legal credential.
> - See [Responsible Use](docs/site/responsible-use.md) for the full policy.

---

```
███╗   ███╗ █████╗ ███╗   ██╗████████╗██╗███████╗
████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝
██╔████╔██║███████║██╔██╗ ██║   ██║   ██║███████╗
██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██║╚════██║
██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝
```

Daemon-driven, evidence-grade automated security research platform.

Mantis plans, executes, verifies, and reports authorized offensive-security
engagements with cryptographically-verifiable provenance. It writes working
exploits, runs continuously against in-scope assets, and improves
measurably between engagements through learned playbooks, evolutionary
self-tuning, and a self-generated training corpus.

## Install

**Via npm / bun / yarn / pnpm** (recommended, one platform binary auto-selected):

```sh
npm  install -g mantishack
bun  add    -g mantishack
yarn global add mantishack
pnpm add    -g mantishack
```

**Or one-line from source:**

```sh
curl -fsSL https://raw.githubusercontent.com/deonmenezes/mantishack/main/install.sh | bash
```

The installer:
1. Builds `mantis-daemon` and `mantis` (release) into `~/.local/bin`.
2. Detects which AI CLI(s) you have installed and copies the matching
   plugin into the CLI's plugin directory:

   | CLI | Detection | Plugin dir |
   |---|---|---|
   | Claude Code | `claude` on PATH or `~/.claude/` | `~/.claude/plugins/mantis/` |
   | Codex CLI   | `codex` on PATH or `~/.codex/` | `~/.codex/plugins/mantis/` |
   | OpenCode    | `opencode` on PATH or `~/.config/opencode/` | `~/.config/opencode/plugins/mantis/` |

After install you can drive Mantis from any of those CLIs:

```
/mantishack <target>       one-shot end-to-end pentest (every step in one command)
/mantis-scan <target>      kick off an authorized engagement
/mantis-status [id]        engagement status
/mantis-claim <id>         inspect a verified finding
/mantis-report <id>        render a disclosure-ready report
/mantis-daemon             start/stop the daemon
```

`/mantishack` accepts:
- web URL: `https://example.com`
- domain: `example.com`
- Android: `app.apk`
- iOS: `app.ipa`
- Windows: `app.exe`
- macOS: `app.dmg` / `app.app`
- API: any URL pointing at an OpenAPI spec or REST endpoint

Embedded URLs are extracted from packaged-app binaries via
`strings` and pentest-routed through the same web pipeline.

### Don't have an AI CLI yet?

```sh
# Claude Code
curl -fsSL https://claude.ai/install.sh | bash

# Codex CLI (OpenAI)
npm install -g @openai/codex

# OpenCode
curl -fsSL https://opencode.ai/install | bash
```

Then rerun the Mantis installer to wire the plugin in.

## Standalone usage (no AI CLI)

```sh
mantis-daemon &                                    # start the daemon
mantis engagement create "demo" --target https://x # create an engagement
mantis engagement start "demo"                     # begin scanning
mantis engagement status "demo" --watch            # live status
mantis engagement report "demo" --format pdf       # render report
```

## Requirements

- One supported host CLI: Claude Code, Codex, or another MCP-capable host — required for the slash-command surface (`/mantishack`, etc.). The standalone CLI (`mantis hack`, `mantis pentest`) has no AI-CLI dependency.
- A working Rust toolchain — only for source builds. The prebuilt npm binary has no deps.

Recon tools (subfinder, httpx, katana, nuclei, jwt_tool) are **auto-installed** into the per-repo `tools/recon/bin/` directory by `install.sh` / `mantis init`. No manual `go install` step needed; the recon-agent prepends that directory to PATH at engagement start. Run `mantis doctor` to confirm what's installed. Mantis runs without any of them — coverage just narrows.

## Attributions

Mantis takes architectural inspiration from open-source projects in the offensive-security space. See [`NOTICE`](./NOTICE) for the full list — covers [Hacker Bob](https://github.com/vmihalis/hacker-bob) (the MCP-tool-orchestrated workflow + wave/handoff pattern), [ProjectDiscovery](https://github.com/projectdiscovery) (recon binaries: subfinder, httpx, katana, nuclei), [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool), and [BLAKE3](https://github.com/BLAKE3-team/BLAKE3). Per-binary licenses + install-time-fetch vs vendoring rationale live in [`tools/recon/THIRD_PARTY.md`](./tools/recon/THIRD_PARTY.md). All Rust code in this repo is original; the third-party projects are credited as inspiration or invoked as separate subprocesses.

## Workspace layout

```
crates/
├── mantis-core/               shared types, errors, traits (no I/O)
├── mantis-proto/              protobuf + tonic-generated types
├── mantis-workspace/          workspace paths, key management, keychain
├── mantis-event-store/        RocksDB-backed event log + Merkle evidence
├── mantis-scope/              scope DSL: parse, sign, verify, evaluate
├── mantis-egress/             scope-enforcing TCP/HTTP egress proxy
├── mantis-scanner-http/       HTTP probing + content discovery
├── mantis-hypothesis/         rule-based hypothesis generator
├── mantis-planner/            MCTS planner with UCB1
├── mantis-posterior/          Bayesian posterior management
├── mantis-claim/              claim model + verifiers
├── mantis-primitive/          exploit-primitive catalog
├── mantis-report/             6 report formats (md/pdf/h1/bugcrowd/sarif/openvex)
├── mantis-playbook/           playbook distiller
├── mantis-memory/             cross-engagement memory
├── mantis-operator-model/     operator preference profile
├── mantis-trajectory/         trajectory compression for training
├── mantis-tuner/              NSGA-II evolutionary tuner
├── mantis-hibernation/        snapshot/restore for serverless
├── mantis-scheduler/          cron + diff reports
├── mantis-tenant/             multi-tenant isolation
├── mantis-k8s/                Kubernetes operator
├── mantis-registry/           OCI plugin registry + Ed25519 signature verify
├── mantis-fuzzer/             grammar-aware coverage fuzzer
├── mantis-sandbox/            record-replay / wasmtime / Firecracker
├── mantis-synthesizer/        corpus + fuzzer + symbolic + LLM pipeline
├── mantis-chain/              capability-graph chain discovery
├── mantis-tui/                terminal-UI model
├── mantis-tui-ratatui/        ratatui terminal renderer
├── mantis-web-ui/             daemon-served Web UI (HTTP + SSE)
├── mantis-gateway/            7-platform operator gateway
├── mantis-runtime/            reactor-per-core / NUMA pinning
├── mantis-crawler/            HTML+JS static endpoint extractor
├── mantis-video/              ffmpeg-based session video capture
├── mantis-benches/            criterion benchmarks vs PRD §11
├── mantis-plugin/             WASM 0.2 component-model plugin host
├── mantis-verify/             standalone evidence-chain verifier (binary)
├── mantis-daemon/             tonic gRPC server + engagement loop (binary)
└── mantis-cli/                operator CLI client (binary)
```

The security-critical crate is `mantis-egress` — it is the single network
boundary. All HTTP traffic from any other component routes through it.
This is enforced at the proxy socket layer, not advisorially.

## Deployment

`deploy/` contains templates for the five §14 deployment modes:

- `deploy/docker/Dockerfile`             — multi-stage build, non-root runtime
- `deploy/systemd/mantis-daemon.service` — hardened systemd unit for VPS
- `deploy/k8s/mantis-deployment.yaml`    — Kubernetes Deployment + RBAC + PVC
- `deploy/modal/mantis_modal.py`         — hibernating serverless on Modal

See `deploy/README.md` for the install commands per mode.

## Authorization

Mantis runs **only against assets you are explicitly authorized to test**.
Every engagement requires a signed scope manifest. The plugin slash
commands re-verify the user has authorization before running any scan.

## License

Dual-licensed under Apache-2.0 OR MIT.
