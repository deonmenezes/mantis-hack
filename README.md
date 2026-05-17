# Mantis

Daemon-driven, evidence-grade automated security research platform.

Mantis plans, executes, verifies, and reports authorized offensive-security
engagements with cryptographically-verifiable provenance. It writes working
exploits, runs continuously against in-scope assets, and improves
measurably between engagements through learned playbooks, evolutionary
self-tuning, and a self-generated training corpus.

## One-line install

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
/mantis-scan <target>      kick off an authorized engagement
/mantis-status [id]        engagement status
/mantis-claim <id>         inspect a verified finding
/mantis-report <id>        render a disclosure-ready report
/mantis-daemon             start/stop the daemon
```

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
