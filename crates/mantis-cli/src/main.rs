//! Mantis CLI (`mantis`).
//!
//! Subcommands either operate on local workspace state directly
//! (workspace, operator, doctor) or talk to a running daemon via the
//! generated `mantis.v1.Engagement` gRPC client (engagement).

mod banner;
mod llm_pick;
mod model_picker;
mod project_config;
mod run_log;
mod setup;

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use mantis_proto::v1::engagement_client::EngagementClient;
use mantis_proto::v1::{
    AuthorizeRequest, CreateRequest, EngagementInfo, EngagementState as ProtoEngagementState,
    ExportRequest, ListRequest, PauseRequest, ScanRequest, StartRequest, StatusRequest,
};
use mantis_fsm::{Goal, GoalKind, GoalStatus};
use mantis_workspace::{default_workspace_root, run_doctor, OsKeyStore, Workspace};
use tracing_subscriber::EnvFilter;

const DEFAULT_DAEMON_ENDPOINT: &str = "http://127.0.0.1:50451";

/// How many times `mantis hack` / `mantis investigate` / `mantis
/// prompt` will auto-resume on a failed `claude --print` session
/// before giving up. Override at runtime via `MANTIS_MAX_RESUMES`.
const DEFAULT_MAX_RESUMES_FALLBACK: u32 = 3;

/// Resolved per-invocation so an operator can dial it via env var
/// without rebuilding. Returns the fallback when unset / malformed.
fn default_max_resumes() -> u32 {
    std::env::var("MANTIS_MAX_RESUMES")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_MAX_RESUMES_FALLBACK)
}

#[derive(Parser, Debug)]
#[command(name = "mantis", version, about = "Mantis daemon CLI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// First-run interface — prints the Mantis banner and shows which
    /// LLM providers are detected on this system (Anthropic API, OpenAI
    /// API, Claude Code CLI). Tells you exactly what to set to get
    /// ready. Running `mantis` with no subcommand is equivalent.
    Setup,
    /// Print Mantis version info. Use `--output-format json` for
    /// scripting (returns `{ "name", "version", "rust_target" }`).
    /// Mirrors the claude-code / claw-code diagnostic convention.
    Version {
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        output_format: String,
    },
    /// Start the Mantis daemon in the foreground.
    Daemon {
        #[arg(long, env = "MANTIS_BIND", default_value = mantis_daemon::DEFAULT_BIND)]
        bind: std::net::SocketAddr,
        #[arg(long, env = "MANTIS_HOME")]
        root: Option<Utf8PathBuf>,
    },
    /// Workspace management.
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },
    /// Operator identity management.
    Operator {
        #[command(subcommand)]
        action: OperatorAction,
    },
    /// Engagement management (talks to a running `mantis-daemon`).
    Engagement {
        #[command(subcommand)]
        action: EngagementAction,
    },
    /// Diagnostic checks against the local workspace.
    Doctor {
        #[arg(long)]
        root: Option<Utf8PathBuf>,
        /// Output format: `text` (default) or `json` (machine-
        /// readable). Mirrors the claude-code / claw-code
        /// convention so any diagnostic verb works under the
        /// same flag.
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        output_format: String,
        /// Legacy alias for `--output-format json`. Hidden in
        /// `--help` but accepted for backwards compatibility.
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Export an engagement's event log as JSONL (M0.5).
    Export { id: String },
    /// Probe a configured LLM provider with a 1-token round-trip.
    /// Used to validate API key + network reachability without
    /// spending tokens on a real synthesis call.
    Llm {
        #[command(subcommand)]
        action: LlmAction,
    },
    /// End-to-end pentest: one command, every step. Detects target
    /// type (web URL, domain, .apk/.ipa/.exe/.dmg/.app), creates
    /// an engagement, generates a default scope manifest, runs
    /// recon + hypothesis + verify + synthesis + report, and
    /// prints a summary.
    ///
    /// Requires explicit authorization to test the target.
    Pentest {
        /// Target: URL (https://example.com), domain (example.com),
        /// or path to a packaged app (.apk, .ipa, .exe, .dmg, .app).
        target: String,
        /// Skip the interactive authorization prompt. The caller
        /// MUST have written authorization to test the target.
        #[arg(long)]
        i_have_authorization: bool,
        /// Output directory for the report. Defaults to
        /// `./mantishack-<engagement-id>/`.
        #[arg(long)]
        output: Option<Utf8PathBuf>,
        /// Report format (markdown | pdf | hackerone | bugcrowd | sarif | openvex).
        #[arg(long, default_value = "markdown")]
        format: String,
        /// Hard cap on engagement wall-clock seconds (default 300).
        #[arg(long, default_value_t = 300)]
        budget_seconds: u32,
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
    /// Full-pipeline pentest. Drives the same FSM + parallel-hunter
    /// wave-fan-out flow as the `/mantishack` slash command, but
    /// from the bare CLI. Ensures the Mantis daemon is up, ensures
    /// `claude` is on PATH with the `mantis` MCP server registered,
    /// then shells out to `claude --print` with `/mantishack <target>`.
    /// stdio is streamed live so the operator sees every phase
    /// (RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT).
    ///
    /// Examples:
    ///   mantis hack app.example.com --i-have-authorization
    ///   mantis hack https://app.example.com/ --i-have-authorization --deep
    ///   mantis hack api.example.com --i-have-authorization --no-auth
    ///
    /// For the legacy unauth-only auth-differential pipeline (no
    /// FSM, no LLM, no waves) see `mantis find-auth-bugs`.
    Hack {
        /// Target URL or bare domain. `example.com` is treated as
        /// `https://example.com/` automatically.
        target: String,
        /// Skip the authorization prompt. The caller MUST hold
        /// written authorization for the target.
        #[arg(long)]
        i_have_authorization: bool,
        /// Enable deep-recon mode (broader script-heavy recon plus
        /// durable surface-lead promotion).
        #[arg(long)]
        deep: bool,
        /// Skip AUTH phase; transition RECON → AUTH → HUNT with
        /// `auth_status: "unauthenticated"`.
        #[arg(long)]
        no_auth: bool,
        /// Named operator-managed egress profile. Defaults to
        /// `default`.
        #[arg(long, default_value = "default")]
        egress: String,
        /// Daemon gRPC endpoint.
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
        /// Override the `claude` binary path. Defaults to whichever
        /// `claude` is on `PATH`.
        #[arg(long, env = "MANTIS_CLAUDE_BIN")]
        claude_bin: Option<Utf8PathBuf>,
        /// "Turbo" preset — equivalent to `--deep` plus forcing the
        /// Opus model (`claude-opus-4-7`) when no model preference is
        /// set via `mantis model` or `-- --model …`. Use this when
        /// you want the most thorough engagement and don't care about
        /// token cost.
        #[arg(long)]
        turbo: bool,
        /// Dump the assembled orchestrator prompt + system prompt to
        /// stdout and exit without launching `claude`. Useful for
        /// debugging prompt changes without spending tokens.
        #[arg(long)]
        print_prompt: bool,
        /// Run all pre-flight checks (daemon up, `claude` on PATH,
        /// `mantis` MCP server registered, model picked) and exit
        /// without launching `claude`. Useful for CI smoke tests and
        /// for verifying setup after `mantis init`.
        #[arg(long)]
        dry_run: bool,
        /// Extra args appended to the `claude` invocation after `--`.
        /// Useful for `--model claude-opus-4-7` or similar provider
        /// overrides. Example:
        ///   mantis hack app.example.com --i-have-authorization -- --model claude-opus-4-7
        #[arg(last = true)]
        claude_extra_args: Vec<String>,

        // -- Legacy flags below: accepted for backwards compat but
        // -- they belong to `mantis find-auth-bugs` now. Setting any
        // -- of them prints a deprecation warning and is otherwise
        // -- ignored by the FSM-driven flow.
        #[arg(long, env = "MANTIS_COOKIE", hide = true)]
        cookie: Option<String>,
        #[arg(long, hide = true)]
        supabase_signup: Option<String>,
        #[arg(long, env = "MANTIS_SUPABASE_APIKEY", hide = true)]
        supabase_apikey: Option<String>,
        #[arg(long, hide = true)]
        attacker_profile: Option<Utf8PathBuf>,
        #[arg(long, hide = true)]
        victim_profile: Option<Utf8PathBuf>,
        #[arg(long = "extra-path", hide = true)]
        extra_paths: Vec<String>,
        #[arg(long, hide = true)]
        max_candidates: Option<usize>,
        #[arg(long, hide = true)]
        max_endpoints_probed: Option<usize>,
    },
    /// End-to-end auth-bug pipeline. Signs up an attacker + victim
    /// (Supabase JSON path), enumerates endpoint candidates from
    /// the seed URL, runs the auth-differential against every
    /// endpoint with all profiles, and aggregates findings into a
    /// per-target archive folder under `./reports/<host>/`.
    ///
    /// Example (Tenkara-shaped target):
    ///   mantis find-auth-bugs \
    ///       --target https://app.tenkara.ai/ \
    ///       --supabase-signup https://lciwjbtbadjpkooufsvx.supabase.co/auth/v1/signup \
    ///       --supabase-apikey "$ANON_KEY" \
    ///       --extra-path "/rest/v1/users" \
    ///       --extra-path "/rest/v1/orders" \
    ///       --i-have-authorization
    ///
    /// Without `--supabase-signup`, the pipeline runs an unauth-only
    /// differential — useful as a fast public-table scan.
    FindAuthBugs {
        /// Seed URL. Enumerator expands paths + (optionally) subdomains from here.
        #[arg(long)]
        target: String,
        /// Supabase signup endpoint URL. When set, `--supabase-apikey`
        /// must also be set.
        #[arg(long)]
        supabase_signup: Option<String>,
        /// Public Supabase anon key (the `apikey` header value).
        #[arg(long, env = "MANTIS_SUPABASE_APIKEY")]
        supabase_apikey: Option<String>,
        /// Operator-supplied paths added to the enumerator's wordlist
        /// (e.g. `/rest/v1/orders`, `/api/materials-view`).
        #[arg(long = "extra-path")]
        extra_paths: Vec<String>,
        /// BYO attacker auth profile JSON (matches `mantis-auth::AuthProfile`).
        /// Use this when the target is NOT Supabase-backed and you've
        /// captured the profile out-of-band (e.g. DevTools paste).
        #[arg(long)]
        attacker_profile: Option<Utf8PathBuf>,
        /// BYO victim auth profile JSON. Mirrors `--attacker-profile`.
        #[arg(long)]
        victim_profile: Option<Utf8PathBuf>,
        /// Max candidate URLs to enumerate.
        #[arg(long, default_value_t = 60)]
        max_candidates: usize,
        /// Hard cap on auth-diff probes (protects against runaway).
        #[arg(long, default_value_t = 60)]
        max_endpoints_probed: usize,
        /// Skip subdomain expansion in the enumerator.
        #[arg(long, default_value_t = true)]
        no_subdomain_expansion: bool,
        /// Skip authorization prompt.
        #[arg(long)]
        i_have_authorization: bool,
        /// Output JSON file. Defaults to
        /// `./reports/<host>/find-auth-bugs-<ulid>.json`.
        #[arg(long)]
        output: Option<Utf8PathBuf>,
    },
    /// Auth-differential runner. Replays one URL under multiple
    /// auth profiles and classifies the divergence to find
    /// cross-tenant reads, IDOR, broken access control, and
    /// privilege-escalation bugs.
    ///
    /// Each `--profile NAME=PATH` reads a JSON auth profile from
    /// disk (matching `mantis-auth::AuthProfile`). Use `NAME` =
    /// `attacker`, `victim`, `admin` to drive the classifier's
    /// pattern matchers. Unauthenticated probe is always added
    /// implicitly.
    ///
    /// Example:
    ///   mantis auth-diff --url https://api.example.com/v1/orders \
    ///       --profile attacker=./attacker.json \
    ///       --profile victim=./victim.json \
    ///       --i-have-authorization
    AuthDiff {
        /// Single target URL to probe.
        #[arg(long)]
        url: String,
        /// One or more `role=path` profile bindings. Roles:
        /// `attacker`, `victim`, `admin`. The unauthenticated
        /// profile is always added on top.
        #[arg(long = "profile", value_name = "ROLE=PATH")]
        profiles: Vec<String>,
        /// Skip the unauthenticated probe (default: include it).
        #[arg(long)]
        no_unauth: bool,
        /// Skip authorization prompt. Caller must hold written
        /// authorization for the target.
        #[arg(long)]
        i_have_authorization: bool,
        /// Optional output JSON path. Defaults to stdout-only.
        #[arg(long)]
        output: Option<Utf8PathBuf>,
    },
    /// Goal-directed engagement. Drives Mantis toward a declarative
    /// success criterion ("find all endpoints", "find vulnerabilities",
    /// "find idor", "authenticate then scan", or any free-form
    /// description). The engagement keeps iterating waves until the
    /// goal is met or the budget is exhausted. Use this when
    /// `mantis pentest` is too one-shot.
    ///
    /// Examples:
    ///   mantis goal "find all endpoints" --target https://app.example.com --i-have-authorization
    ///   mantis goal "find idor" --target https://api.example.com --i-have-authorization
    Goal {
        /// Free-form goal description. Parsed by
        /// `mantis_fsm::Goal::parse`. Keywords like `endpoint`,
        /// `vuln`, `idor`, `sqli`, `xss`, `auth` trigger structured
        /// goal kinds; otherwise the goal becomes `Custom` and the
        /// orchestrator runs until budget or operator-mark-met.
        description: String,
        /// Target URL or domain.
        #[arg(long)]
        target: String,
        /// Skip authorization prompt. Caller must hold written
        /// authorization for the target.
        #[arg(long)]
        i_have_authorization: bool,
        /// Hard cap on wall-clock seconds (default 300).
        #[arg(long, default_value_t = 300)]
        budget_seconds: u32,
        /// Max candidate URLs to probe in the endpoint-enumeration
        /// path. Higher = more thorough, slower.
        #[arg(long, default_value_t = 200)]
        max_candidates: usize,
        /// Output directory. Defaults to
        /// `./mantishack-<engagement-id>/`.
        #[arg(long)]
        output: Option<Utf8PathBuf>,
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
    /// Wire Mantis into the local AI CLIs (idempotent).
    ///
    /// Copies the bundled Claude Code plugin to
    /// `~/.claude/plugins/mantis/`, registers `mantis-mcp` as a
    /// user-scope MCP server with the `claude` CLI, and (unless
    /// `--no-daemon`) spawns the daemon in the background.
    ///
    /// Called automatically by the npm install path on first
    /// invocation; safe to re-run any time.
    Init {
        /// Path to the `plugin/` directory bundled with this repo.
        /// Defaults to `$MANTIS_PLUGIN_SRC`, then `./plugin`.
        #[arg(long, env = "MANTIS_PLUGIN_SRC")]
        plugin_src: Option<Utf8PathBuf>,
        /// Skip spawning the daemon.
        #[arg(long)]
        no_daemon: bool,
        /// Skip MCP registration.
        #[arg(long)]
        no_mcp: bool,
        /// Skip plugin file copy.
        #[arg(long)]
        no_plugin: bool,
        /// Daemon endpoint baked into the MCP registration.
        #[arg(long, default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon_endpoint: String,
        /// Also scaffold per-repo project files in the current
        /// directory: `.mantis.json` template + `MANTIS.md`
        /// guidance file. Idempotent — existing files are skipped.
        /// Mirrors `claude init` / `claw init`.
        #[arg(long)]
        project: bool,
    },
    /// Interactive TUI — Claude-Code-style prompt box. Type a request
    /// (e.g. "hack example.com") and Mantis routes it to your chosen
    /// AI CLI (claude / codex / opencode / gemini). Tab cycles
    /// providers; Ctrl-C exits.
    ///
    /// `mantis` (no arguments) defaults to launching this TUI when a
    /// supported AI CLI is on PATH.
    Tui,
    /// Pick / set the Claude model used by `mantis hack`. With no
    /// args, opens an interactive picker (Tab / Shift+Tab to cycle,
    /// Enter to confirm). The chosen model is persisted to
    /// `~/.Mantis/model` and applied automatically on the next
    /// `mantis hack` run, unless the user passes `-- --model …`
    /// explicitly.
    Model {
        #[command(subcommand)]
        action: Option<ModelAction>,
    },
    /// Investigate anything carefully using the full Mantis stack —
    /// MCP tools, spawned sub-agents, the egress proxy, the Merkle
    /// log — but without the rigid 7-phase FSM that `mantis hack`
    /// enforces. The subject auto-classifies:
    ///
    /// * URL (`https://…` / `http://…`) — runs an offensive
    ///   investigation against the target (requires
    ///   `--i-have-authorization`). The orchestrator spawns recon
    ///   and hunter agents as needed and reports back.
    /// * File path that exists on disk — reads the file (capped at
    ///   64 KB), embeds it in the prompt, and runs a code/config-
    ///   focused investigation. No auth flag required.
    /// * Anything else — treated as a free-form prompt. The
    ///   orchestrator spawns whatever agents help answer it.
    ///
    /// Examples:
    ///   mantis investigate https://app.example.com/api/users --i-have-authorization
    ///   mantis investigate ./suspicious.js
    ///   mantis investigate "this IDOR claim — does it really compose into ATO?"
    Investigate {
        /// What to investigate. URL, file path, or free-form text.
        subject: String,
        /// Required ONLY when the subject classifies as a URL.
        /// Non-URL subjects don't issue offensive traffic so they
        /// don't gate on this flag.
        #[arg(long)]
        i_have_authorization: bool,
        /// Daemon gRPC endpoint.
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
        /// Override the `claude` binary path.
        #[arg(long, env = "MANTIS_CLAUDE_BIN")]
        claude_bin: Option<Utf8PathBuf>,
        /// Output format: `text` (default) or `json` (raw stream-json).
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        output_format: String,
        /// Extra args forwarded to `claude --print` after `--`.
        #[arg(last = true)]
        claude_extra_args: Vec<String>,
    },
    /// One-shot Claude-Code-style prompt. Wires the `mantis` MCP
    /// server and applies the saved model preference, then runs
    /// `claude --print` so you can ask anything — no engagement,
    /// no scope manifest, no FSM. For full pentests use
    /// `mantis hack`; for ad-hoc questions or quick automation,
    /// use this.
    ///
    /// Examples:
    ///   mantis prompt "summarize the recent recon notes"
    ///   mantis prompt "what does the auth-diff classifier do"
    ///   mantis prompt -- --model claude-haiku-4-5-20251001  "ping"
    Prompt {
        /// The prompt text. Anything you'd otherwise pipe into
        /// `claude --print`.
        text: String,
        /// Daemon gRPC endpoint (used only to wire MCP).
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
        /// Override the `claude` binary path.
        #[arg(long, env = "MANTIS_CLAUDE_BIN")]
        claude_bin: Option<Utf8PathBuf>,
        /// Output format: `text` (default, streams pretty events
        /// to stderr) or `json` (streams raw `stream-json` events
        /// to stdout, for scripting).
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        output_format: String,
        /// Extra args forwarded to `claude --print` after `--`.
        #[arg(last = true)]
        claude_extra_args: Vec<String>,
    },
    /// Show the current Mantis session state in one place: which
    /// model is active, daemon up/down, MCP registered, most-recent
    /// engagement, and `~/.Mantis/` artifacts.
    ///
    /// Use `--output-format json` for scripting.
    Status {
        /// Output format: `text` (default, human-readable) or
        /// `json` (machine-readable).
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        output_format: String,
        /// Daemon gRPC endpoint.
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
}

#[derive(Subcommand, Debug)]
enum ModelAction {
    /// Print the currently-saved model preference.
    Show,
    /// Set the model to `<id>` (the value passed to `claude --model`).
    /// Use `auto` or an empty string to clear.
    Set {
        /// `auto` to clear, or one of `claude-opus-4-7`,
        /// `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`, or any
        /// custom id accepted by `claude --model`.
        id: String,
    },
    /// Clear the saved preference (revert to claude's default).
    Clear,
    /// Open the interactive Tab / Shift+Tab picker (default).
    Pick,
}

#[derive(Subcommand, Debug)]
enum LlmAction {
    /// One-shot health check against a provider. For `anthropic` and
    /// `openai`, the API key comes from the environment variable
    /// named after the provider (`ANTHROPIC_API_KEY` or
    /// `OPENAI_API_KEY`). For `claude-cli`, no key is required —
    /// the adapter shells out to the local `claude` CLI and reuses
    /// whatever Claude Code authentication is already configured.
    Probe {
        /// Provider: `anthropic`, `openai`, or `claude-cli`.
        #[arg(long, default_value = "anthropic")]
        provider: String,
        /// Override the model (defaults to each adapter's default).
        #[arg(long)]
        model: Option<String>,
        /// Prompt to send. Default is a trivial liveness ping.
        #[arg(long, default_value = "Reply with exactly the word: ok")]
        prompt: String,
    },
}

#[derive(Subcommand, Debug)]
enum WorkspaceAction {
    Init {
        #[arg(long)]
        root: Option<Utf8PathBuf>,
    },
    Info {
        #[arg(long)]
        root: Option<Utf8PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum OperatorAction {
    Create {
        name: String,
        #[arg(long)]
        root: Option<Utf8PathBuf>,
    },
    List {
        #[arg(long)]
        root: Option<Utf8PathBuf>,
    },
    Delete {
        id: String,
        #[arg(long)]
        root: Option<Utf8PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum EngagementAction {
    Create {
        name: String,
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
    Authorize {
        id: String,
        /// Path to a signed scope JSON file.
        #[arg(long)]
        scope: Utf8PathBuf,
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
    Start {
        id: String,
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
    Pause {
        id: String,
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
    Status {
        id: String,
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
    List {
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
    /// Probe URL targets and run the hypothesis catalog over each.
    Scan {
        id: String,
        /// URL targets (e.g. https://api.example.com/v1/users). Repeatable.
        #[arg(long, required = true)]
        target: Vec<String>,
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
    /// Export an engagement's event log as JSONL.
    Export {
        id: String,
        /// Output path (defaults to stdout).
        #[arg(long)]
        output: Option<Utf8PathBuf>,
        #[arg(long, env = "MANTIS_DAEMON", default_value = DEFAULT_DAEMON_ENDPOINT)]
        daemon: String,
    },
}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let command = match cli.command {
        Some(c) => c,
        None => {
            // Bare `mantis` — launch the Claude-Code-style prompt TUI
            // when a supported AI CLI is on PATH; otherwise fall back
            // to the first-run setup screen so the user gets wired
            // up before trying again.
            if has_any_ai_cli() {
                return mantis_tui_ratatui::prompt::run();
            }
            setup::run();
            return Ok(());
        }
    };
    match command {
        Command::Tui => mantis_tui_ratatui::prompt::run(),
        Command::Model { action } => handle_model(action),
        Command::Prompt {
            text,
            daemon,
            claude_bin,
            output_format,
            claude_extra_args,
        } => run_async(handle_prompt(text, daemon, claude_bin, output_format, claude_extra_args)),
        Command::Investigate {
            subject,
            i_have_authorization,
            daemon,
            claude_bin,
            output_format,
            claude_extra_args,
        } => run_async(handle_investigate(
            subject,
            i_have_authorization,
            daemon,
            claude_bin,
            output_format,
            claude_extra_args,
        )),
        Command::Status {
            output_format,
            daemon,
        } => handle_status(output_format, daemon),
        Command::Init {
            plugin_src,
            no_daemon,
            no_mcp,
            no_plugin,
            daemon_endpoint,
            project,
        } => handle_init(plugin_src, no_daemon, no_mcp, no_plugin, daemon_endpoint, project),
        Command::Setup => {
            setup::run();
            Ok(())
        }
        Command::Version { output_format } => handle_version(output_format),
        Command::Daemon { bind, root } => run_async(async move {
            mantis_daemon::run(mantis_daemon::DaemonConfig {
                bind,
                workspace_root: root,
            })
            .await
        }),
        Command::Workspace { action } => match action {
            WorkspaceAction::Init { root } => cmd_workspace_init(root),
            WorkspaceAction::Info { root } => cmd_workspace_info(root),
        },
        Command::Operator { action } => match action {
            OperatorAction::Create { name, root } => cmd_operator_create(&name, root),
            OperatorAction::List { root } => cmd_operator_list(root),
            OperatorAction::Delete { id, root } => cmd_operator_delete(&id, root),
        },
        Command::Engagement { action } => run_async(handle_engagement(action)),
        Command::Doctor { root, output_format, json } => {
            cmd_doctor(root, json || output_format == "json")
        }
        Command::Export { id } => run_async(handle_engagement(EngagementAction::Export {
            id,
            output: None,
            daemon: DEFAULT_DAEMON_ENDPOINT.to_owned(),
        })),
        Command::Llm { action } => run_async(handle_llm(action)),
        Command::Pentest {
            target,
            i_have_authorization,
            output,
            format,
            budget_seconds,
            daemon,
        } => run_async(handle_pentest(
            target,
            i_have_authorization,
            output,
            format,
            budget_seconds,
            daemon,
        )),
        Command::Hack {
            target,
            i_have_authorization,
            deep,
            no_auth,
            egress,
            daemon,
            claude_bin,
            turbo,
            print_prompt,
            dry_run,
            claude_extra_args,
            cookie,
            supabase_signup,
            supabase_apikey,
            attacker_profile,
            victim_profile,
            extra_paths,
            max_candidates,
            max_endpoints_probed,
        } => run_async(handle_hack(
            target,
            i_have_authorization,
            deep,
            no_auth,
            egress,
            daemon,
            claude_bin,
            turbo,
            print_prompt,
            dry_run,
            claude_extra_args,
            HackLegacyFlags {
                cookie,
                supabase_signup,
                supabase_apikey,
                attacker_profile,
                victim_profile,
                extra_paths,
                max_candidates,
                max_endpoints_probed,
            },
        )),
        Command::FindAuthBugs {
            target,
            supabase_signup,
            supabase_apikey,
            extra_paths,
            attacker_profile,
            victim_profile,
            max_candidates,
            max_endpoints_probed,
            no_subdomain_expansion,
            i_have_authorization,
            output,
        } => run_async(handle_find_auth_bugs(
            target,
            supabase_signup,
            supabase_apikey,
            extra_paths,
            attacker_profile,
            victim_profile,
            max_candidates,
            max_endpoints_probed,
            no_subdomain_expansion,
            i_have_authorization,
            output,
        )),
        Command::AuthDiff {
            url,
            profiles,
            no_unauth,
            i_have_authorization,
            output,
        } => run_async(handle_auth_diff(
            url,
            profiles,
            no_unauth,
            i_have_authorization,
            output,
        )),
        Command::Goal {
            description,
            target,
            i_have_authorization,
            budget_seconds,
            max_candidates,
            output,
            daemon,
        } => run_async(handle_goal(
            description,
            target,
            i_have_authorization,
            budget_seconds,
            max_candidates,
            output,
            daemon,
        )),
    }
}

async fn handle_pentest(
    target: String,
    i_have_authorization: bool,
    output: Option<Utf8PathBuf>,
    format: String,
    budget_seconds: u32,
    daemon: String,
) -> Result<()> {
    banner::print();
    if !i_have_authorization {
        anyhow::bail!(
            "refusing to start: this command runs offensive-security tests against the named target.\n\
             Re-run with --i-have-authorization once you have written permission to test it.\n\
             Mantis enforces scope cryptographically at the egress proxy, but the legal gate is yours."
        );
    }

    let target_kind = classify_target(&target);
    eprintln!("[mantishack] target classified as: {target_kind:?}");

    let urls: Vec<String> = match &target_kind {
        TargetKind::WebUrl(u) | TargetKind::Domain(u) => vec![u.clone()],
        TargetKind::PackagedApp { path, kind } => {
            eprintln!("[mantishack] extracting embedded URLs from {kind} app at {path:?}");
            extract_urls_from_binary(path).await.unwrap_or_else(|e| {
                eprintln!("[mantishack] extraction failed: {e}. proceeding with no URLs.");
                vec![]
            })
        }
    };
    if urls.is_empty() {
        anyhow::bail!("no URLs to scan; provide a URL/domain or an app with embedded endpoints");
    }
    eprintln!("[mantishack] discovered {} URL target(s)", urls.len());

    let engagement_name = format!("mantishack-{}", ulid::Ulid::new());
    eprintln!("[mantishack] creating engagement `{engagement_name}` on {daemon}");

    let mut client = EngagementClient::connect(daemon.clone())
        .await
        .with_context(|| format!("connecting to daemon at {daemon}"))?;

    let create_resp = client
        .create(CreateRequest {
            name: engagement_name.clone(),
        })
        .await?
        .into_inner();
    let engagement_id = create_resp.id;
    eprintln!("[mantishack] engagement id: {engagement_id}");

    eprintln!(
        "[mantishack] auto-authorizing default scope (host-only) — {} target(s)",
        urls.len()
    );
    let scope_json = build_signed_scope_json(&engagement_id, &urls, budget_seconds)
        .context("build signed scope")?;
    client
        .authorize(AuthorizeRequest {
            id: engagement_id.clone(),
            signed_scope_json: scope_json.into_bytes(),
        })
        .await?;
    eprintln!("[mantishack] scope authorized");

    client
        .start(StartRequest {
            id: engagement_id.clone(),
        })
        .await?;
    eprintln!("[mantishack] engagement started, scanning targets...");

    client
        .scan(ScanRequest {
            id: engagement_id.clone(),
            targets: urls.clone(),
        })
        .await?;
    eprintln!("[mantishack] scan dispatched");

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(budget_seconds as u64);
    let mut last_state = String::new();
    loop {
        let status = client
            .status(StatusRequest {
                id: engagement_id.clone(),
            })
            .await?
            .into_inner();
        let state_text = format!(
            "events={} state={}",
            status.event_count,
            engagement_state_name(status.state)
        );
        if state_text != last_state {
            eprintln!("[mantishack] {state_text}");
            last_state = state_text;
        }
        if status.state == ProtoEngagementState::Completed as i32 {
            break;
        }
        if std::time::Instant::now() > deadline {
            eprintln!("[mantishack] budget exhausted; collecting results");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    }

    let output_dir =
        output.unwrap_or_else(|| Utf8PathBuf::from(format!("./mantishack-{engagement_id}")));
    std::fs::create_dir_all(&output_dir).context("create output dir")?;

    let info = client
        .status(StatusRequest {
            id: engagement_id.clone(),
        })
        .await?
        .into_inner();

    eprintln!("[mantishack] exporting event log -> {output_dir}/events.jsonl");
    let export = client
        .export(ExportRequest {
            id: engagement_id.clone(),
        })
        .await?
        .into_inner();
    std::fs::write(output_dir.join("events.jsonl"), &export.jsonl).context("write events.jsonl")?;

    let report_path = output_dir.join(format!("report.{}", format_extension(&format)));
    eprintln!("[mantishack] rendering {format} report -> {report_path}");
    let report_body = render_minimal_report(
        &engagement_name,
        &engagement_id,
        &target_kind,
        &info,
        &export.jsonl,
    );
    std::fs::write(&report_path, report_body).context("write report")?;

    let summary = build_summary(&engagement_name, &engagement_id, &target_kind, &info);
    std::fs::write(output_dir.join("summary.txt"), &summary).ok();
    eprintln!("\n{summary}");

    eprintln!("[mantishack] done. engagement {engagement_id} artifacts under {output_dir}");
    eprintln!("[mantishack]   - summary.txt    human-readable summary");
    eprintln!("[mantishack]   - events.jsonl   full append-only event log");
    eprintln!(
        "[mantishack]   - {}     engagement report",
        report_path.file_name().unwrap_or("report")
    );
    Ok(())
}

fn render_minimal_report(
    name: &str,
    id: &str,
    target_kind: &TargetKind,
    info: &EngagementInfo,
    events_jsonl: &[u8],
) -> String {
    let kind_label = match target_kind {
        TargetKind::WebUrl(u) => format!("web URL `{u}`"),
        TargetKind::Domain(u) => format!("domain `{u}`"),
        TargetKind::PackagedApp { path, kind } => format!("{kind} app `{path}`"),
    };
    let event_lines: Vec<&str> = std::str::from_utf8(events_jsonl)
        .unwrap_or("")
        .lines()
        .collect();
    let mut surfaces = 0usize;
    let mut hypotheses = 0usize;
    let mut claims_verified = 0usize;
    for line in &event_lines {
        if line.contains("\"SurfaceDiscovered\"") {
            surfaces += 1;
        } else if line.contains("\"HypothesisGenerated\"") {
            hypotheses += 1;
        } else if line.contains("\"ClaimVerified\"") {
            claims_verified += 1;
        }
    }
    format!(
        "# Mantis Engagement Report\n\n\
         - **Name:** `{name}`\n\
         - **Engagement:** `{id}`\n\
         - **Target:** {kind_label}\n\
         - **State:** `{}`\n\
         - **Events recorded:** {}\n\n\
         ## Pipeline summary\n\n\
         | Stage | Count |\n\
         |---|---|\n\
         | Surfaces discovered | {surfaces} |\n\
         | Hypotheses generated | {hypotheses} |\n\
         | Claims verified | {claims_verified} |\n\n\
         ## Event log\n\n\
         {} events appended to the per-engagement Merkle-evidence \
         log under the workspace. See `events.jsonl` for the raw stream; \
         every entry is BLAKE3-hashed into the engagement's tree head \
         and signed by the workspace key.\n",
        engagement_state_name(info.state),
        info.event_count,
        event_lines.len()
    )
}

fn engagement_state_name(s: i32) -> &'static str {
    match s {
        x if x == ProtoEngagementState::Draft as i32 => "draft",
        x if x == ProtoEngagementState::Authorized as i32 => "authorized",
        x if x == ProtoEngagementState::Active as i32 => "active",
        x if x == ProtoEngagementState::Paused as i32 => "paused",
        x if x == ProtoEngagementState::Completed as i32 => "completed",
        x if x == ProtoEngagementState::Archived as i32 => "archived",
        _ => "unknown",
    }
}

fn format_extension(format: &str) -> &str {
    match format {
        "pdf" => "pdf",
        "hackerone" => "h1.json",
        "bugcrowd" => "bugcrowd.json",
        "sarif" => "sarif.json",
        "openvex" => "vex.json",
        _ => "md",
    }
}

async fn handle_goal(
    description: String,
    target: String,
    i_have_authorization: bool,
    budget_seconds: u32,
    max_candidates: usize,
    output: Option<Utf8PathBuf>,
    daemon: String,
) -> Result<()> {
    banner::print();
    if !i_have_authorization {
        anyhow::bail!(
            "refusing to start: goal-directed engagements run offensive-security tests.\n\
             Re-run with --i-have-authorization once you have written permission for {target}."
        );
    }

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut goal = Goal::parse(&description, now_unix);
    eprintln!("[mantis-goal] description: {}", goal.description);
    eprintln!("[mantis-goal] parsed kind: {:?}", goal.kind);

    let target_kind = classify_target(&target);
    let seed_url: String = match &target_kind {
        TargetKind::WebUrl(u) => u.clone(),
        TargetKind::Domain(u) => u.clone(),
        TargetKind::PackagedApp { .. } => {
            anyhow::bail!("packaged-app targets not supported for goal-directed runs in v1");
        }
    };
    eprintln!("[mantis-goal] target: {seed_url}");

    // Create + authorize + start the engagement (same as pentest).
    let engagement_name = format!("mantis-goal-{}", ulid::Ulid::new());
    let mut client = EngagementClient::connect(daemon.clone())
        .await
        .with_context(|| format!("connecting to daemon at {daemon}"))?;
    let create_resp = client
        .create(CreateRequest {
            name: engagement_name.clone(),
        })
        .await?
        .into_inner();
    let engagement_id = create_resp.id;
    eprintln!("[mantis-goal] engagement id: {engagement_id}");

    // Build & authorize a permissive single-host scope so the egress
    // proxy admits the candidates we're about to probe.
    let scope_json = build_signed_scope_json(&engagement_id, &[seed_url.clone()], budget_seconds)
        .context("build signed scope")?;
    client
        .authorize(AuthorizeRequest {
            id: engagement_id.clone(),
            signed_scope_json: scope_json.into_bytes(),
        })
        .await
        .context("authorize")?;
    client
        .start(StartRequest {
            id: engagement_id.clone(),
        })
        .await
        .context("start")?;
    eprintln!("[mantis-goal] engagement authorized + started");

    // Pass-loop. Each pass:
    //   1. Mantis daemon scans the next batch of candidates.
    //   2. We poll engagement status for total event count.
    //   3. We update the goal's pass bookkeeping.
    //   4. Evaluate. Stop when met OR budget elapsed.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(budget_seconds as u64);
    let mut pass = 0u32;
    let mut total_surfaces = 0u32;
    while std::time::Instant::now() < deadline && !goal.is_done() {
        pass += 1;
        eprintln!("[mantis-goal] pass {pass} starting");

        // For endpoint-enumeration goals, generate a fresh candidate
        // batch from the wordlist. For other goal kinds, just probe
        // the seed (the daemon's hypothesis+primitive flow takes
        // over from there).
        let candidates: Vec<String> = match &goal.kind {
            GoalKind::EnumerateEndpoints { .. } => {
                use mantis_scanner_http::{generate_candidates, EnumerationConfig};
                generate_candidates(
                    &seed_url,
                    &EnumerationConfig {
                        max_candidates,
                        expand_subdomains: true,
                        ..Default::default()
                    },
                )
            }
            _ => vec![seed_url.clone()],
        };
        eprintln!("[mantis-goal]   {} candidate URL(s) this pass", candidates.len());

        // Dispatch to the daemon. The daemon will record each
        // SurfaceDiscovered event into the merkle log.
        let scan = client
            .scan(ScanRequest {
                id: engagement_id.clone(),
                targets: candidates,
            })
            .await;
        match scan {
            Ok(r) => {
                let r = r.into_inner();
                eprintln!(
                    "[mantis-goal]   surfaces_recorded={} hypotheses_recorded={}",
                    r.surfaces_recorded, r.hypotheses_recorded
                );
                total_surfaces = total_surfaces.saturating_add(r.surfaces_recorded);
            }
            Err(e) => {
                eprintln!("[mantis-goal]   scan error: {e}");
                break;
            }
        }

        // Update the goal's pass bookkeeping and evaluate.
        goal.record_pass(total_surfaces);
        let status = goal.evaluate(total_surfaces, &[]);
        eprintln!(
            "[mantis-goal]   pass {pass} status: {status:?} (total surfaces: {total_surfaces}, stagnation streak: {})",
            goal.stagnation_streak
        );
        if matches!(status, GoalStatus::Met) {
            goal.mark_met(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            );
            break;
        }

        // Trivial pacing — let the daemon flush events before the
        // next scan. The Tokio scheduler doesn't need this, but
        // operators reading the output do.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    let final_status = goal.status.as_str();
    eprintln!();
    eprintln!("============================================================");
    eprintln!("Mantis goal — summary");
    eprintln!("============================================================");
    eprintln!("Engagement:    {engagement_id}");
    eprintln!("Goal:          {}", goal.description);
    eprintln!("Status:        {final_status}");
    eprintln!("Passes spent:  {}", goal.passes_spent);
    eprintln!("Surfaces seen: {total_surfaces}");
    eprintln!("============================================================");

    // Export the event log + render a report so the operator can
    // inspect.
    let out_dir = output.unwrap_or_else(|| Utf8PathBuf::from(format!("./mantishack-{engagement_id}")));
    std::fs::create_dir_all(&out_dir).context("create output dir")?;
    let export_resp = client
        .export(ExportRequest {
            id: engagement_id.clone(),
        })
        .await
        .context("export")?
        .into_inner();
    std::fs::write(out_dir.join("events.jsonl"), &export_resp.jsonl)
        .context("write events.jsonl")?;
    std::fs::write(
        out_dir.join("goal.json"),
        serde_json::to_vec_pretty(&goal).context("encode goal")?,
    )
    .context("write goal.json")?;
    eprintln!("[mantis-goal] artifacts under {out_dir}");
    Ok(())
}

async fn handle_auth_diff(
    url: String,
    profiles: Vec<String>,
    no_unauth: bool,
    i_have_authorization: bool,
    output: Option<Utf8PathBuf>,
) -> Result<()> {
    banner::print();
    if !i_have_authorization {
        anyhow::bail!(
            "refusing to start: auth-differential runs offensive-security \
             tests across N profiles. Re-run with --i-have-authorization once \
             you have written permission for {url}."
        );
    }

    // Parse each `role=path` binding from disk.
    use mantis_auth::AuthProfile;
    use mantis_auth_differential::{
        run_differential, ProfileBinding, ProfileRole, RunnerConfig,
    };

    let mut loaded: Vec<(ProfileRole, AuthProfile)> = Vec::new();
    for entry in &profiles {
        let (role_str, path_str) = entry.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("--profile expects ROLE=PATH; got `{entry}`")
        })?;
        let role = match role_str.to_ascii_lowercase().as_str() {
            "attacker" => ProfileRole::Attacker,
            "victim" => ProfileRole::Victim,
            "admin" => ProfileRole::Admin,
            "unauth" | "unauthenticated" => ProfileRole::Unauthenticated,
            other => anyhow::bail!(
                "unknown role `{other}` (expected: attacker | victim | admin | unauthenticated)"
            ),
        };
        let path = std::path::PathBuf::from(path_str);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read profile JSON at {}", path.display()))?;
        let profile: AuthProfile = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse profile JSON at {}", path.display()))?;
        loaded.push((role, profile));
    }

    if loaded.is_empty() && no_unauth {
        anyhow::bail!(
            "no profiles supplied and --no-unauth set — nothing to probe. \
             Provide at least one --profile ROLE=PATH or remove --no-unauth."
        );
    }

    // Build bindings: optional unauth always first.
    let mut bindings: Vec<ProfileBinding<'_>> = Vec::new();
    if !no_unauth {
        bindings.push(ProfileBinding {
            role: ProfileRole::Unauthenticated,
            profile: None,
        });
    }
    for (role, profile) in &loaded {
        bindings.push(ProfileBinding {
            role: *role,
            profile: Some(profile),
        });
    }

    eprintln!("[mantis-auth-diff] target URL: {url}");
    eprintln!("[mantis-auth-diff] probing under {} profile(s)", bindings.len());
    for b in &bindings {
        let name = b.profile.map(|p| p.name.as_str()).unwrap_or("(none)");
        eprintln!("[mantis-auth-diff]   role={:?} profile_name={}", b.role, name);
    }

    let findings = run_differential(&url, &bindings, &RunnerConfig::default())
        .await
        .map_err(|e| anyhow::anyhow!("differential runner: {e}"))?;

    eprintln!();
    eprintln!("============================================================");
    eprintln!("Auth-differential findings: {}", findings.len());
    eprintln!("============================================================");
    if findings.is_empty() {
        eprintln!("No divergence detected. Endpoint appears properly authorized");
        eprintln!("OR all roles were blocked equivalently.");
    } else {
        for (i, f) in findings.iter().enumerate() {
            eprintln!();
            eprintln!("[{}] {:?} (severity={})", i + 1, f.class, f.class.default_severity());
            eprintln!("    finding_id:    {}", f.finding_id);
            eprintln!("    finding_hash:  {}", f.finding_hash);
            eprintln!("    vuln_class:    {}", f.class.vuln_class());
            eprintln!("    url:           {}", f.url);
            eprintln!("    evidence:      {}", f.evidence);
        }
    }

    // Optional JSON output.
    if let Some(path) = output {
        let out = serde_json::json!({
            "url": url,
            "findings": findings,
            "summary": {
                "total": findings.len(),
                "by_severity": severity_counts(&findings),
            },
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&out)?)
            .with_context(|| format!("write {}", path))?;
        eprintln!();
        eprintln!("[mantis-auth-diff] JSON output: {}", path);
    }

    Ok(())
}

/// True iff a bare `host` or `host:port` is most likely served over
/// plain HTTP. Heuristic: localhost / 127.x / IP-literal targets, or
/// non-443/8443 ports.
fn host_port_is_likely_http(host_port: &str) -> bool {
    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (host_port, None),
    };
    let is_local = host == "localhost"
        || host.starts_with("127.")
        || host == "0.0.0.0"
        || host.parse::<std::net::IpAddr>().is_ok();
    match (is_local, port) {
        (true, _) => true,
        (false, Some(443)) => false,
        (false, Some(8443)) => false,
        (false, Some(_)) => false, // public host with a port → still default to https
        (false, None) => false,
    }
}

/// `mantis hack <target>` — the simple-as-bob-hunt command. Auto-
/// discovers Supabase config from the target's HTML, runs the full
/// pipeline, archives.
#[allow(clippy::too_many_arguments)]
/// Legacy `mantis hack` flags that pre-date the FSM-driven flow.
/// Kept on the clap struct so old scripts don't hard-fail; we emit a
/// deprecation warning if any are set and redirect the operator to
/// `mantis find-auth-bugs`.
struct HackLegacyFlags {
    cookie: Option<String>,
    supabase_signup: Option<String>,
    supabase_apikey: Option<String>,
    attacker_profile: Option<Utf8PathBuf>,
    victim_profile: Option<Utf8PathBuf>,
    extra_paths: Vec<String>,
    max_candidates: Option<usize>,
    max_endpoints_probed: Option<usize>,
}

impl HackLegacyFlags {
    fn any_set(&self) -> bool {
        self.cookie.is_some()
            || self.supabase_signup.is_some()
            || self.supabase_apikey.is_some()
            || self.attacker_profile.is_some()
            || self.victim_profile.is_some()
            || !self.extra_paths.is_empty()
            || self.max_candidates.is_some()
            || self.max_endpoints_probed.is_some()
    }
}

async fn handle_hack(
    target: String,
    i_have_authorization: bool,
    deep: bool,
    no_auth: bool,
    egress: String,
    daemon: String,
    claude_bin: Option<Utf8PathBuf>,
    turbo: bool,
    print_prompt: bool,
    dry_run: bool,
    claude_extra_args: Vec<String>,
    legacy: HackLegacyFlags,
) -> Result<()> {
    banner::print();
    if !i_have_authorization {
        anyhow::bail!(
            "refusing to start: `mantis hack` runs offensive-security tests against {target}.\n\
             Re-run with --i-have-authorization once you have written permission.\n\
             Mantis enforces scope at the egress proxy when daemon-driven, but the legal gate is yours."
        );
    }

    if legacy.any_set() {
        eprintln!(
            "[mantishack] warning: --cookie / --supabase-* / --attacker-profile / \
             --victim-profile / --extra-path / --max-candidates / --max-endpoints-probed \
             are no-ops for `mantis hack` (FSM-driven). Use `mantis find-auth-bugs` for \
             the legacy auth-differential pipeline."
        );
    }

    // Pull per-repo defaults from `.mantis.json` (if any). CLI flags
    // beat them; project config beats global defaults. Egress is
    // string-typed so we only override when the user kept the
    // default "default" value.
    let project_cfg = project_config::load().ok().flatten();
    let project_deep = project_cfg.as_ref().and_then(|(_, c)| c.deep).unwrap_or(false);
    let project_no_auth = project_cfg.as_ref().and_then(|(_, c)| c.no_auth).unwrap_or(false);
    let project_egress = project_cfg.as_ref().and_then(|(_, c)| c.egress.clone());
    if let Some((path, _)) = &project_cfg {
        eprintln!("[mantishack] config:    {}", path.display());
    }

    // `--turbo` is a preset: deep recon + Opus model when no other
    // preference exists. Resolved here so the rest of the function
    // sees the post-preset values. CLI deep / no_auth / egress beat
    // the project config; otherwise the project values fill in.
    let deep = deep || turbo || project_deep;
    let no_auth = no_auth || project_no_auth;
    let egress = if egress == "default" {
        project_egress.unwrap_or(egress)
    } else {
        egress
    };
    if turbo {
        eprintln!("[mantishack] turbo: deep recon + Opus model preset");
    }

    let target_url = normalize_target_url(&target);
    eprintln!("[mantishack] target: {target_url}");
    eprintln!("[mantishack] daemon: {daemon}");

    // Run the three sync pre-flight checks concurrently. Each is
    // network or subprocess-bound, so doing them in parallel cuts
    // startup latency by ~2x in the common cached-claude / running-
    // daemon path.
    //
    //   - ensure_daemon_for_hack: gRPC-pings the daemon, spawning
    //     one if down.
    //   - resolve_claude_binary: walks PATH (filesystem stats).
    //   - mantis-mcp-on-PATH precheck: walks PATH to fail fast
    //     before we try to register.
    //
    // The actual `claude mcp get` / `claude mcp add` register step
    // depends on `claude_path` and must run after — but the cheap
    // `which mantis-mcp` precheck can ride along in parallel.
    let daemon_for_task = daemon.clone();
    let claude_bin_for_task = claude_bin.clone();
    let (daemon_res, claude_res, mcp_bin_res) = tokio::join!(
        tokio::task::spawn_blocking(move || ensure_daemon_for_hack(&daemon_for_task)),
        tokio::task::spawn_blocking(move || resolve_claude_binary(claude_bin_for_task.as_deref())),
        tokio::task::spawn_blocking(|| which_bin("mantis-mcp")),
    );
    daemon_res.context("spawn_blocking(daemon-check)")??;
    let claude_path = claude_res.context("spawn_blocking(claude-resolve)")??;
    let mcp_bin = mcp_bin_res.context("spawn_blocking(mantis-mcp lookup)")?;
    eprintln!("[mantishack] claude: {}", claude_path.display());

    // MCP registration depends on `claude_path`; do it sequentially
    // but use the prefetched `mantis-mcp` lookup so we fail fast on
    // a missing helper before doing the more expensive `claude mcp
    // add` subprocess.
    let claude_path_for_task = claude_path.clone();
    let daemon_for_mcp = daemon.clone();
    tokio::task::spawn_blocking(move || {
        ensure_mantis_mcp_registered_with_prefetched_helper(
            &claude_path_for_task,
            &daemon_for_mcp,
            mcp_bin,
        )
    })
    .await
    .context("spawn_blocking(mcp-register)")??;

    // 4. Build the orchestrator system prompt and shell out.
    //
    //    `claude --print` does NOT expand slash commands; the model
    //    sees `/mantishack` as literal text and tries to resolve it
    //    via the `Skill` tool, which can return arbitrary skill
    //    content. In a previous run the model then took a shortcut
    //    and tried to recursively `Bash(mantis hack ...)` — an
    //    infinite loop. The fix: inline the orchestrator role body
    //    directly as `--append-system-prompt`, ban the `Skill` tool
    //    via `--disallowed-tools`, and explicitly forbid shelling
    //    out to `mantis` in the prompt.
    let arguments = build_orchestrator_arguments(&target_url, deep, no_auth, &egress);
    let orchestrator_body = orchestrator_role_body(&arguments);

    // Auto-load per-repo guidance (MANTIS.md) if present. Capped at
    // 8 KB so an oversized guide can't blow the prompt budget.
    let guidance_block = match project_config::load_guidance(8 * 1024) {
        Some((path, body)) => {
            eprintln!("[mantishack] guidance: {} ({} bytes)", path.display(), body.len());
            format!(
                "\n\n=== REPO GUIDANCE (MANTIS.md from {}) ===\n\n{body}\n\n\
                 The orchestrator must consult this guidance when deciding scope, \
                 do-not-touch lists, authorized auth profiles, and severity floor \
                 for this engagement. Any explicit constraint in this guidance \
                 wins over the default playbook.\n",
                path.display()
            )
        }
        None => String::new(),
    };

    let preauth_system_prompt = format!(
        "Non-interactive invocation by `mantis hack`.\n\
         The operator has provided explicit written authorization for the target \
         `{target_url}` via the `--i-have-authorization` flag at the CLI gate. \
         The legal authorization gate AND the scope confirmation gate are \
         PRE-CONFIRMED for this session. Do not ask the user to re-confirm \
         either gate; the user is not interactive and cannot answer.\n\n\
         HARD RULES for this session:\n\
         - Do NOT use the `Skill` tool for anything. It is disabled.\n\
         - Do NOT shell out to `mantis hack`, `mantis pentest`, or any other \
           `mantis` CLI command via `Bash`. The `mantis` binary spawned YOU; \
           calling it again is an infinite loop. Use only `mcp__mantis__*` \
           tools and `Task` spawns of the named subagents.\n\
         - The orchestrator role prompt is appended below. Follow it exactly. \
           Begin with PHASE 1: RECON. Do not delegate the whole engagement to \
           a single sub-agent — drive the FSM yourself by calling MCP tools \
           and spawning the named role subagents (recon-agent, \
           surface-router-agent, hunter-agent, chain-builder, \
           brutalist-verifier, balanced-verifier, final-verifier, \
           evidence-agent, grader, report-writer).{guidance_block}\n\n\
         === ORCHESTRATOR ROLE PROMPT ===\n\n\
         {orchestrator_body}",
    );

    let prompt = format!(
        "Authorization granted at the CLI gate for `{target_url}`. \
         Scope confirmed: `{target_url}`. Both legal and scope gates are \
         PRE-CONFIRMED — do not re-ask the user. \n\
         Engagement input ($ARGUMENTS): {arguments}\n\n\
         Begin the engagement now. Start with PHASE 1: RECON by calling \
         `mcp__mantis__mantis_init_session({{ target_domain, target_url, deep_mode }})` \
         and then spawning the recon agent via the `Task` tool. Drive the \
         full FSM (RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT). \
         Do NOT use Skill. Do NOT shell out to `mantis hack`."
    );

    eprintln!("[mantishack] orchestrator: inlined ({} chars)", orchestrator_body.len());

    // Apply the saved-model preference unless the user already passed
    // `--model …` themselves (or via `-m`). `mantis model` writes the
    // chosen id to `~/.Mantis/model`; reading it here is the bridge.
    // `--turbo` upgrades the default to Opus when nothing else is set.
    let claude_extra_args = apply_model_preference(claude_extra_args, turbo);

    if print_prompt {
        eprintln!("[mantishack] --print-prompt: dumping assembled prompt and exiting (no `claude` exec)");
        eprintln!();
        println!("=== SYSTEM PROMPT (append-system-prompt) ===\n");
        println!("{preauth_system_prompt}");
        println!("\n=== USER PROMPT ===\n");
        println!("{prompt}");
        println!("\n=== FORWARDED CLAUDE ARGS ===\n");
        for a in &claude_extra_args {
            println!("  {a}");
        }
        return Ok(());
    }

    if dry_run {
        eprintln!("[mantishack] --dry-run: pre-flight checks passed; skipping `claude` exec");
        return Ok(());
    }

    eprintln!(
        "[mantishack] handing off to the orchestrator — RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT"
    );
    // Open the markdown command log. Best-effort: a failure to open
    // (e.g. read-only cwd) just disables logging for this run.
    let log_path = run_log::pick_log_path(Some(&target_url));
    let run_log = match run_log::RunLog::open(log_path.clone(), "mantis hack", &target_url) {
        Ok(l) => {
            eprintln!("[mantishack] log:       {} (pretty markdown)", log_path.display());
            Some(l)
        }
        Err(e) => {
            eprintln!("[mantishack] log:       disabled ({e})");
            None
        }
    };
    eprintln!();

    let status = run_slash_with_resume(
        &claude_path,
        &claude_extra_args,
        run_log.as_ref(),
        &prompt,
        &preauth_system_prompt,
        default_max_resumes(),
        /* json_mode */ false,
    )
    .await?;
    if let Some(log) = &run_log {
        let label = if status.success() {
            "success".to_string()
        } else {
            format!("exit {status}")
        };
        log.finalize(&label);
    }

    if !status.success() {
        anyhow::bail!(
            "`claude` exited with status {} — see streamed output above for details",
            status
        );
    }

    eprintln!();
    eprintln!("[mantishack] orchestrator returned cleanly.");
    print_post_run_summary();
    Ok(())
}

/// Find the most-recent `./mantishack-<id>/` engagement directory and
/// print a claude-code-style "what just happened" summary: findings
/// by severity, grade verdict (SUBMIT / HOLD / SKIP), and the path
/// to the rendered report.
fn print_post_run_summary() {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut newest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    let Ok(entries) = std::fs::read_dir(&cwd) else {
        eprintln!("[mantishack] artifacts (if produced) live under ./mantishack-<engagement-id>/");
        return;
    };
    for ent in entries.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("mantishack-") {
            continue;
        }
        let Ok(meta) = ent.metadata() else { continue; };
        if !meta.is_dir() {
            continue;
        }
        let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        if newest.as_ref().is_none_or(|(t, _)| mtime > *t) {
            newest = Some((mtime, ent.path()));
        }
    }
    let Some((_, eng_dir)) = newest else {
        eprintln!("[mantishack] artifacts (if produced) live under ./mantishack-<engagement-id>/");
        return;
    };

    eprintln!();
    eprintln!("┌──────────────────────────────────────────────────────────────");
    eprintln!("│ engagement: {}", eng_dir.display());

    // Findings.jsonl — count by severity.
    let findings_path = eng_dir.join("findings.jsonl");
    if let Ok(raw) = std::fs::read_to_string(&findings_path) {
        let mut counts: std::collections::BTreeMap<String, u32> = Default::default();
        let mut total = 0u32;
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                let sev = v.get("severity").and_then(|s| s.as_str()).unwrap_or("?");
                *counts.entry(sev.to_string()).or_insert(0) += 1;
                total += 1;
            }
        }
        eprintln!("│ findings:   {total} total");
        for sev in ["critical", "high", "medium", "low", "info"] {
            if let Some(n) = counts.get(sev) {
                eprintln!("│   {sev:<10} {n}");
            }
        }
    } else {
        eprintln!("│ findings:   (no findings.jsonl)");
    }

    // Grade verdict.
    let grade_path = eng_dir.join("grade-verdict.json");
    if let Ok(raw) = std::fs::read_to_string(&grade_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            let verdict = v.get("verdict").and_then(|s| s.as_str()).unwrap_or("(unknown)");
            let total = v.get("total_score").and_then(|s| s.as_i64()).unwrap_or(0);
            eprintln!("│ grade:      {verdict} (total_score={total})");
        }
    }

    // Report — list rendered formats.
    let mut report_paths: Vec<String> = vec![];
    if eng_dir.join("report.md").is_file() {
        report_paths.push("report.md".into());
    }
    for ext in ["pdf", "json", "sarif", "openvex"] {
        if eng_dir.join(format!("report.{ext}")).is_file() {
            report_paths.push(format!("report.{ext}"));
        }
    }
    if !report_paths.is_empty() {
        eprintln!("│ reports:    {}", report_paths.join(", "));
    }

    // Merkle log size.
    if let Ok(meta) = std::fs::metadata(eng_dir.join("events.jsonl")) {
        eprintln!("│ events.jsonl: {} bytes (signed Merkle log)", meta.len());
    }

    eprintln!("└──────────────────────────────────────────────────────────────");
    eprintln!();
    eprintln!("[mantishack] render report in other formats:");
    eprintln!("[mantishack]   mantis engagement report <id> --format pdf");
    eprintln!("[mantishack]   mantis engagement report <id> --format hackerone");
}

/// Prepend `--model <id>` to the args forwarded to `claude --print`,
/// honoring (in priority order, claude-code / claw-code style):
///   1. user-supplied `-- --model …` / `-m …` (wins — leave untouched)
///   2. `MANTIS_MODEL` env var (per-shell override)
///   3. `.mantis.json` `model` key (per-repo)
///   4. `~/.Mantis/model` (persistent — set via `mantis model`)
///   5. `--turbo` default (Opus, only when nothing else fires)
fn apply_model_preference(claude_extra_args: Vec<String>, turbo: bool) -> Vec<String> {
    if claude_extra_args
        .iter()
        .any(|a| a == "--model" || a == "-m" || a.starts_with("--model="))
    {
        // User overrode; don't touch.
        return claude_extra_args;
    }
    let env_model = std::env::var("MANTIS_MODEL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let project_model = project_config::load()
        .ok()
        .flatten()
        .and_then(|(_, cfg)| cfg.model)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let (model_id, source) = if let Some(env_id) = env_model {
        (env_id, "from $MANTIS_MODEL env var")
    } else if let Some(proj) = project_model {
        (proj, "from .mantis.json")
    } else if let Some(saved) = model_picker::load_saved() {
        (saved, "from `mantis model`")
    } else if turbo {
        ("claude-opus-4-7".to_string(), "from --turbo preset")
    } else {
        return claude_extra_args;
    };
    eprintln!("[mantishack] model: {model_id}  ({source}; override via `-- --model …`)");
    let mut out = Vec::with_capacity(claude_extra_args.len() + 2);
    out.push("--model".to_string());
    out.push(model_id);
    out.extend(claude_extra_args);
    out
}

fn handle_model(action: Option<ModelAction>) -> Result<()> {
    match action.unwrap_or(ModelAction::Pick) {
        ModelAction::Show => {
            model_picker::print_show();
            Ok(())
        }
        ModelAction::Clear => {
            model_picker::save("")?;
            println!("model preference cleared.");
            Ok(())
        }
        ModelAction::Set { id } => {
            // "auto" / empty → clear.
            let id = id.trim();
            if id.is_empty() || id.eq_ignore_ascii_case("auto") {
                model_picker::save("")?;
                println!("model preference cleared.");
                return Ok(());
            }
            model_picker::save(id)?;
            match model_picker::find_by_id(id) {
                Some(m) => println!("model set to {} ({}).", m.label, id),
                None => println!("model set to {id} (custom id — not in the built-in list)."),
            }
            Ok(())
        }
        ModelAction::Pick => match model_picker::pick_interactive()? {
            Some(m) => {
                model_picker::save(m.id)?;
                if m.id.is_empty() {
                    println!("model preference cleared — claude default applies.");
                } else {
                    println!("model set to {} ({}).", m.label, m.id);
                }
                Ok(())
            }
            None => {
                println!("cancelled — preference unchanged.");
                Ok(())
            }
        },
    }
}

/// `mantis version` — mirror of claude-code / claw-code's
/// diagnostic verb. Default text is one line; `--output-format json`
/// emits `{ "name", "version", "rust_target" }`.
fn handle_version(output_format: String) -> Result<()> {
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    let rust_target = std::env::consts::ARCH.to_string()
        + "-"
        + std::env::consts::OS;
    if output_format == "json" {
        let v = serde_json::json!({
            "name": name,
            "version": version,
            "rust_target": rust_target,
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("{name} {version} ({rust_target})");
    }
    Ok(())
}

/// `mantis prompt "..."` — claude-code-style one-shot. No
/// engagement, no scope manifest, no FSM. Wires the `mantis` MCP
/// server so the spawned `claude` has the same tool surface as
/// `mantis hack`, applies the saved-model preference, and streams
/// the response.
async fn handle_prompt(
    text: String,
    daemon: String,
    claude_bin: Option<Utf8PathBuf>,
    output_format: String,
    claude_extra_args: Vec<String>,
) -> Result<()> {
    let json_mode = output_format == "json";
    // Resolve claude + register MCP in parallel — same parallelism
    // win as `mantis hack`'s pre-flight.
    let daemon_for_task = daemon.clone();
    let claude_bin_for_task = claude_bin.clone();
    let (claude_res, mcp_bin_res) = tokio::join!(
        tokio::task::spawn_blocking(move || resolve_claude_binary(claude_bin_for_task.as_deref())),
        tokio::task::spawn_blocking(|| which_bin("mantis-mcp")),
    );
    let claude_path = claude_res.context("spawn_blocking(claude-resolve)")??;
    let mcp_bin = mcp_bin_res.context("spawn_blocking(mantis-mcp lookup)")?;

    // MCP registration is best-effort here — `mantis prompt` is the
    // ad-hoc path. If the helper is missing we still let the user's
    // prompt through; they just won't have mantis_* tools.
    if mcp_bin.is_some() {
        let claude_path_for_task = claude_path.clone();
        let _ = tokio::task::spawn_blocking(move || {
            ensure_mantis_mcp_registered_with_prefetched_helper(
                &claude_path_for_task,
                &daemon_for_task,
                mcp_bin,
            )
        })
        .await
        .context("spawn_blocking(mcp-register)")?;
    } else if !json_mode {
        eprintln!(
            "[mantis prompt] note: `mantis-mcp` is not on PATH — \
             continuing without mantis_* tools."
        );
    }

    let claude_extra_args = apply_model_preference(claude_extra_args, false);

    // The system prompt is intentionally short: this is an ad-hoc
    // surface, not an FSM run. The only invariant is "do not start
    // an engagement without explicit authorization".
    let mut system_prompt = String::from(
        "You are running under `mantis prompt` — a one-shot Claude-Code-style \
         assistant invocation. The `mantis` MCP server is wired so you have \
         access to mantis_* tools, but no engagement has been authorized. \
         If the user asks you to start an engagement or run offensive-security \
         tests against any target, refuse and direct them to `mantis hack \
         <target> --i-have-authorization`. For everything else (questions \
         about the codebase, summarizing recon notes, ad-hoc analysis), \
         answer directly.",
    );
    if let Some((path, body)) = project_config::load_guidance(8 * 1024) {
        if !json_mode {
            eprintln!("[mantis prompt] guidance: {} ({} bytes)", path.display(), body.len());
        }
        system_prompt.push_str("\n\n=== REPO GUIDANCE (MANTIS.md from ");
        system_prompt.push_str(&path.display().to_string());
        system_prompt.push_str(") ===\n\n");
        system_prompt.push_str(&body);
    }

    if !json_mode {
        eprintln!("[mantis prompt] claude: {}", claude_path.display());
    }
    // Open the markdown command log. Best-effort.
    let target_hint = text.chars().take(40).collect::<String>();
    let log_path = run_log::pick_log_path(None);
    let run_log = match run_log::RunLog::open(log_path.clone(), "mantis prompt", &target_hint) {
        Ok(l) => {
            if !json_mode {
                eprintln!("[mantis prompt] log:    {} (pretty markdown)", log_path.display());
            }
            Some(l)
        }
        Err(_) => None,
    };
    if !json_mode {
        eprintln!();
    }
    let status = run_one_shot_with_resume(
        &claude_path,
        &claude_extra_args,
        run_log.as_ref(),
        &text,
        &system_prompt,
        default_max_resumes(),
        json_mode,
    )
    .await?;
    if let Some(log) = &run_log {
        let label = if status.success() {
            "success".to_string()
        } else {
            format!("exit {status}")
        };
        log.finalize(&label);
    }

    if !status.success() {
        anyhow::bail!("`claude` exited with status {status}");
    }
    Ok(())
}

/// Classification of a `mantis investigate <subject>` argument.
#[derive(Debug, PartialEq, Eq)]
enum InvestigateSubject {
    /// URL — auto-detected by `http://` / `https://` scheme.
    /// Offensive testing → requires `--i-have-authorization`.
    Url(String),
    /// Existing file on disk — content embedded in the investigator
    /// prompt (capped at 64 KB).
    File {
        path: std::path::PathBuf,
        body: String,
        truncated: bool,
    },
    /// Free-form text. Anything else.
    Prompt(String),
}

fn classify_subject(raw: &str) -> InvestigateSubject {
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return InvestigateSubject::Url(trimmed.to_string());
    }
    // File path heuristic: looks like a path AND exists on disk.
    // We don't treat random multi-word text as a file even if it
    // contains slashes (e.g. "the /api/users endpoint…").
    let looks_pathy = !trimmed.contains(char::is_whitespace)
        && (trimmed.starts_with('/')
            || trimmed.starts_with("./")
            || trimmed.starts_with("../")
            || trimmed.starts_with('~')
            || trimmed.contains('.'));
    if looks_pathy {
        let expanded = if let Some(rest) = trimmed.strip_prefix('~') {
            if let Ok(home) = std::env::var("HOME") {
                std::path::PathBuf::from(home).join(rest.trim_start_matches('/'))
            } else {
                std::path::PathBuf::from(trimmed)
            }
        } else {
            std::path::PathBuf::from(trimmed)
        };
        if expanded.is_file() {
            const CAP: usize = 64 * 1024;
            match std::fs::read_to_string(&expanded) {
                Ok(mut body) => {
                    let truncated = body.len() > CAP;
                    if truncated {
                        // truncate at a UTF-8 boundary
                        let mut end = CAP;
                        while end > 0 && !body.is_char_boundary(end) {
                            end -= 1;
                        }
                        body.truncate(end);
                    }
                    return InvestigateSubject::File {
                        path: expanded,
                        body,
                        truncated,
                    };
                }
                Err(_) => {
                    // Fall through to Prompt — couldn't read, treat as text.
                }
            }
        }
    }
    InvestigateSubject::Prompt(trimmed.to_string())
}

/// `mantis investigate <subject>` — flexible variant of `mantis
/// hack` that takes a URL, a file, or a free-form prompt and runs
/// the full 7-phase Mantis FSM with the subject as priority
/// investigation context.
///
/// Flow:
///
///   1. Classify the subject (URL / file / prompt).
///   2. Extract a target URL from it (URL: itself; file: first URL
///      found in the body; prompt: first URL found in the text).
///   3. If we have a target_url AND --i-have-authorization →
///      **drive the full FSM** (RECON → AUTH → HUNT → CHAIN →
///      VERIFY → GRADE → REPORT), the same orchestrator role body
///      `mantis hack` uses, with the subject body inlined as
///      priority context so the spawned hunters know which finding
///      / file / hunch to dig into first.
///   4. Otherwise → read-only investigation. No FSM, no scope
///      manifest, no live HTTP. The orchestrator uses MCP read
///      tools and `Read` / `Grep` to answer.
async fn handle_investigate(
    subject: String,
    i_have_authorization: bool,
    daemon: String,
    claude_bin: Option<Utf8PathBuf>,
    output_format: String,
    claude_extra_args: Vec<String>,
) -> Result<()> {
    let json_mode = output_format == "json";
    if !json_mode {
        banner::print();
    }

    let classified = classify_subject(&subject);
    let extracted_target = extract_first_url(&classified);
    let drives_fsm = extracted_target.is_some() && i_have_authorization;

    // URL subject without auth is always a hard fail — it's offensive
    // by construction.
    if matches!(classified, InvestigateSubject::Url(_)) && !i_have_authorization {
        anyhow::bail!(
            "refusing to start: `mantis investigate <url>` issues HTTP probes against the target.\n\
             Re-run with --i-have-authorization once you have written permission."
        );
    }
    // File / prompt with embedded URL but no auth: drop to static
    // mode and let the operator know.
    if extracted_target.is_some() && !i_have_authorization && !json_mode {
        eprintln!(
            "[mantis investigate] target URL detected but --i-have-authorization not set; \
             dropping to read-only static investigation"
        );
    }

    // Pre-flight: parallel claude + mantis-mcp resolution + (when
    // driving the FSM) daemon-up check.
    let daemon_for_task = daemon.clone();
    let claude_bin_for_task = claude_bin.clone();
    let (claude_res, mcp_bin_res, daemon_res) = tokio::join!(
        tokio::task::spawn_blocking(move || resolve_claude_binary(claude_bin_for_task.as_deref())),
        tokio::task::spawn_blocking(|| which_bin("mantis-mcp")),
        {
            let daemon = daemon.clone();
            tokio::task::spawn_blocking(move || {
                if drives_fsm {
                    ensure_daemon_for_hack(&daemon).map(|_| true)
                } else {
                    // Best-effort — we still want MCP tools to work
                    // for read-only investigation, but don't fail if
                    // the daemon is down.
                    Ok(daemon_is_up(&daemon))
                }
            })
        },
    );
    let claude_path = claude_res.context("spawn_blocking(claude-resolve)")??;
    let mcp_bin = mcp_bin_res.context("spawn_blocking(mantis-mcp lookup)")?;
    let daemon_up = daemon_res.context("spawn_blocking(daemon-check)")??;
    if mcp_bin.is_some() {
        let claude_path_for_task = claude_path.clone();
        let _ = tokio::task::spawn_blocking(move || {
            ensure_mantis_mcp_registered_with_prefetched_helper(
                &claude_path_for_task,
                &daemon_for_task,
                mcp_bin,
            )
        })
        .await
        .context("spawn_blocking(mcp-register)")?;
    } else if !json_mode {
        eprintln!("[mantis investigate] note: `mantis-mcp` not on PATH — continuing without mantis_* tools.");
    }

    let claude_extra_args = apply_model_preference(claude_extra_args, false);

    // Build the prompts. The FSM path inlines the same orchestrator
    // role body `mantis hack` uses; the static path uses a leaner
    // read-only investigator prompt.
    let (subject_label, user_prompt, append_system_prompt) = if drives_fsm {
        let target_url = normalize_target_url(extracted_target.as_deref().unwrap_or(""));
        build_fsm_investigator_prompts(&target_url, &classified)
    } else {
        build_static_investigator_prompts(&classified)
    };

    if !json_mode {
        eprintln!("[mantis investigate] subject: {subject_label}");
        eprintln!("[mantis investigate] claude:  {}", claude_path.display());
        eprintln!("[mantis investigate] daemon:  {} ({})", daemon, if daemon_up { "up" } else { "down" });
        eprintln!(
            "[mantis investigate] mode:    {}",
            if drives_fsm { "FSM (RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT)" } else { "static (read-only)" }
        );
    }

    // Open the markdown run log so every claude command is captured.
    let log_path = run_log::pick_log_path(extracted_target.as_deref());
    let run_log = match run_log::RunLog::open(log_path.clone(), "mantis investigate", &subject_label) {
        Ok(l) => {
            if !json_mode {
                eprintln!("[mantis investigate] log:     {} (pretty markdown)", log_path.display());
            }
            Some(l)
        }
        Err(_) => None,
    };
    if !json_mode {
        eprintln!();
    }

    // Driving the FSM uses run_claude_slash_command (Skill tool
    // disallowed, mirrors mantis hack). Static mode uses the
    // one-shot path with json/text streaming. Both go through
    // run_with_resume so an API error → auto-restart with the
    // current logs.md as context.
    let status = if drives_fsm {
        run_slash_with_resume(
            &claude_path,
            &claude_extra_args,
            run_log.as_ref(),
            &user_prompt,
            &append_system_prompt,
            default_max_resumes(),
            json_mode,
        )
        .await?
    } else {
        run_one_shot_with_resume(
            &claude_path,
            &claude_extra_args,
            run_log.as_ref(),
            &user_prompt,
            &append_system_prompt,
            default_max_resumes(),
            json_mode,
        )
        .await?
    };
    if let Some(log) = &run_log {
        let label = if status.success() {
            "success".to_string()
        } else {
            format!("exit {status}")
        };
        log.finalize(&label);
    }
    if !status.success() {
        anyhow::bail!("`claude` exited with status {status}");
    }
    if drives_fsm && !json_mode {
        eprintln!();
        eprintln!("[mantis investigate] investigation returned cleanly.");
        print_post_run_summary();
    }
    Ok(())
}

/// Extract the first URL-shaped substring from a subject. For
/// `InvestigateSubject::Url`, returns the URL itself; for `File`,
/// scans the body; for `Prompt`, scans the text.
fn extract_first_url(s: &InvestigateSubject) -> Option<String> {
    match s {
        InvestigateSubject::Url(u) => Some(u.clone()),
        InvestigateSubject::File { body, .. } => first_url_in_text(body),
        InvestigateSubject::Prompt(text) => first_url_in_text(text),
    }
}

/// Return the first `http://` or `https://` URL in `text`, stripped
/// of trailing punctuation common to prose contexts.
fn first_url_in_text(text: &str) -> Option<String> {
    let lowered = text.to_ascii_lowercase();
    let start = lowered.find("https://").or_else(|| lowered.find("http://"))?;
    let rest = &text[start..];
    let end = rest
        .find(|c: char| {
            c.is_whitespace()
                || matches!(c, '"' | '\'' | '`' | '<' | '>' | ')' | ',' | ';' | '\\')
        })
        .unwrap_or(rest.len());
    let url = rest[..end].trim_end_matches(|c: char| matches!(c, '.' | '!' | '?'));
    if url.len() <= 8 {
        None
    } else {
        Some(url.to_string())
    }
}

/// Build the (subject_label, user_prompt, system_prompt) triple for
/// the FSM-driving path. Mirrors `mantis hack`'s system+prompt
/// structure, but inlines the operator's investigation seed
/// (URL / file body / prompt) as priority context the orchestrator
/// must thread through to spawned hunters.
fn build_fsm_investigator_prompts(
    target_url: &str,
    classified: &InvestigateSubject,
) -> (String, String, String) {
    // Reuse the same orchestrator role body and argument format
    // mantis hack uses — we want the FSM-driving behavior to be
    // identical except for the priority context we inject below.
    let arguments = build_orchestrator_arguments(target_url, /* deep */ false, /* no_auth */ false, "default");
    let orchestrator_body = orchestrator_role_body(&arguments);

    let (label, priority_block) = match classified {
        InvestigateSubject::Url(url) => (
            format!("url:{url}"),
            format!(
                "The operator opened this investigation specifically to dig into the URL \
                 `{url}`. The orchestrator's RECON / AUTH / HUNT phases should weight that \
                 path heavily — wave fan-out must include at least one hunter whose surface \
                 brief is rooted at or under this URL."
            ),
        ),
        InvestigateSubject::File { path, body, truncated } => {
            let trunc = if *truncated { "\n(NOTE: file content was truncated at 64 KB.)" } else { "" };
            (
                format!("file:{}", path.display()),
                format!(
                    "The operator opened this investigation around a specific file: `{}`. \
                     The file body is included below — treat it as priority static-analysis \
                     context. Cross-reference its imports, endpoints, and patterns with the \
                     RECON output and steer hunter briefs toward the surfaces this file touches.{trunc}\n\n\
                     === FILE: {} ===\n\n```\n{body}\n```\n",
                    path.display(),
                    path.display(),
                ),
            )
        }
        InvestigateSubject::Prompt(text) => (
            format!("prompt:{}", text.chars().take(40).collect::<String>()),
            format!(
                "The operator opened this investigation with the following question / hunch:\n\n\
                 ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄\n\
                 {text}\n\
                 ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄\n\n\
                 Drive the FSM with this concern as priority context. Hunter briefs must \
                 reflect it; chain-builder must search for chains that confirm or refute it; \
                 the grader weights findings against this question when scoring."
            ),
        ),
    };

    let preauth_system_prompt = format!(
        "Non-interactive invocation by `mantis investigate`.\n\
         The operator has provided explicit written authorization for the target \
         `{target_url}` via the `--i-have-authorization` flag at the CLI gate. \
         The legal authorization gate AND the scope confirmation gate are \
         PRE-CONFIRMED for this session. Do not ask the user to re-confirm \
         either gate; the user is not interactive and cannot answer.\n\n\
         HARD RULES for this session:\n\
         - Do NOT use the `Skill` tool for anything. It is disabled.\n\
         - Do NOT shell out to `mantis hack`, `mantis investigate`, `mantis pentest`, or any \
           other `mantis` CLI command via `Bash`. The `mantis` binary spawned YOU; calling \
           it again is an infinite loop. Use only `mcp__mantis__*` tools and `Task` spawns \
           of the named subagents.\n\
         - The orchestrator role prompt is appended below. Drive the full FSM \
           (RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT). Spawn ≥3 \
           parallel hunters on every wave even if the surface count is low — the \
           investigation seed should always get its own dedicated hunter.\n\n\
         === PRIORITY INVESTIGATION CONTEXT (FROM THE OPERATOR) ===\n\n\
         {priority_block}\n\n\
         === ORCHESTRATOR ROLE PROMPT ===\n\n\
         {orchestrator_body}",
    );

    let user_prompt = format!(
        "Authorization granted at the CLI gate for `{target_url}`. \
         Scope confirmed: `{target_url}`. Both legal and scope gates are \
         PRE-CONFIRMED — do not re-ask the user.\n\
         Engagement input ($ARGUMENTS): {arguments}\n\n\
         This run was launched via `mantis investigate`, not `mantis hack` — \
         the operator has supplied priority investigation context in the system \
         prompt above. Make sure every phase respects it: weight RECON toward \
         the seeded path, ensure HUNT spawns at least one hunter rooted at it, \
         and have the grader / report-writer foreground findings that bear on \
         the seeded concern.\n\n\
         Begin the engagement now. Start with PHASE 1: RECON by calling \
         `mcp__mantis__mantis_init_session({{ target_domain, target_url, deep_mode }})` \
         and then spawning the recon agent via the `Task` tool. Drive the full \
         FSM. Do NOT use Skill. Do NOT shell out to `mantis`."
    );

    (label, user_prompt, preauth_system_prompt)
}

/// Build the (subject_label, user_prompt, system_prompt) triple for
/// the read-only investigation path (no target URL or no auth flag).
/// Uses MCP read tools + Read / Grep over the working directory.
fn build_static_investigator_prompts(
    classified: &InvestigateSubject,
) -> (String, String, String) {
    let common_system = "You are running under `mantis investigate` in READ-ONLY mode \
                         — no target URL was supplied (or no authorization was given), so no \
                         offensive HTTP traffic will be issued. You have access to the full \
                         Mantis MCP server (every `mcp__mantis__*` read tool) and may spawn \
                         specialized sub-agents via `Task` for non-network work.\n\n\
                         Available pure-utility leaf tools (call them on raw evidence):\n\
                         - `mantis_decode_jwt`, `mantis_diff_responses`, `mantis_summarize_url`\n\
                         - `mantis_extract_secrets`, `mantis_extract_html_forms`, `mantis_extract_links`\n\
                         - `mantis_hash_request`, `mantis_score_finding`\n\n\
                         RULES:\n\
                         - Do NOT shell out to `mantis hack` / `mantis investigate` via Bash.\n\
                         - Do NOT issue offensive HTTP traffic. If you find that you need it, \
                           tell the user to re-run with `mantis investigate <url> --i-have-authorization`.\n\
                         - Read existing engagement state via `mantis_read_findings`, \
                           `mantis_read_chain_attempts`, `mantis_read_verification_round`, \
                           `mantis_read_http_audit`. Use `Read` / `Grep` / `Glob` on the cwd.\n\
                         - Lead with the bottom-line answer; back it up with evidence; tell \
                           the user what to do next.";

    match classified {
        InvestigateSubject::Url(url) => (
            format!("url:{url}"),
            format!(
                "Investigate this URL passively: `{url}`\n\n\
                 No authorization was given, so do not issue HTTP probes. \
                 What you CAN do: parse / classify the URL (`mantis_summarize_url`), \
                 check existing engagement artifacts for any prior probes against this \
                 host (`mantis_read_http_audit`, `mantis_read_findings`), and reason \
                 about likely vulnerabilities given the URL shape and the codebase. \
                 If a live probe is necessary, tell the user to re-run with `--i-have-authorization`."
            ),
            common_system.to_string(),
        ),
        InvestigateSubject::File { path, body, truncated } => {
            let trunc = if *truncated { "\n(NOTE: file content was truncated at 64 KB.)" } else { "" };
            (
                format!("file:{}", path.display()),
                format!(
                    "Investigate this file carefully: `{}`{trunc}\n\n\
                     Static analysis only. Use:\n\
                     - `Read` / `Grep` / `Glob` to walk the surrounding repo\n\
                     - `mantis_extract_secrets` to scan for leaked credentials\n\
                     - `mantis_extract_links` to discover referenced URLs / hosts\n\
                     - `mantis_summarize_url` on every URL you discover\n\n\
                     Look for: hardcoded secrets, unsafe patterns, broken auth checks, \
                     missing input validation, SQL injection / SSRF / RCE primitives, \
                     untrusted-input → privileged-action sinks, mass-assignment risks. \
                     Report ranked by severity. Tell the user concretely what to do next.\n\n\
                     === FILE: {} ===\n\n```\n{body}\n```\n",
                    path.display(),
                    path.display()
                ),
                common_system.to_string(),
            )
        }
        InvestigateSubject::Prompt(text) => {
            let label = text.chars().take(40).collect::<String>();
            (
                format!("prompt:{label}"),
                format!(
                    "Investigate this matter carefully: {text}\n\n\
                     Free-form prompt — no target URL was extracted. Decide what's needed:\n\
                     - If it references an existing engagement / finding, walk the artifacts \
                       on disk (`Read` / `Grep`) and via MCP read tools \
                       (`mantis_read_findings`, `mantis_read_chain_attempts`, \
                       `mantis_read_verification_round`).\n\
                     - If it's a question about the codebase, answer from the artifacts available.\n\
                     - If it references a target that should be probed live, refuse and tell \
                       the user to re-run with `mantis investigate <url> --i-have-authorization`.\n\n\
                     Lead with the bottom-line answer; back it up with evidence; tell the \
                     user what to do next."
                ),
                common_system.to_string(),
            )
        }
    }
}


/// Like [`run_claude_slash_command`] but for the `mantis prompt`
/// surface: skips `--disallowed-tools Skill` (the prompt path
/// doesn't have an orchestrator that could be derailed by it), and
/// optionally streams raw `stream-json` events to stdout when the
/// caller asked for `--output-format json`.
/// Build a resume prompt that seeds the new claude session with
/// the prior log tail plus the original task. The new claude reads
/// what already happened, then continues from where the previous
/// session failed.
fn build_resume_prompt(original_prompt: &str, reason: &str, log_tail: &str) -> String {
    format!(
        "AUTO-RESUME from a previous Mantis session that failed.\n\n\
         REASON: {reason}\n\n\
         The earlier session was recording every tool call, sub-agent spawn, \
         and assistant turn into a structured markdown log. The most recent \
         portion of that log is included below — read it carefully so you do \
         not redo work that already completed, and so you understand what \
         state the engagement is in.\n\n\
         === PRIOR RUN LOG TAIL (most recent first / newest at the bottom) ===\n\n\
         {log_tail}\n\n\
         === END LOG ===\n\n\
         Now CONTINUE from where the previous session left off. Re-run the \
         original task below; the MCP server, daemon, and any in-flight \
         engagement state are still present, so prefer reading existing \
         artifacts via `mantis_read_*` tools before re-doing finished work.\n\n\
         === ORIGINAL TASK ===\n\n{original_prompt}"
    )
}

/// Auto-resume wrapper around `run_claude_slash_command`. On any
/// non-success exit OR mid-stream API-error detection, reads the
/// run log tail and re-spawns `claude --print` with a resume
/// prompt that includes the log. Capped at `max_resumes` retries.
async fn run_slash_with_resume(
    claude_path: &std::path::Path,
    extra_args: &[String],
    log: Option<&run_log::RunLog>,
    base_prompt: &str,
    base_system: &str,
    max_resumes: u32,
    json_mode: bool,
) -> Result<std::process::ExitStatus> {
    let mut prompt = base_prompt.to_string();
    let mut attempt: u32 = 0;
    loop {
        let (status, err) = run_claude_slash_command(
            claude_path, &prompt, base_system, extra_args, log,
        )
        .await?;
        if err.is_none() && status.success() {
            return Ok(status);
        }
        if attempt >= max_resumes {
            log_resume_exhausted(json_mode, max_resumes, status, err.as_deref());
            return Ok(status);
        }
        attempt += 1;
        let reason = err.unwrap_or_else(|| format!("exit {status}"));
        log_resume_attempt(json_mode, attempt, max_resumes, &reason);
        prompt = prepare_resume_prompt(log, base_prompt, &reason, attempt);
    }
}

/// Auto-resume wrapper around `run_claude_one_shot`.
async fn run_one_shot_with_resume(
    claude_path: &std::path::Path,
    extra_args: &[String],
    log: Option<&run_log::RunLog>,
    base_prompt: &str,
    base_system: &str,
    max_resumes: u32,
    json_mode: bool,
) -> Result<std::process::ExitStatus> {
    let mut prompt = base_prompt.to_string();
    let mut attempt: u32 = 0;
    loop {
        let (status, err) = run_claude_one_shot(
            claude_path, &prompt, base_system, extra_args, json_mode, log,
        )
        .await?;
        if err.is_none() && status.success() {
            return Ok(status);
        }
        if attempt >= max_resumes {
            log_resume_exhausted(json_mode, max_resumes, status, err.as_deref());
            return Ok(status);
        }
        attempt += 1;
        let reason = err.unwrap_or_else(|| format!("exit {status}"));
        log_resume_attempt(json_mode, attempt, max_resumes, &reason);
        prompt = prepare_resume_prompt(log, base_prompt, &reason, attempt);
    }
}

fn log_resume_attempt(json_mode: bool, attempt: u32, max_resumes: u32, reason: &str) {
    if json_mode {
        return;
    }
    eprintln!();
    eprintln!(
        "[mantishack] ⚠ claude session failed — auto-resume #{attempt}/{max_resumes} \
         (reason: {reason})"
    );
}

fn log_resume_exhausted(
    json_mode: bool,
    max_resumes: u32,
    status: std::process::ExitStatus,
    reason: Option<&str>,
) {
    if json_mode {
        return;
    }
    eprintln!(
        "[mantishack] auto-resume budget exhausted ({max_resumes} retries used). \
         Final status: {status}, reason: {}",
        reason.unwrap_or("non-zero exit")
    );
}

fn prepare_resume_prompt(
    log: Option<&run_log::RunLog>,
    base_prompt: &str,
    reason: &str,
    attempt: u32,
) -> String {
    let log_tail = log
        .and_then(|l| run_log::tail(l.path(), 32 * 1024))
        .unwrap_or_else(|| "(no prior log available)".into());
    if let Some(l) = log {
        let _ = run_log::append_resume_header(l.path(), attempt, reason);
    }
    build_resume_prompt(base_prompt, reason, &log_tail)
}

async fn run_claude_one_shot(
    claude_path: &std::path::Path,
    prompt: &str,
    append_system_prompt: &str,
    extra_args: &[String],
    json_mode: bool,
    log: Option<&run_log::RunLog>,
) -> Result<(std::process::ExitStatus, Option<String>)> {
    use tokio::io::AsyncBufReadExt;

    let cwd = std::env::current_dir().context("get cwd")?;
    let mut cmd = tokio::process::Command::new(claude_path);
    cmd.arg("--print")
        .arg("--dangerously-skip-permissions")
        .arg("--output-format")
        .arg("stream-json")
        .arg("--verbose")
        .arg("--add-dir")
        .arg(&cwd)
        .arg("--append-system-prompt")
        .arg(append_system_prompt)
        .arg(prompt);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("exec `{}`", claude_path.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("claude child has no stdout pipe"))?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();

    let mut api_error: Option<String> = None;
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        if json_mode {
            // Pass through raw stream-json — that's the contract for
            // `--output-format json` scripting. Still record into the
            // markdown log so the operator gets a human-readable
            // mirror of the run.
            if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&line) {
                if let Some(log) = log {
                    log.record(&ev);
                }
                if api_error.is_none() {
                    api_error = run_log::detect_api_error(&ev);
                }
            }
            println!("{line}");
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(event) => {
                if let Some(log) = log {
                    log.record(&event);
                }
                if api_error.is_none() {
                    api_error = run_log::detect_api_error(&event);
                }
                if let Some(pretty) = format_stream_event(&event) {
                    eprintln!("{pretty}");
                }
            }
            Err(_) => eprintln!("{line}"),
        }
    }
    let status = child.wait().await?;
    Ok((status, api_error))
}

/// `mantis status` — one-shot snapshot of the local Mantis setup.
fn handle_status(output_format: String, daemon: String) -> Result<()> {
    let json_mode = output_format == "json";
    let saved_model = model_picker::load_saved();
    let env_model = std::env::var("MANTIS_MODEL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let project_cfg = project_config::load().ok().flatten();
    let project_model = project_cfg
        .as_ref()
        .and_then(|(_, c)| c.model.clone())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    // Effective model resolution mirrors apply_model_preference:
    // env > .mantis.json > ~/.Mantis/model > none.
    let (effective_model, effective_source) = if let Some(m) = env_model.as_ref() {
        (Some(m.clone()), "MANTIS_MODEL env")
    } else if let Some(m) = project_model.as_ref() {
        (Some(m.clone()), ".mantis.json")
    } else if let Some(m) = saved_model.as_ref() {
        (Some(m.clone()), "~/.Mantis/model")
    } else {
        (None, "claude default")
    };
    let claude_path = which_bin("claude");
    let mcp_bin = which_bin("mantis-mcp");
    let daemon_bin = which_bin("mantis-daemon");
    let daemon_up = daemon_is_up(&daemon);
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let mantis_home = home.as_ref().map(|h| h.join(".Mantis"));
    let pid_file = mantis_home.as_ref().map(|d| d.join("daemon.pid"));
    let log_file = mantis_home.as_ref().map(|d| d.join("daemon.log"));
    let daemon_pid = pid_file
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse::<u32>().ok());

    let mcp_registered = match &claude_path {
        Some(c) => std::process::Command::new(c)
            .args(["mcp", "get", "mantis"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        None => false,
    };

    if json_mode {
        let v = serde_json::json!({
            "daemon": {
                "endpoint": daemon,
                "up": daemon_up,
                "binary_on_path": daemon_bin.as_ref().map(|p| p.display().to_string()),
                "pid": daemon_pid,
                "pid_file": pid_file.as_ref().map(|p| p.display().to_string()),
                "log_file": log_file.as_ref().map(|p| p.display().to_string()),
            },
            "claude": {
                "binary_on_path": claude_path.as_ref().map(|p| p.display().to_string()),
                "mantis_mcp_registered": mcp_registered,
            },
            "mcp": {
                "binary_on_path": mcp_bin.as_ref().map(|p| p.display().to_string()),
            },
            "model": {
                "effective": effective_model,
                "effective_source": effective_source,
                "saved": saved_model,
                "env": env_model,
                "project": project_model,
                "file": mantis_home.as_ref().map(|d| d.join("model").display().to_string()),
                "resolution_order": ["cli --model flag", "MANTIS_MODEL env", ".mantis.json", "~/.Mantis/model", "claude default"],
            },
            "project_config": project_cfg.as_ref().map(|(p, _)| p.display().to_string()),
            "mantis_home": mantis_home.as_ref().map(|p| p.display().to_string()),
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }

    println!("Mantis session status");
    println!();
    println!("  daemon:");
    println!("    endpoint:        {daemon}");
    println!("    up:              {}", if daemon_up { "yes" } else { "no" });
    if let Some(p) = &daemon_bin {
        println!("    binary:          {}", p.display());
    } else {
        println!("    binary:          (not on PATH)");
    }
    if let Some(pid) = daemon_pid {
        println!("    pid:             {pid}");
    }
    println!();
    println!("  claude:");
    if let Some(p) = &claude_path {
        println!("    binary:          {}", p.display());
        println!(
            "    mantis MCP:      {}",
            if mcp_registered { "registered" } else { "not registered (run `mantis init`)" }
        );
    } else {
        println!("    binary:          (not on PATH — install from https://claude.com/claude-code)");
    }
    println!();
    println!("  mantis-mcp:");
    println!(
        "    binary:          {}",
        mcp_bin.map(|p| p.display().to_string()).unwrap_or_else(|| "(not on PATH)".into())
    );
    println!();
    println!("  model:");
    match &effective_model {
        Some(id) => {
            let label = model_picker::find_by_id(id).map(|m| m.label).unwrap_or("custom");
            println!("    effective:       {id} ({label})");
            println!("    source:          {effective_source}");
        }
        None => {
            println!("    effective:       (none — claude default applies)");
        }
    }
    println!(
        "    env MANTIS_MODEL: {}",
        env_model.as_deref().unwrap_or("(unset)")
    );
    println!(
        "    .mantis.json:     {}",
        project_model.as_deref().unwrap_or("(no model key)")
    );
    println!(
        "    saved file:       {}",
        saved_model.as_deref().unwrap_or("(empty)")
    );
    if let Some((p, _)) = &project_cfg {
        println!();
        println!("  project config:   {}", p.display());
    }
    if let Some(h) = &mantis_home {
        println!();
        println!("  ~/.Mantis:       {}", h.display());
    }
    Ok(())
}

fn normalize_target_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        return target.to_string();
    }
    let stripped = target.trim_end_matches('/');
    let needs_http = stripped
        .split('/')
        .next()
        .map(host_port_is_likely_http)
        .unwrap_or(false);
    let scheme = if needs_http { "http" } else { "https" };
    format!("{scheme}://{stripped}/")
}

/// Pre-flight: make sure the daemon is reachable. If not, try to
/// spawn a fresh one using whichever `mantis-daemon` is on PATH.
fn ensure_daemon_for_hack(endpoint: &str) -> Result<()> {
    if daemon_is_up(endpoint) {
        eprintln!("[mantishack] daemon: up");
        return Ok(());
    }
    eprintln!("[mantishack] daemon: down at {endpoint} — attempting to spawn");
    let daemon_bin = which_bin("mantis-daemon").ok_or_else(|| {
        anyhow::anyhow!(
            "daemon is down at {endpoint} and `mantis-daemon` is not on PATH.\n\
             Install / wire up via the `mantis` setup screen (run `mantis`), then re-run."
        )
    })?;
    spawn_daemon_detached(&daemon_bin, endpoint)
        .with_context(|| format!("spawning mantis-daemon at {endpoint}"))?;
    Ok(())
}

/// Find the `claude` CLI binary, honoring `--claude-bin` /
/// `MANTIS_CLAUDE_BIN` if set, otherwise a plain PATH lookup.
fn resolve_claude_binary(override_path: Option<&camino::Utf8Path>) -> Result<std::path::PathBuf> {
    if let Some(p) = override_path {
        let pb: std::path::PathBuf = p.as_str().into();
        if !pb.exists() {
            anyhow::bail!("claude binary override {p} does not exist on disk");
        }
        return Ok(pb);
    }
    which_bin("claude").ok_or_else(|| {
        anyhow::anyhow!(
            "`claude` is not on PATH — install Claude Code from \
             https://claude.com/claude-code, then re-run `mantis hack`.\n\
             Or point at a specific binary with `--claude-bin <path>` / \
             `MANTIS_CLAUDE_BIN=<path>`."
        )
    })
}

/// Idempotent. Probe `claude mcp get mantis`; if it fails, register
/// `mantis-mcp` as a user-scope MCP server pointing at the daemon
/// endpoint we'll be using.
fn ensure_mantis_mcp_registered(claude_path: &std::path::Path, daemon_endpoint: &str) -> Result<()> {
    let mcp_bin_prefetched = which_bin("mantis-mcp");
    ensure_mantis_mcp_registered_with_prefetched_helper(claude_path, daemon_endpoint, mcp_bin_prefetched)
}

/// Same as [`ensure_mantis_mcp_registered`] but takes the
/// `mantis-mcp` binary path as a prefetched lookup so we don't
/// re-walk `PATH` after a parallel pre-flight already did the walk.
fn ensure_mantis_mcp_registered_with_prefetched_helper(
    claude_path: &std::path::Path,
    daemon_endpoint: &str,
    mcp_bin_prefetched: Option<std::path::PathBuf>,
) -> Result<()> {
    let probe = std::process::Command::new(claude_path)
        .args(["mcp", "get", "mantis"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if matches!(probe, Ok(s) if s.success()) {
        eprintln!("[mantishack] mcp:    `mantis` already registered with claude");
        return Ok(());
    }
    eprintln!("[mantishack] mcp:    registering `mantis` MCP server with claude");
    let mcp_bin = mcp_bin_prefetched.ok_or_else(|| {
        anyhow::anyhow!(
            "`mantis-mcp` is not on PATH. Install Mantis (`mantis` setup screen, \
             `cargo install --path crates/mantis-mcp`, or `npm i -g mantishack`), \
             then re-run."
        )
    })?;
    // Best-effort cleanup of any prior registration so add succeeds.
    let _ = std::process::Command::new(claude_path)
        .args(["mcp", "remove", "mantis", "-s", "user"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let status = std::process::Command::new(claude_path)
        .args([
            "mcp",
            "add",
            "mantis",
            "-s",
            "user",
            "--",
            mcp_bin.to_string_lossy().as_ref(),
            "--daemon",
            daemon_endpoint,
        ])
        .status()
        .context("invoke `claude mcp add`")?;
    if !status.success() {
        anyhow::bail!("`claude mcp add` exited with status {status}");
    }
    Ok(())
}

/// `mantis init` — wire plugin + MCP + daemon in one command. Used
/// both manually and by the npm shim on first invocation.
fn handle_init(
    plugin_src: Option<Utf8PathBuf>,
    no_daemon: bool,
    no_mcp: bool,
    no_plugin: bool,
    daemon_endpoint: String,
    project: bool,
) -> Result<()> {
    println!("Mantis init — wiring plugin + MCP + daemon");

    if !no_plugin {
        let src = resolve_plugin_src(plugin_src.as_ref())?;
        copy_claude_plugin(&src)?;
    } else {
        println!("  plugin:  skipped (--no-plugin)");
    }

    if !no_mcp {
        let claude = which_bin("claude").ok_or_else(|| {
            anyhow::anyhow!(
                "`claude` is not on PATH — install Claude Code from \
                 https://claude.com/claude-code, then re-run `mantis init`."
            )
        })?;
        ensure_mantis_mcp_registered(&claude, &daemon_endpoint)?;
    } else {
        println!("  mcp:     skipped (--no-mcp)");
    }

    if !no_daemon {
        if daemon_is_up(&daemon_endpoint) {
            println!("  daemon:  already running at {daemon_endpoint}");
        } else {
            let daemon_bin = which_bin("mantis-daemon").ok_or_else(|| {
                anyhow::anyhow!(
                    "`mantis-daemon` is not on PATH. Install via `npm i -g mantishack`, \
                     `cargo install --path crates/mantis-daemon`, or curl-install."
                )
            })?;
            spawn_daemon_detached(&daemon_bin, &daemon_endpoint)?;
        }
    } else {
        println!("  daemon:  skipped (--no-daemon)");
    }

    if project {
        scaffold_project_files()?;
    }

    println!();
    println!("Ready.");
    println!("  In Claude Code:   /mantishack <target>");
    println!("  From the shell:   mantis hack <target> --i-have-authorization");
    println!("  Re-run anytime:   mantis init");
    if !project {
        println!("  Per-repo setup:   mantis init --project   (creates .mantis.json + MANTIS.md)");
    }
    Ok(())
}

/// Scaffold `.mantis.json` + `MANTIS.md` in the current directory.
/// Both writes are idempotent — existing files are skipped with a
/// log line, never overwritten.
fn scaffold_project_files() -> Result<()> {
    println!();
    println!("Scaffolding per-repo files:");
    let cwd = std::env::current_dir().context("get cwd")?;
    write_if_missing(
        &cwd.join(".mantis.json"),
        MANTIS_JSON_TEMPLATE,
        "  .mantis.json",
    )?;
    write_if_missing(
        &cwd.join("MANTIS.md"),
        MANTIS_MD_TEMPLATE,
        "  MANTIS.md",
    )?;
    Ok(())
}

fn write_if_missing(path: &std::path::Path, contents: &str, label: &str) -> Result<()> {
    if path.exists() {
        println!("{label}:  skipped (already exists)");
        return Ok(());
    }
    std::fs::write(path, contents)
        .with_context(|| format!("write {}", path.display()))?;
    println!("{label}:  created");
    Ok(())
}

const MANTIS_JSON_TEMPLATE: &str = r#"{
  "$schema": "https://github.com/deonmenezes/mantishack/blob/main/docs/site/cli/model.md",
  "_comment": "Per-repo Mantis defaults. Every key is optional; missing keys fall through to env / global. See https://github.com/deonmenezes/mantishack/blob/main/docs/site/cli/model.md",

  "model": null,
  "deep": false,
  "no_auth": false,
  "egress": "default",
  "daemon": null
}
"#;

const MANTIS_MD_TEMPLATE: &str = r#"# Mantis project notes

> Repo-level guidance for `mantis hack`, `mantis prompt`, and other Mantis subcommands when run in this directory. Loaded automatically alongside `.mantis.json`.

## Scope

<!-- Document the in-scope and out-of-scope hosts / paths / accounts for engagements run from this repo. -->

- **In scope:**  _e.g. `https://app.example.com/`, subdomains of `*.api.example.com`._
- **Out of scope:**  _e.g. shared SaaS, identity providers, third-party CDNs._

## Authorization

<!-- Who signed off, when, for how long. Mantis enforces the technical scope at the egress proxy but the legal gate is yours. -->

- **Authorized by:**  _name / contact_
- **Window:**  _start → end_
- **Disclosure path:**  _where to send confirmed findings_

## Test posture

<!-- Conventions and constraints specific to this engagement. -->

- Preferred severity floor for rendered reports: `low`
- Hunters should NOT touch: _e.g. `/admin/reset-all`, `/api/v1/billing/refund`_
- Auth profiles available: _e.g. `attacker`, `victim`, `admin`_

## Local config

`.mantis.json` in this repo pins per-engagement defaults (model, deep mode, no-auth, egress profile). The model-resolution chain is:

1. CLI flag    `-- --model …`
2. Env         `MANTIS_MODEL=…`
3. `.mantis.json` `"model"` key   ← this file's sibling
4. `~/.Mantis/model`              (set via `mantis model`)
5. Claude default

## Quick commands

```sh
mantis status                          # show current daemon / model / config
mantis model                           # pick a model interactively (Tab / Shift+Tab)
mantis hack <target> --i-have-authorization
mantis hack --print-prompt <target>    # debug the orchestrator prompt without running
mantis prompt "summarize the recent findings"
```
"#;


/// Resolve the plugin source dir: env override → ./plugin → error.
fn resolve_plugin_src(override_path: Option<&Utf8PathBuf>) -> Result<Utf8PathBuf> {
    if let Some(p) = override_path {
        if !p.as_std_path().is_dir() {
            anyhow::bail!("plugin src {p} is not a directory");
        }
        return Ok(p.clone());
    }
    if let Ok(env) = std::env::var("MANTIS_PLUGIN_SRC") {
        let p = Utf8PathBuf::from(env);
        if p.as_std_path().is_dir() {
            return Ok(p);
        }
    }
    let cwd_plugin = Utf8PathBuf::from("./plugin");
    if cwd_plugin.as_std_path().is_dir() {
        return Ok(cwd_plugin);
    }
    anyhow::bail!(
        "could not locate plugin source. Pass --plugin-src <path> or set MANTIS_PLUGIN_SRC."
    )
}

/// Copy `<plugin_src>/claude-code/` into `~/.claude/plugins/mantis/`.
/// Removes the previous install first so stale files don't linger.
fn copy_claude_plugin(plugin_src: &Utf8PathBuf) -> Result<()> {
    let src = plugin_src.join("claude-code");
    if !src.as_std_path().is_dir() {
        anyhow::bail!("plugin source has no `claude-code/` subdirectory: {plugin_src}");
    }
    let home = std::env::var("HOME").context("HOME not set")?;
    let dest = std::path::PathBuf::from(format!("{home}/.claude/plugins/mantis"));
    if dest.exists() {
        std::fs::remove_dir_all(&dest)
            .with_context(|| format!("remove existing plugin dir {}", dest.display()))?;
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create plugin parent {}", parent.display()))?;
    }
    copy_dir_recursive(src.as_std_path(), &dest)
        .with_context(|| format!("copy plugin -> {}", dest.display()))?;
    println!("  plugin:  installed at {}", dest.display());
    Ok(())
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}

/// Probe PATH for any supported AI-CLI provider. Used to decide
/// whether bare `mantis` should land on the prompt TUI or fall back
/// to the first-run setup screen.
fn has_any_ai_cli() -> bool {
    ["claude", "codex", "opencode", "gemini"]
        .iter()
        .any(|n| which_bin(n).is_some())
}

/// Look up an executable on the current `PATH`. Lightweight std-only
/// replacement for the `which` crate.
fn which_bin(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// TCP-connect probe to confirm the daemon's gRPC endpoint accepts
/// connections. Cheap and sync — avoids pulling tonic into this path.
fn daemon_is_up(endpoint: &str) -> bool {
    let addr = endpoint
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let addr = addr.split('/').next().unwrap_or(addr);
    let Ok(parsed) = addr.parse::<std::net::SocketAddr>() else {
        return false;
    };
    std::net::TcpStream::connect_timeout(&parsed, std::time::Duration::from_millis(250)).is_ok()
}

/// Spawn `mantis-daemon` in the background, detached from this
/// process so a `Ctrl-C` in this shell doesn't take it down. Stdio
/// goes to `~/.Mantis/daemon.log`, pid to `~/.Mantis/daemon.pid`.
fn spawn_daemon_detached(daemon_bin: &std::path::Path, endpoint: &str) -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let state_dir = std::path::PathBuf::from(format!("{home}/.Mantis"));
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("create {}", state_dir.display()))?;
    let log_path = state_dir.join("daemon.log");
    let pid_path = state_dir.join("daemon.pid");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let log_err = log.try_clone()?;

    let mut cmd = std::process::Command::new(daemon_bin);
    cmd.stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(log_err);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", daemon_bin.display()))?;
    let _ = std::fs::write(&pid_path, child.id().to_string());

    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(5) {
        if daemon_is_up(endpoint) {
            eprintln!(
                "[mantishack] daemon: started (pid {}, log {})",
                child.id(),
                log_path.display()
            );
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    anyhow::bail!(
        "daemon did not start listening on {endpoint} within 5s — check {}",
        log_path.display()
    );
}

/// The rich 7-phase orchestrator role prompt, baked into the binary
/// at compile time. We inline this rather than rely on slash-command
/// resolution because `claude --print` does NOT expand slash
/// commands — the model would see `/mantishack` as text and try to
/// resolve it via the `Skill` tool, which is exactly the recursion
/// trap we're avoiding.
const ORCHESTRATOR_SLASH_COMMAND_SRC: &str =
    include_str!("../../../plugin/claude-code/commands/mantishack.md");

/// Strip the leading YAML frontmatter (between `---` lines) and
/// substitute `$ARGUMENTS` with the supplied target+flags string.
fn orchestrator_role_body(arguments: &str) -> String {
    let raw = ORCHESTRATOR_SLASH_COMMAND_SRC;
    let body = if raw.starts_with("---") {
        // Find the closing `---` of the frontmatter.
        let after_open = &raw[3..];
        match after_open.find("\n---\n").or_else(|| after_open.find("\r\n---\r\n")) {
            Some(pos) => {
                // pos is offset within after_open; advance past the closing fence + newline.
                let close_len = if after_open[pos..].starts_with("\r\n") { 7 } else { 5 };
                after_open[pos + close_len..].trim_start_matches('\n').to_string()
            }
            None => raw.to_string(),
        }
    } else {
        raw.to_string()
    };
    body.replace("$ARGUMENTS", arguments)
}

/// Reconstruct the slash-command-style argument string the
/// orchestrator references as `$ARGUMENTS`.
fn build_orchestrator_arguments(target_url: &str, deep: bool, no_auth: bool, egress: &str) -> String {
    let mut parts = vec![target_url.to_string()];
    if deep {
        parts.push("--deep".to_string());
    }
    if no_auth {
        parts.push("--no-auth".to_string());
    }
    if !egress.is_empty() && egress != "default" {
        parts.push(format!("--egress {egress}"));
    }
    parts.join(" ")
}

/// Run `claude --print --output-format stream-json` and pretty-print
/// each event live to the operator's terminal. The system prompt
/// inlines the orchestrator role and pre-grants both interactive
/// gates so the non-interactive session doesn't stall. The `Skill`
/// tool is disallowed to prevent skill-resolution recursion.
async fn run_claude_slash_command(
    claude_path: &std::path::Path,
    prompt: &str,
    append_system_prompt: &str,
    extra_args: &[String],
    log: Option<&run_log::RunLog>,
) -> Result<(std::process::ExitStatus, Option<String>)> {
    use tokio::io::AsyncBufReadExt;

    let cwd = std::env::current_dir().context("get cwd")?;
    let mut cmd = tokio::process::Command::new(claude_path);
    cmd.arg("--print")
        .arg("--dangerously-skip-permissions")
        .arg("--output-format")
        .arg("stream-json")
        .arg("--verbose")
        .arg("--disallowed-tools")
        .arg("Skill")
        .arg("--add-dir")
        .arg(&cwd)
        .arg("--append-system-prompt")
        .arg(append_system_prompt)
        .arg(prompt);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("exec `{}`", claude_path.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("claude child has no stdout pipe"))?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();

    let mut api_error: Option<String> = None;
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(event) => {
                if let Some(log) = log {
                    log.record(&event);
                }
                if api_error.is_none() {
                    api_error = run_log::detect_api_error(&event);
                }
                if let Some(pretty) = format_stream_event(&event) {
                    eprintln!("{pretty}");
                }
            }
            // Not JSON (e.g. claude warmup banner) — passthrough.
            Err(_) => eprintln!("{line}"),
        }
    }

    let status = child.wait().await?;
    Ok((status, api_error))
}

/// Convert one `--output-format stream-json` event into a human line
/// for the operator's terminal. Returns `None` to drop noisy events
/// (e.g. per-token partial deltas).
fn format_stream_event(event: &serde_json::Value) -> Option<String> {
    let ty = event.get("type")?.as_str()?;
    match ty {
        "system" => {
            let subtype = event
                .get("subtype")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            Some(format!("[mantishack] · session {subtype}"))
        }
        "assistant" => {
            let content = event.pointer("/message/content")?.as_array()?;
            let mut out = Vec::new();
            for block in content {
                let bty = block.get("type")?.as_str()?;
                match bty {
                    "tool_use" => {
                        let name = block.get("name").and_then(|s| s.as_str()).unwrap_or("?");
                        let args = summarize_tool_input(name, block.get("input"));
                        out.push(format!("[mantishack] → {name}({args})"));
                    }
                    "text" => {
                        let txt = block
                            .get("text")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("")
                            .trim();
                        if txt.is_empty() {
                            continue;
                        }
                        for raw_line in txt.lines() {
                            let line = raw_line.trim_end();
                            if line.is_empty() {
                                continue;
                            }
                            out.push(format!("[mantishack] · {line}"));
                        }
                    }
                    _ => {}
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(out.join("\n"))
            }
        }
        "user" => {
            let content = event.pointer("/message/content")?.as_array()?;
            for block in content {
                if block.get("type").and_then(|s| s.as_str()) == Some("tool_result") {
                    let is_error = block
                        .get("is_error")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    let marker = if is_error { "✗" } else { "✓" };
                    return Some(format!("[mantishack]   {marker} result"));
                }
            }
            None
        }
        "result" => {
            let subtype = event
                .get("subtype")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let cost = event
                .get("total_cost_usd")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0);
            let turns = event
                .get("num_turns")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            Some(format!(
                "[mantishack] · session {subtype} ({turns} turns, ${cost:.4})"
            ))
        }
        // Skip per-token partial chunks and any unknown event type to
        // avoid drowning the terminal.
        _ => None,
    }
}

fn summarize_tool_input(name: &str, input: Option<&serde_json::Value>) -> String {
    let Some(input) = input else {
        return String::new();
    };
    match name {
        "Task" => {
            let subtype = input
                .get("subagent_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let in_bg = input
                .get("run_in_background")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let suffix = if in_bg { ", background" } else { "" };
            format!("type={subtype}{suffix}")
        }
        n if n.starts_with("mcp__mantis__") => {
            let mut parts = Vec::new();
            for key in [
                "target_domain",
                "wave",
                "to_phase",
                "round",
                "auth_status",
                "profile_name",
            ] {
                if let Some(v) = input.get(key).and_then(serde_json::Value::as_str) {
                    let label = match key {
                        "to_phase" => format!("→{v}"),
                        _ => format!("{key}={v}"),
                    };
                    parts.push(label);
                }
            }
            parts.join(", ")
        }
        "Bash" => input
            .get("command")
            .and_then(serde_json::Value::as_str)
            .map(|c| {
                let preview: String = c.chars().take(60).collect();
                format!("`{preview}`")
            })
            .unwrap_or_default(),
        _ => input
            .as_object()
            .map(|m| format!("{} args", m.len()))
            .unwrap_or_default(),
    }
}

async fn handle_find_auth_bugs(
    target: String,
    supabase_signup: Option<String>,
    supabase_apikey: Option<String>,
    extra_paths: Vec<String>,
    attacker_profile: Option<Utf8PathBuf>,
    victim_profile: Option<Utf8PathBuf>,
    max_candidates: usize,
    max_endpoints_probed: usize,
    no_subdomain_expansion: bool,
    i_have_authorization: bool,
    output: Option<Utf8PathBuf>,
) -> Result<()> {
    if !i_have_authorization {
        anyhow::bail!(
            "refusing to start: find-auth-bugs runs offensive-security tests \
             (signup + multi-profile probing). Re-run with --i-have-authorization \
             once you have written permission for {target}."
        );
    }

    use mantis_auth::AuthProfile;
    use mantis_orchestrator::{find_auth_bugs, find_auth_bugs_with_profiles, write_archive, AuthBugConfig};

    let cfg = AuthBugConfig {
        target_url: target.clone(),
        supabase_signup_url: supabase_signup.clone(),
        supabase_apikey: supabase_apikey.clone(),
        max_candidates,
        max_endpoints_probed,
        no_subdomain_expansion,
        extra_paths,
    };

    eprintln!("[mantis-find-auth-bugs] target: {target}");

    // Decide which path: BYO profiles OR Supabase signup OR unauth-only.
    let byo_attacker = match &attacker_profile {
        Some(p) => {
            let bytes = std::fs::read(p).with_context(|| format!("read {p}"))?;
            let prof: AuthProfile =
                serde_json::from_slice(&bytes).with_context(|| format!("parse {p}"))?;
            eprintln!("[mantis-find-auth-bugs] BYO attacker profile: {p}");
            Some(prof)
        }
        None => None,
    };
    let byo_victim = match &victim_profile {
        Some(p) => {
            let bytes = std::fs::read(p).with_context(|| format!("read {p}"))?;
            let prof: AuthProfile =
                serde_json::from_slice(&bytes).with_context(|| format!("parse {p}"))?;
            eprintln!("[mantis-find-auth-bugs] BYO victim profile: {p}");
            Some(prof)
        }
        None => None,
    };
    let using_byo = byo_attacker.is_some() || byo_victim.is_some();

    if using_byo {
        if supabase_signup.is_some() {
            eprintln!(
                "[mantis-find-auth-bugs] BYO profiles supplied — ignoring --supabase-signup"
            );
        }
    } else if supabase_signup.is_some()
        && supabase_apikey.as_deref().map(str::is_empty) != Some(false)
    {
        eprintln!(
            "[mantis-find-auth-bugs] supabase signup configured but apikey is empty — running unauth-only"
        );
    } else if let Some(url) = &supabase_signup {
        eprintln!("[mantis-find-auth-bugs] supabase signup: {url}");
    } else {
        eprintln!("[mantis-find-auth-bugs] no supabase signup — running unauth-only");
    }
    eprintln!(
        "[mantis-find-auth-bugs] caps: max_candidates={} max_endpoints_probed={}",
        max_candidates, max_endpoints_probed
    );

    let started = std::time::Instant::now();
    let report = if using_byo {
        find_auth_bugs_with_profiles(&cfg, byo_attacker, byo_victim)
            .await
            .map_err(|e| anyhow::anyhow!("pipeline: {e}"))?
    } else {
        find_auth_bugs(&cfg)
            .await
            .map_err(|e| anyhow::anyhow!("pipeline: {e}"))?
    };
    let elapsed = started.elapsed();

    eprintln!();
    eprintln!("============================================================");
    eprintln!("Mantis find-auth-bugs — summary");
    eprintln!("============================================================");
    if let Some(e) = &report.attacker_email {
        eprintln!("Attacker email:           {e}");
    }
    if let Some(e) = &report.victim_email {
        eprintln!("Victim email:             {e}");
    }
    eprintln!("Endpoints probed:         {}", report.endpoints_probed);
    eprintln!("Endpoints with findings:  {}", report.endpoints_with_findings);
    eprintln!("Findings total:           {}", report.findings_total);
    eprintln!("Elapsed:                  {:.2}s", elapsed.as_secs_f64());
    if !report.findings_by_severity.is_empty() {
        eprintln!("By severity:");
        for sev in ["critical", "high", "medium", "low", "info"] {
            if let Some(n) = report.findings_by_severity.get(sev) {
                eprintln!("  {sev:10} {n:>3}");
            }
        }
    }
    if !report.findings_by_class.is_empty() {
        eprintln!("By class:");
        for (k, v) in &report.findings_by_class {
            eprintln!("  {k:60} {v:>3}");
        }
    }

    // Top-N per-endpoint with findings.
    let endpoints_with_hits: Vec<_> = report
        .per_endpoint
        .iter()
        .filter(|e| !e.findings.is_empty())
        .collect();
    if !endpoints_with_hits.is_empty() {
        eprintln!();
        eprintln!("Endpoints with findings:");
        for ep in &endpoints_with_hits {
            eprintln!("  {} ({} finding(s))", ep.url, ep.findings.len());
            for f in &ep.findings {
                eprintln!(
                    "    [{:?}] severity={} hash={}",
                    f.class,
                    f.class.default_severity(),
                    &f.finding_hash[..16.min(f.finding_hash.len())]
                );
            }
        }
    }

    // JSON output.
    let host = host_from_target(&target);
    let default_out = Utf8PathBuf::from(format!(
        "reports/{}/find-auth-bugs-{}.json",
        host,
        ulid::Ulid::new()
    ));
    let out_path = output.unwrap_or(default_out);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).context("create output dir")?;
    }
    std::fs::write(&out_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write {out_path}"))?;
    eprintln!();
    eprintln!("[mantis-find-auth-bugs] JSON report: {out_path}");

    // Auto-archive: write per-target folder with per-finding markdown
    // files, phases/, timeline.md, vulnerability-report.md, README.md.
    let engagement_id = format!("AB-{}", ulid::Ulid::new());
    let reports_root = std::path::Path::new("reports");
    match write_archive(&report, &engagement_id, reports_root) {
        Ok(outcome) => {
            eprintln!("[mantis-find-auth-bugs] archive root:        {}", outcome.root.display());
            eprintln!("[mantis-find-auth-bugs] readme:              {}", outcome.readme.display());
            eprintln!("[mantis-find-auth-bugs] vulnerability-report: {}", outcome.vuln_report.display());
            eprintln!("[mantis-find-auth-bugs] findings written:    {}", outcome.finding_count);

            // Optional LLM-augmented executive summary appended to
            // vulnerability-report.md. Best-effort; never blocks.
            if let Some((adapter, provider)) = llm_pick::pick() {
                eprintln!(
                    "[mantis-find-auth-bugs] LLM provider: {} (drafting executive summary)",
                    provider.label()
                );
                let summary = build_findings_summary(&target, &report, elapsed);
                llm_pick::append_exec_summary(adapter.as_ref(), &outcome.vuln_report, &summary).await;
            }
        }
        Err(e) => eprintln!("[mantis-find-auth-bugs] archive error: {e}"),
    }
    Ok(())
}

/// Short, factual blob fed to the LLM for the executive summary.
/// Stays under ~2KB so it's cheap and fits in any model's context.
fn build_findings_summary(
    target: &str,
    report: &mantis_orchestrator::AuthBugReport,
    elapsed: std::time::Duration,
) -> String {
    let mut s = String::new();
    s.push_str(&format!("Target: {target}\n"));
    s.push_str(&format!("Elapsed: {:.2}s\n", elapsed.as_secs_f64()));
    s.push_str(&format!("Endpoints probed: {}\n", report.endpoints_probed));
    s.push_str(&format!(
        "Endpoints with findings: {}\n",
        report.endpoints_with_findings
    ));
    s.push_str(&format!("Findings total: {}\n", report.findings_total));
    if !report.findings_by_severity.is_empty() {
        s.push_str("By severity:\n");
        for sev in ["critical", "high", "medium", "low", "info"] {
            if let Some(n) = report.findings_by_severity.get(sev) {
                s.push_str(&format!("  {sev}: {n}\n"));
            }
        }
    }
    if !report.findings_by_class.is_empty() {
        s.push_str("By class:\n");
        for (k, v) in report.findings_by_class.iter().take(10) {
            s.push_str(&format!("  {k}: {v}\n"));
        }
    }
    let with_hits: Vec<_> = report
        .per_endpoint
        .iter()
        .filter(|e| !e.findings.is_empty())
        .take(10)
        .collect();
    if !with_hits.is_empty() {
        s.push_str("Top endpoints with findings:\n");
        for ep in &with_hits {
            s.push_str(&format!("  {} ({} finding(s))\n", ep.url, ep.findings.len()));
        }
    }
    s
}

/// Crude host extraction for output-folder naming.
fn host_from_target(t: &str) -> String {
    let s = t
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = s.split(['/', '?', '#']).next().unwrap_or("unknown");
    let host = host.split(':').next().unwrap_or("unknown");
    host.trim_start_matches("www.").to_string()
}

fn severity_counts(
    findings: &[mantis_auth_differential::DiffFinding],
) -> std::collections::BTreeMap<String, u32> {
    let mut out = std::collections::BTreeMap::new();
    for f in findings {
        *out.entry(f.class.default_severity().to_string()).or_default() += 1;
    }
    out
}

#[derive(Debug)]
enum TargetKind {
    WebUrl(String),
    Domain(String),
    PackagedApp {
        path: Utf8PathBuf,
        kind: &'static str,
    },
}

fn classify_target(target: &str) -> TargetKind {
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return TargetKind::WebUrl(target.to_owned());
    }
    let path = std::path::Path::new(target);
    if path.exists() {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let kind = match ext.as_str() {
            "apk" => Some("android"),
            "ipa" => Some("ios"),
            "exe" => Some("windows-pe"),
            "dmg" => Some("macos-dmg"),
            "app" => Some("macos-app"),
            _ => None,
        };
        if let Some(k) = kind {
            return TargetKind::PackagedApp {
                path: Utf8PathBuf::from(target),
                kind: k,
            };
        }
    }
    // Treat as bare domain — prefix https://
    TargetKind::Domain(format!("https://{target}"))
}

async fn extract_urls_from_binary(path: &Utf8PathBuf) -> Result<Vec<String>> {
    // Best-effort URL extraction via the `strings` utility. Operator
    // installs strings (binutils) if they want richer parsing; this
    // covers .apk, .ipa, .exe, .dmg, .app without per-format SDKs.
    let output = tokio::process::Command::new("strings")
        .arg(path.as_str())
        .output()
        .await;
    let stdout = match output {
        Ok(o) if o.status.success() => o.stdout,
        _ => {
            // Fallback: read the file and scan for URL substrings.
            std::fs::read(path).with_context(|| format!("read {path}"))?
        }
    };
    let mut urls: std::collections::BTreeSet<String> = Default::default();
    let text = String::from_utf8_lossy(&stdout);
    for token in text.split(|c: char| {
        !matches!(c,
            'A'..='Z' | 'a'..='z' | '0'..='9' |
            '/' | ':' | '?' | '&' | '=' | '%' | '.' | '-' | '_' | '~'
        )
    }) {
        if token.starts_with("https://") || token.starts_with("http://") {
            let trimmed = token.trim_end_matches(['.', ',', ';', '"', '\'', ')', '}']);
            if trimmed.len() > 8 {
                urls.insert(trimmed.to_owned());
            }
        }
    }
    Ok(urls.into_iter().collect())
}

fn build_signed_scope_json(
    engagement_id: &str,
    urls: &[String],
    budget_seconds: u32,
) -> Result<String> {
    use mantis_core::{EngagementId, Signer};
    use mantis_scope::budget::BudgetEnvelope;
    use mantis_scope::host_pattern::HostPattern;
    use mantis_scope::manifest::{Protocol, ScopeManifest, ScopeRules};
    use mantis_scope::port_range::PortMatcher;
    use mantis_scope::signed::SignedScope;
    use mantis_workspace::keystore::KeyStore;
    use mantis_workspace::{
        default_workspace_root, operator_keystore_service, Keypair, OsKeyStore, Workspace,
    };
    use ulid::Ulid;

    let root = default_workspace_root();
    let keystore = OsKeyStore::new();
    let workspace = Workspace::open(&root, &keystore)
        .context("open workspace (run `mantis workspace init` first)")?;

    let operator = workspace
        .list_operators()
        .ok()
        .and_then(|ops| ops.into_iter().next())
        .ok_or_else(|| {
            anyhow::anyhow!("no operator yet — run `mantis operator create <name>` first")
        })?;

    let operator_secret = keystore
        .get(&operator_keystore_service(operator.id), "signing-key")
        .context("read operator signing key from OS keystore")?;
    let secret_arr: [u8; 32] = operator_secret
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("operator key wrong length"))?;
    let operator_keypair = Keypair::from_secret_bytes(&secret_arr);

    let hosts: std::collections::BTreeSet<String> =
        urls.iter().filter_map(|u| url_host(u)).collect();
    let host_patterns: Vec<HostPattern> = hosts.into_iter().map(HostPattern::new).collect();

    let ports: std::collections::BTreeSet<u16> = urls.iter().filter_map(|u| url_port(u)).collect();
    let port_matchers: Vec<PortMatcher> = if ports.is_empty() {
        vec![PortMatcher::single(80), PortMatcher::single(443)]
    } else {
        ports.into_iter().map(PortMatcher::single).collect()
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let manifest = ScopeManifest {
        schema_version: 1,
        engagement_id: EngagementId(
            Ulid::from_string(engagement_id).context("parse engagement id")?,
        ),
        authorized_by: operator.id,
        expires_at_unix: now + budget_seconds as u64 + 600,
        budget: BudgetEnvelope {
            max_requests: 5_000,
            max_egress_bytes: 50_000_000,
            max_wall_clock_seconds: budget_seconds as u64,
            max_requests_per_second: 50,
        },
        include: ScopeRules {
            hosts: host_patterns,
            ports: port_matchers,
            paths: vec!["/*".into()],
            protocols: vec![Protocol::Http, Protocol::Https],
        },
        exclude: ScopeRules::default(),
    };

    struct OpSigner<'a>(&'a Keypair);
    impl<'a> Signer for OpSigner<'a> {
        fn sign(&self, context: &str, payload: &[u8]) -> [u8; 64] {
            self.0.sign(context, payload).to_bytes()
        }
        fn public_key_bytes(&self) -> [u8; 32] {
            *self.0.public().as_bytes()
        }
    }
    let _ = workspace; // silence unused warning; workspace open already validated
    let signed = SignedScope::create(manifest, &OpSigner(&operator_keypair))
        .context("sign scope manifest")?;
    Ok(serde_json::to_string(&signed)?)
}

fn url_port(u: &str) -> Option<u16> {
    let after_scheme = u.split_once("://")?.1;
    let authority = after_scheme.split('/').next()?;
    let (_, port) = authority.rsplit_once(':')?;
    port.parse::<u16>().ok()
}

fn url_host(u: &str) -> Option<String> {
    let after_scheme = u.split_once("://").map(|(_, rest)| rest).unwrap_or(u);
    let host = after_scheme
        .split('/')
        .next()?
        .split('?')
        .next()?
        .split('#')
        .next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.split(':').next().unwrap_or(host).to_owned())
    }
}

fn build_summary(name: &str, id: &str, target_kind: &TargetKind, info: &EngagementInfo) -> String {
    let kind_label = match target_kind {
        TargetKind::WebUrl(u) => format!("web URL ({u})"),
        TargetKind::Domain(u) => format!("domain ({u})"),
        TargetKind::PackagedApp { path, kind } => format!("{kind} app ({path})"),
    };
    format!(
        "============================================================\n\
         Mantishack — engagement summary\n\
         ============================================================\n\
         Name:        {name}\n\
         Engagement:  {id}\n\
         Target:      {kind_label}\n\
         State:       {}\n\
         Events:      {}\n\
         ============================================================\n\
         Next steps:\n\
           mantis claims {id}                  # list verified claims\n\
           mantis engagement report {id} --format pdf\n\
           mantis exploit <claim-id>           # export a reproducer\n",
        engagement_state_name(info.state),
        info.event_count
    )
}

async fn handle_llm(action: LlmAction) -> Result<()> {
    use mantis_synthesizer::{
        anthropic::AnthropicAdapter, claude_cli::ClaudeCliAdapter, openai::OpenAIAdapter,
        LlmAdapter,
    };
    match action {
        LlmAction::Probe {
            provider,
            model,
            prompt,
        } => {
            let result = match provider.as_str() {
                "anthropic" => {
                    let key = std::env::var("ANTHROPIC_API_KEY").context(
                        "ANTHROPIC_API_KEY is not set; export it and rerun `mantis llm probe`",
                    )?;
                    let mut adapter = AnthropicAdapter::new(key).with_max_tokens(16);
                    if let Some(m) = model {
                        adapter = adapter.with_model(m);
                    }
                    adapter.complete(&prompt).await
                }
                "openai" => {
                    let key = std::env::var("OPENAI_API_KEY")
                        .context("OPENAI_API_KEY is not set; export it and rerun")?;
                    let mut adapter = OpenAIAdapter::new(key).with_max_tokens(16);
                    if let Some(m) = model {
                        adapter = adapter.with_model(m);
                    }
                    adapter.complete(&prompt).await
                }
                "claude-cli" => {
                    let mut adapter = ClaudeCliAdapter::new();
                    if let Some(m) = model {
                        adapter = adapter.with_model(m);
                    }
                    adapter.complete(&prompt).await
                }
                other => anyhow::bail!(
                    "unknown provider `{other}`; supported: anthropic, openai, claude-cli"
                ),
            };
            match result {
                Ok(text) => {
                    println!("[mantis llm probe ok] provider={provider} reply={text:?}");
                    Ok(())
                }
                Err(e) => anyhow::bail!("provider call failed: {e}"),
            }
        }
    }
}

fn run_async<F: std::future::Future<Output = Result<()>>>(fut: F) -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(fut)
}

fn resolve_root(root: Option<Utf8PathBuf>) -> Utf8PathBuf {
    root.unwrap_or_else(default_workspace_root)
}

fn cmd_workspace_init(root: Option<Utf8PathBuf>) -> Result<()> {
    let root = resolve_root(root);
    let ks = OsKeyStore::new();
    let ws = Workspace::init(&root, &ks).context("initialize workspace")?;
    println!("Workspace initialized.");
    println!("  root:        {}", ws.root());
    println!("  id:          {}", ws.id());
    println!("  fingerprint: {}", ws.fingerprint());
    Ok(())
}

fn cmd_workspace_info(root: Option<Utf8PathBuf>) -> Result<()> {
    let root = resolve_root(root);
    let ks = OsKeyStore::new();
    let ws = Workspace::open(&root, &ks).context("open workspace")?;
    println!("Workspace:");
    println!("  root:           {}", ws.root());
    println!("  id:             {}", ws.id());
    println!("  fingerprint:    {}", ws.fingerprint());
    println!("  schema version: {}", ws.config().schema_version);
    println!("  created at:     {} (unix)", ws.config().created_at_unix);
    println!("  operators:      {}", ws.list_operators()?.len());
    Ok(())
}

fn cmd_operator_create(name: &str, root: Option<Utf8PathBuf>) -> Result<()> {
    let root = resolve_root(root);
    let ks = OsKeyStore::new();
    let ws = Workspace::open(&root, &ks).context("open workspace")?;
    let profile = ws.create_operator(name, &ks).context("create operator")?;
    println!("Operator created.");
    println!("  id:          {}", profile.id);
    println!("  name:        {}", profile.name);
    println!("  fingerprint: {}", profile.fingerprint());
    Ok(())
}

fn cmd_operator_list(root: Option<Utf8PathBuf>) -> Result<()> {
    let root = resolve_root(root);
    let ks = OsKeyStore::new();
    let ws = Workspace::open(&root, &ks).context("open workspace")?;
    let operators = ws.list_operators()?;
    if operators.is_empty() {
        println!("(no operators yet — run `mantis operator create <name>`)");
        return Ok(());
    }
    println!("{:<28} {:<24} {:<16}  CREATED", "ID", "NAME", "FINGERPRINT");
    for op in operators {
        println!(
            "{:<28} {:<24} {:<16}  {}",
            op.id, op.name, op.fingerprint, op.created_at_unix
        );
    }
    Ok(())
}

fn cmd_operator_delete(id_str: &str, root: Option<Utf8PathBuf>) -> Result<()> {
    use mantis_core::OperatorId;
    use ulid::Ulid;
    let ulid: Ulid = id_str.parse().context("parse operator id as ULID")?;
    let operator_id = OperatorId(ulid);

    let root = resolve_root(root);
    let ks = OsKeyStore::new();
    let ws = Workspace::open(&root, &ks).context("open workspace")?;
    ws.delete_operator(operator_id, &ks)
        .context("delete operator")?;
    println!("Operator {operator_id} deleted.");
    Ok(())
}

fn cmd_doctor(root: Option<Utf8PathBuf>, json: bool) -> Result<()> {
    let root = resolve_root(root);
    let ks = OsKeyStore::new();
    let report = run_doctor(&root, &ks).context("run doctor")?;
    let recon_inv = mantis_recon_tools::ToolInventory::scan();

    if json {
        let combined = serde_json::json!({
            "workspace": report,
            "recon_tools": recon_inv,
        });
        println!("{}", serde_json::to_string_pretty(&combined)?);
        return Ok(());
    }

    println!("Mantis doctor report:");
    println!("  workspace root:    {}", report.workspace_root);
    println!("  workspace exists:  {}", report.workspace_exists);
    if let Some(id) = &report.workspace_id {
        println!("  workspace id:      {id}");
    }
    if let Some(fp) = &report.fingerprint {
        println!("  fingerprint:       {fp}");
    }
    if let Some(v) = report.schema_version {
        println!("  schema version:    {v}");
    }
    println!("  operators:         {}", report.operator_count);
    println!("  keystore backend:  {}", report.keystore_backend);
    println!("  keystore working:  {}", report.keystore_available);

    // Optional recon tools — present or missing. Mantis runs without
    // any of these; their presence widens surface discovery.
    let installed = recon_inv.installed_count();
    let total = recon_inv.tools.len();
    println!();
    println!("Optional recon tools ({installed}/{total} installed):");
    for tool in &recon_inv.tools {
        let mark = if tool.installed { "✓" } else { "·" };
        let name = tool.kind.binary_name();
        let extra = if tool.installed {
            tool.version
                .as_deref()
                .map(|v| format!("  ({v})"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        println!("  {mark} {name:14}{extra}");
    }
    if installed < total {
        println!();
        println!("Install hints for missing tools:");
        for tool in recon_inv.tools.iter().filter(|t| !t.installed) {
            println!("  {}: {}", tool.kind.binary_name(), tool.kind.install_hint());
        }
    }

    if report.is_healthy() {
        println!("\nStatus: OK");
    } else if !report.keystore_available {
        println!("\nStatus: keystore unavailable");
    } else {
        println!("\nStatus: no workspace — run `mantis workspace init`");
    }
    Ok(())
}

async fn handle_engagement(action: EngagementAction) -> Result<()> {
    match action {
        EngagementAction::Create { name, daemon } => {
            let mut client = EngagementClient::connect(daemon)
                .await
                .context("connect to daemon")?;
            let resp = client.create(CreateRequest { name }).await?;
            print_engagement(resp.into_inner());
        }
        EngagementAction::Authorize { id, scope, daemon } => {
            let bytes = std::fs::read(scope.as_std_path()).context("read scope file")?;
            let mut client = EngagementClient::connect(daemon).await?;
            let resp = client
                .authorize(AuthorizeRequest {
                    id,
                    signed_scope_json: bytes,
                })
                .await?;
            print_engagement(resp.into_inner());
        }
        EngagementAction::Start { id, daemon } => {
            let mut client = EngagementClient::connect(daemon).await?;
            let resp = client.start(StartRequest { id }).await?;
            print_engagement(resp.into_inner());
        }
        EngagementAction::Pause { id, daemon } => {
            let mut client = EngagementClient::connect(daemon).await?;
            let resp = client.pause(PauseRequest { id }).await?;
            print_engagement(resp.into_inner());
        }
        EngagementAction::Status { id, daemon } => {
            let mut client = EngagementClient::connect(daemon).await?;
            let resp = client.status(StatusRequest { id }).await?;
            print_engagement(resp.into_inner());
        }
        EngagementAction::List { daemon } => {
            let mut client = EngagementClient::connect(daemon).await?;
            let resp = client.list(ListRequest {}).await?;
            let engs = resp.into_inner().engagements;
            if engs.is_empty() {
                println!("(no engagements)");
            } else {
                println!("{:<28} {:<20} {:<12} EVENTS", "ID", "NAME", "STATE");
                for e in engs {
                    println!(
                        "{:<28} {:<20} {:<12} {}",
                        e.id,
                        e.name,
                        state_label(e.state),
                        e.event_count
                    );
                }
            }
        }
        EngagementAction::Scan { id, target, daemon } => {
            let mut client = EngagementClient::connect(daemon).await?;
            let resp = client
                .scan(ScanRequest {
                    id,
                    targets: target,
                })
                .await?
                .into_inner();
            println!("Scan complete.");
            println!("  surfaces:   {}", resp.surfaces_recorded);
            println!("  hypotheses: {}", resp.hypotheses_recorded);
        }
        EngagementAction::Export { id, output, daemon } => {
            let mut client = EngagementClient::connect(daemon).await?;
            let resp = client.export(ExportRequest { id }).await?.into_inner();
            match output {
                Some(path) => {
                    std::fs::write(path.as_std_path(), &resp.jsonl).context("write export file")?;
                    eprintln!("wrote {} bytes to {}", resp.jsonl.len(), path);
                }
                None => {
                    use std::io::Write as _;
                    std::io::stdout()
                        .write_all(&resp.jsonl)
                        .context("write stdout")?;
                }
            }
        }
    }
    Ok(())
}

fn state_label(state: i32) -> &'static str {
    match ProtoEngagementState::try_from(state) {
        Ok(ProtoEngagementState::Draft) => "draft",
        Ok(ProtoEngagementState::Authorized) => "authorized",
        Ok(ProtoEngagementState::Active) => "active",
        Ok(ProtoEngagementState::Paused) => "paused",
        Ok(ProtoEngagementState::Completed) => "completed",
        Ok(ProtoEngagementState::Archived) => "archived",
        _ => "unknown",
    }
}

fn print_engagement(info: EngagementInfo) {
    println!("Engagement:");
    println!("  id:           {}", info.id);
    println!("  name:         {}", info.name);
    println!("  state:        {}", state_label(info.state));
    println!("  created_at:   {} (unix)", info.created_at_unix);
    println!("  events:       {}", info.event_count);
    if let Some(hash) = info.scope_hash {
        println!("  scope_hash:   {hash}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_https_is_url() {
        match classify_subject("https://app.example.com/users/42") {
            InvestigateSubject::Url(u) => {
                assert_eq!(u, "https://app.example.com/users/42");
            }
            other => panic!("expected Url, got {other:?}"),
        }
    }

    #[test]
    fn classify_http_is_url() {
        assert!(matches!(
            classify_subject("http://localhost:8080/admin"),
            InvestigateSubject::Url(_)
        ));
    }

    #[test]
    fn classify_existing_file_is_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "let x = 1;\n").unwrap();
        match classify_subject(tmp.path().to_str().unwrap()) {
            InvestigateSubject::File { path, body, truncated } => {
                assert_eq!(path, tmp.path());
                assert!(body.contains("let x"));
                assert!(!truncated);
            }
            other => panic!("expected File, got {other:?}"),
        }
    }

    #[test]
    fn classify_pathy_but_missing_falls_through_to_prompt() {
        // Looks like a path (starts with /) but doesn't exist on disk.
        let r = classify_subject("/this/path/does/not/exist.example");
        assert!(matches!(r, InvestigateSubject::Prompt(_)));
    }

    #[test]
    fn classify_free_text_is_prompt() {
        match classify_subject("does this IDOR claim hold up?") {
            InvestigateSubject::Prompt(t) => assert_eq!(t, "does this IDOR claim hold up?"),
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn classify_trims_whitespace() {
        match classify_subject("  https://example.com/  ") {
            InvestigateSubject::Url(u) => assert_eq!(u, "https://example.com/"),
            other => panic!("expected Url, got {other:?}"),
        }
    }

    #[test]
    fn classify_truncates_large_files() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // 80 KB of ASCII
        let big: String = "x".repeat(80 * 1024);
        std::fs::write(tmp.path(), &big).unwrap();
        match classify_subject(tmp.path().to_str().unwrap()) {
            InvestigateSubject::File { truncated, body, .. } => {
                assert!(truncated);
                assert_eq!(body.len(), 64 * 1024);
            }
            other => panic!("expected File, got {other:?}"),
        }
    }
}
