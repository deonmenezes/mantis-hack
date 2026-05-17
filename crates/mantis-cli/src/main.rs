//! Mantis CLI (`mantis`).
//!
//! Subcommands either operate on local workspace state directly
//! (workspace, operator, doctor) or talk to a running daemon via the
//! generated `mantis.v1.Engagement` gRPC client (engagement).

mod banner;

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

#[derive(Parser, Debug)]
#[command(name = "mantis", version, about = "Mantis daemon CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
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
        #[arg(long)]
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
    /// One-shot pentest. The simple command. Takes a single
    /// positional target (URL or bare domain), auto-discovers the
    /// auth stack from the target's HTML, signs up attacker +
    /// victim accounts when possible, enumerates endpoints, runs
    /// the auth-differential against everything, and archives the
    /// findings to `./reports/<host>/`.
    ///
    /// Examples:
    ///   mantis hack app.example.com --i-have-authorization
    ///   mantis hack https://app.example.com/ --i-have-authorization
    ///
    /// This is the equivalent of hacker-bob's `/bob-hunt target.com`
    /// — one command, zero flags beyond the authorization gate.
    Hack {
        /// Target URL or bare domain. `example.com` is treated as
        /// `https://example.com/` automatically.
        target: String,
        /// Skip the authorization prompt. The caller MUST hold
        /// written authorization for the target.
        #[arg(long)]
        i_have_authorization: bool,
        /// Cookie header passed through every discovery + probe
        /// request. Use after solving the target's WAF challenge
        /// once in your browser: copy the Cookie header from
        /// DevTools → Network. Format: `name1=value1; name2=value2`.
        #[arg(long, env = "MANTIS_COOKIE")]
        cookie: Option<String>,
        /// Override the Supabase signup URL discovered from the
        /// target HTML.
        #[arg(long)]
        supabase_signup: Option<String>,
        /// Override the Supabase anon key discovered from the target
        /// HTML.
        #[arg(long, env = "MANTIS_SUPABASE_APIKEY")]
        supabase_apikey: Option<String>,
        /// BYO attacker auth profile (skip signup phase).
        #[arg(long)]
        attacker_profile: Option<Utf8PathBuf>,
        /// BYO victim auth profile (skip signup phase).
        #[arg(long)]
        victim_profile: Option<Utf8PathBuf>,
        /// Operator-supplied paths added on top of the built-in
        /// wordlist.
        #[arg(long = "extra-path")]
        extra_paths: Vec<String>,
        /// Max candidate URLs enumerated. Default: 100.
        #[arg(long, default_value_t = 100)]
        max_candidates: usize,
        /// Max endpoints probed (hard cap, protects against runaway).
        #[arg(long, default_value_t = 100)]
        max_endpoints_probed: usize,
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
    match cli.command {
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
        Command::Doctor { root, json } => cmd_doctor(root, json),
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
            cookie,
            supabase_signup,
            supabase_apikey,
            attacker_profile,
            victim_profile,
            extra_paths,
            max_candidates,
            max_endpoints_probed,
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
async fn handle_hack(
    target: String,
    i_have_authorization: bool,
    cookie: Option<String>,
    supabase_signup_override: Option<String>,
    supabase_apikey_override: Option<String>,
    attacker_profile: Option<Utf8PathBuf>,
    victim_profile: Option<Utf8PathBuf>,
    extra_paths: Vec<String>,
    max_candidates: usize,
    max_endpoints_probed: usize,
) -> Result<()> {
    banner::print();
    if !i_have_authorization {
        anyhow::bail!(
            "refusing to start: `mantis hack` runs offensive-security tests against the named target.\n\
             Re-run with --i-have-authorization once you have written permission to test {target}.\n\
             Mantis enforces scope at the egress proxy when daemon-driven, but the legal gate is yours."
        );
    }

    // Normalize:
    //   has scheme → use as-is
    //   bare host with no port → https://host/
    //   bare host:port where port is a common-http port → http://host:port/
    //   bare host:port otherwise → https://host:port/
    let target_url = if target.starts_with("http://") || target.starts_with("https://") {
        target.clone()
    } else {
        let stripped = target.trim_end_matches('/');
        let needs_http = stripped.split('/').next().map(host_port_is_likely_http).unwrap_or(false);
        let scheme = if needs_http { "http" } else { "https" };
        format!("{scheme}://{stripped}/")
    };

    eprintln!("[mantishack] target: {target_url}");
    if let Some(c) = &cookie {
        eprintln!(
            "[mantishack] cookie supplied ({} chars) — passed through every discovery probe",
            c.len()
        );
    }
    eprintln!("[mantishack] phase 1/3: auto-discover");
    let discovered = mantis_orchestrator::discover_with_cookie(&target_url, cookie.as_deref()).await;
    for note in &discovered.notes {
        eprintln!("[mantishack]   • {note}");
    }

    // Operator overrides beat discovery.
    let supabase_signup = supabase_signup_override
        .or(discovered.supabase_signup_url.clone());
    let supabase_apikey = supabase_apikey_override.or(discovered.supabase_anon_key.clone());

    if let Some(s) = &supabase_signup {
        eprintln!("[mantishack]   ✓ supabase signup: {s}");
    }
    if let Some(k) = &supabase_apikey {
        eprintln!("[mantishack]   ✓ supabase apikey: {}…", &k[..k.len().min(20)]);
    }
    if supabase_signup.is_none() && attacker_profile.is_none() {
        eprintln!("[mantishack]   ⚠ no Supabase signup discovered — running unauth-only");
        eprintln!("[mantishack]     supply --attacker-profile / --victim-profile to drive the full diff");
    }

    eprintln!("[mantishack] phase 2/3: signup + enumerate + auth-diff");
    handle_find_auth_bugs(
        target_url,
        supabase_signup,
        supabase_apikey,
        extra_paths,
        attacker_profile,
        victim_profile,
        max_candidates,
        max_endpoints_probed,
        true, // no_subdomain_expansion — `hack` defaults to host-only for speed
        i_have_authorization,
        None,
    )
    .await?;

    eprintln!("[mantishack] phase 3/3: archive written under ./reports/<host>/AB-<id>/");
    Ok(())
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
        }
        Err(e) => eprintln!("[mantis-find-auth-bugs] archive error: {e}"),
    }
    Ok(())
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
