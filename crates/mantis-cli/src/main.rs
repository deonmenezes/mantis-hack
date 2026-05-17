//! Mantis CLI (`mantis`).
//!
//! Subcommands either operate on local workspace state directly
//! (workspace, operator, doctor) or talk to a running daemon via the
//! generated `mantis.v1.Engagement` gRPC client (engagement).

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use mantis_proto::v1::engagement_client::EngagementClient;
use mantis_proto::v1::{
    AuthorizeRequest, CreateRequest, EngagementInfo, EngagementState as ProtoEngagementState,
    ExportRequest, ListRequest, PauseRequest, ScanRequest, StartRequest, StatusRequest,
};
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

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
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
