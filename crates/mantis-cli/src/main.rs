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
}

#[derive(Subcommand, Debug)]
enum LlmAction {
    /// One-shot health check against a provider. The API key comes
    /// from the environment variable named after the provider
    /// (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`).
    Probe {
        /// Provider: `anthropic` or `openai`.
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
    }
}

async fn handle_llm(action: LlmAction) -> Result<()> {
    use mantis_synthesizer::{anthropic::AnthropicAdapter, openai::OpenAIAdapter, LlmAdapter};
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
                other => anyhow::bail!("unknown provider `{other}`; supported: anthropic, openai"),
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
