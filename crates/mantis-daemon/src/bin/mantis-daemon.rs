//! Standalone `mantis-daemon` binary. Mirrors the `mantis daemon`
//! subcommand of the main CLI. On macOS prefer `mantis daemon` because
//! it shares a code-signing identity with `mantis` and avoids
//! Keychain ACL prompts.

use std::net::SocketAddr;

use camino::Utf8PathBuf;
use clap::Parser;
use mantis_daemon::{run, DaemonConfig, DEFAULT_BIND};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "mantis-daemon", version, about = "Mantis daemon (standalone)")]
struct Cli {
    #[arg(long, env = "MANTIS_BIND", default_value = DEFAULT_BIND)]
    bind: SocketAddr,
    #[arg(long, env = "MANTIS_HOME")]
    workspace_root: Option<Utf8PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let cli = Cli::parse();
    run(DaemonConfig {
        bind: cli.bind,
        workspace_root: cli.workspace_root,
    })
    .await
}
