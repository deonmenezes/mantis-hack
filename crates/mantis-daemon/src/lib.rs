//! Mantis daemon library.
//!
//! Exposes [`run`] which boots the workspace, opens the event store,
//! and serves the `mantis.v1.Engagement` gRPC API. Used by both the
//! standalone `mantis-daemon` binary and the `mantis daemon` CLI
//! subcommand. The latter is the recommended entry point on macOS
//! because it shares a code-signing identity with the rest of the
//! `mantis` binary and therefore the same Keychain ACL.

mod pipeline;
mod service;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use camino::Utf8PathBuf;
use mantis_event_store::EventStore;
use mantis_proto::v1::engagement_server::EngagementServer;
use mantis_workspace::{default_workspace_root, OsKeyStore, Workspace};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use crate::service::EngagementServiceImpl;

pub const DEFAULT_BIND: &str = "127.0.0.1:50451";

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub bind: SocketAddr,
    pub workspace_root: Option<Utf8PathBuf>,
}

impl DaemonConfig {
    pub fn resolved_root(&self) -> Utf8PathBuf {
        self.workspace_root
            .clone()
            .unwrap_or_else(default_workspace_root)
    }
}

/// Boot the daemon. Returns only on shutdown error — successful
/// service loop runs forever.
pub async fn run(config: DaemonConfig) -> anyhow::Result<()> {
    let root = config.resolved_root();
    let ks = OsKeyStore::new();
    let workspace = Arc::new(
        Workspace::open_with_env_fallback(&root, &ks).context("open workspace")?,
    );
    let event_store =
        Arc::new(EventStore::open(&root.join("events.rocksdb")).context("open event store")?);

    let service = EngagementServiceImpl::new(workspace.clone(), event_store.clone())
        .context("construct engagement service")?;

    let listener = TcpListener::bind(config.bind).await.context("bind tcp")?;
    let bound = listener.local_addr().context("local_addr")?;

    let endpoint_path = root.join("daemon.endpoint");
    std::fs::write(&endpoint_path, format!("http://{bound}")).context("write daemon.endpoint")?;

    tracing::info!(
        workspace_root = %root,
        bind = %bound,
        workspace_fingerprint = %workspace.fingerprint(),
        "mantis daemon listening"
    );

    Server::builder()
        .add_service(EngagementServer::new(service))
        .serve_with_incoming(TcpListenerStream::new(listener))
        .await
        .context("tonic server")?;
    Ok(())
}
