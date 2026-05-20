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

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use camino::{Utf8Path, Utf8PathBuf};
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
    let event_store_path = root.join("events.rocksdb");
    let event_store = Arc::new(EventStore::open(&event_store_path).map_err(|e| {
        if is_lock_contention(&e) {
            already_running_error(&root, &event_store_path)
        } else {
            anyhow::Error::new(e).context("open event store")
        }
    })?);

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

fn is_lock_contention(err: &mantis_event_store::EventStoreError) -> bool {
    let chain = format!("{err:#}");
    chain.contains("While lock file") || chain.contains("Resource temporarily unavailable")
}

fn already_running_error(root: &Utf8Path, lock_dir: &Utf8Path) -> anyhow::Error {
    let lock_file = lock_dir.join("LOCK");
    let holder = lookup_lock_holder(lock_file.as_str());
    let endpoint = std::fs::read_to_string(root.join("daemon.endpoint"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let endpoint_live = endpoint.as_deref().is_some_and(probe_endpoint_alive);

    let mut msg = String::new();

    if endpoint_live {
        // Common case: a healthy daemon is already serving this workspace.
        msg.push_str(
            "this workspace is already being served by a running mantis-daemon — \
             you don't need to start a second one.\n",
        );
        msg.push_str(&format!("  workspace: {root}\n"));
        if let Some(endpoint) = &endpoint {
            msg.push_str(&format!("  endpoint:  {endpoint}\n"));
        }
        if let Some((pid, cmd)) = &holder {
            msg.push_str(&format!("  process:   pid {pid} ({cmd})\n"));
        }
        msg.push_str(
            "\nThe mantis architecture is one daemon + many clients:\n  \
             - mantis-daemon  → server, owns the workspace (only ONE at a time)\n  \
             - mantis         → CLI client (run as many as you want)\n  \
             - mantis-mcp     → MCP bridge for AI CLIs (run as many as you want)\n\
             \nIf you really want to restart the daemon, stop the existing one first:",
        );
        if let Some((pid, _)) = &holder {
            msg.push_str(&format!("\n  kill {pid}"));
        } else {
            msg.push_str("\n  pkill -x mantis-daemon");
        }
    } else {
        // Lock is held but nothing is answering on the endpoint — likely a
        // zombie daemon or stale lock from a previous crash.
        msg.push_str(
            "the workspace lock is held but no daemon is responding on the recorded endpoint\n",
        );
        msg.push_str(&format!("  workspace: {root}\n"));
        if let Some(endpoint) = &endpoint {
            msg.push_str(&format!(
                "  endpoint:  {endpoint}  (not responding to TCP connect)\n"
            ));
        }
        match &holder {
            Some((pid, cmd)) => {
                msg.push_str(&format!("  held by:   pid {pid} ({cmd})\n"));
                msg.push_str(&format!(
                    "\nThis usually means a previous mantis-daemon is stuck.\nKill it and retry:\n  kill {pid}"
                ));
            }
            None => {
                msg.push_str(&format!("  lock file: {lock_file}\n"));
                msg.push_str(
                    "\nCould not identify the holder. Find and stop it:\n  \
                     lsof ",
                );
                msg.push_str(lock_file.as_str());
                msg.push_str("\n  pkill -x mantis-daemon");
            }
        }
    }

    anyhow::anyhow!(msg)
}

/// Quick TCP-connect probe to verify a daemon is actually accepting
/// connections at the URL recorded in `daemon.endpoint`. Returns false
/// on parse failure, DNS failure, refused connection, or timeout.
fn probe_endpoint_alive(endpoint: &str) -> bool {
    let host_port = endpoint
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let Ok(mut addrs) = host_port.to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

/// Best-effort lookup of the PID holding the RocksDB LOCK file via `lsof`.
/// Returns None if `lsof` is unavailable or the file is not held.
fn lookup_lock_holder(lock_path: &str) -> Option<(u32, String)> {
    let output = Command::new("lsof")
        .args(["-F", "pc", lock_path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    // lsof -F pc emits records like:
    //   p12345
    //   cmantis-daemon
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pid: Option<u32> = None;
    let mut cmd: Option<String> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix('p') {
            pid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix('c') {
            cmd = Some(rest.trim().to_string());
        }
        if pid.is_some() && cmd.is_some() {
            break;
        }
    }
    Some((pid?, cmd.unwrap_or_else(|| "unknown".to_string())))
}
