//! The egress proxy itself.
//!
//! ```text
//! client ── HTTP/1.1 CONNECT host:port ─► [proxy] ──► target IP:port
//!                                          │
//!                                          ├─ resolve host (once)
//!                                          ├─ ScopeEvaluator.evaluate(host, port, /, https)
//!                                          ├─ BudgetTracker.try_acquire_request()
//!                                          ├─ EventStore.append(ScopeDecisionLogged)
//!                                          └─ if Ok: dial(IP, port), reply 200, splice
//! ```
//!
//! DNS resolution happens once per connection. The resulting IP is the
//! one the proxy dials. The scope check is performed against the
//! requested hostname (not the IP), so an attacker who controls DNS
//! cannot bypass scope by returning a different IP between the scope
//! check and the dial — they're already pinned. See ADR-0004.

use std::net::SocketAddr;
use std::sync::Arc;

use mantis_core::{EngagementId, Signer};
use mantis_event_store::{EventKind, EventStore};
use mantis_scope::{
    BudgetDecision, BudgetTracker, Protocol, ScopeDecision, ScopeEvaluator, ScopeQuery,
};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::lookup_host;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::error::EgressError;
use crate::request::{read_connect_request, write_response, ConnectRequest};

pub struct EgressProxy {
    listener: TcpListener,
    config: Arc<EgressConfig>,
}

pub struct EgressConfig {
    pub engagement_id: EngagementId,
    pub evaluator: ScopeEvaluator,
    pub budget: Arc<BudgetTracker>,
    pub event_store: Arc<EventStore>,
    pub signer: Arc<dyn Signer>,
}

impl std::fmt::Debug for EgressConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressConfig")
            .field("engagement_id", &self.engagement_id)
            .finish_non_exhaustive()
    }
}

impl EgressProxy {
    pub async fn bind(addr: SocketAddr, config: EgressConfig) -> Result<Self, EgressError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, EgressError> {
        Ok(self.listener.local_addr()?)
    }

    /// Run the accept loop until the listener errors. Each connection
    /// is handled on its own spawned task; the loop continues across
    /// per-connection errors.
    pub async fn serve(self) -> Result<(), EgressError> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let cfg = self.config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, peer, cfg).await {
                    warn!(error = %e, %peer, "egress connection ended with error");
                }
            });
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    cfg: Arc<EgressConfig>,
) -> Result<(), EgressError> {
    let mut reader = BufReader::new(&mut stream);
    let req = match read_connect_request(&mut reader).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, %peer, "rejecting malformed request");
            write_response(&mut stream, 400, "Bad Request").await?;
            return Ok(());
        }
    };
    drop(reader); // releases the &mut on `stream`

    handle_connect(stream, req, peer, cfg).await
}

async fn handle_connect(
    mut stream: TcpStream,
    req: ConnectRequest,
    peer: SocketAddr,
    cfg: Arc<EgressConfig>,
) -> Result<(), EgressError> {
    // Scope check is on the requested HOSTNAME, not the resolved IP.
    let decision = cfg.evaluator.evaluate(&ScopeQuery {
        host: &req.host,
        port: req.port,
        path: None,
        protocol: Protocol::Https,
    });
    let in_scope = matches!(decision, ScopeDecision::InScope);
    let reason = match &decision {
        ScopeDecision::InScope => format!("connect {}:{}", req.host, req.port),
        ScopeDecision::OutOfScope { reason } => reason.clone(),
    };
    log_decision(&cfg, &req, in_scope, &reason).await?;
    if !in_scope {
        warn!(host = %req.host, port = req.port, %peer, "out-of-scope CONNECT rejected");
        write_response(&mut stream, 403, "Out of scope").await?;
        return Ok(());
    }

    // Budget check.
    let budget_decision = cfg.budget.try_acquire_request(0);
    if budget_decision != BudgetDecision::Ok {
        warn!(?budget_decision, %peer, "budget exhausted");
        write_response(&mut stream, 429, "Budget exhausted").await?;
        return Err(EgressError::Budget(budget_decision));
    }

    // DNS resolve, then pin the IP for this connection.
    let resolved = lookup_host((req.host.as_str(), req.port))
        .await
        .map_err(|e| EgressError::Resolve {
            host: req.host.clone(),
            reason: e.to_string(),
        })?
        .next()
        .ok_or_else(|| EgressError::Resolve {
            host: req.host.clone(),
            reason: "no address records".into(),
        })?;

    // Dial.
    let upstream = match TcpStream::connect(resolved).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, %resolved, %peer, "dial failed");
            write_response(&mut stream, 502, "Bad Gateway").await?;
            return Ok(());
        }
    };
    info!(host = %req.host, port = req.port, %resolved, %peer, "CONNECT established");
    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    stream.flush().await?;
    splice(stream, upstream, cfg).await
}

async fn splice(
    mut client: TcpStream,
    mut upstream: TcpStream,
    cfg: Arc<EgressConfig>,
) -> Result<(), EgressError> {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();
    let budget = &cfg.budget;
    let client_to_upstream = async {
        let bytes = tokio::io::copy(&mut cr, &mut uw).await.unwrap_or(0);
        budget.record_egress_bytes(bytes);
        let _ = uw.shutdown().await;
        bytes
    };
    let upstream_to_client = async {
        let bytes = tokio::io::copy(&mut ur, &mut cw).await.unwrap_or(0);
        budget.record_egress_bytes(bytes);
        let _ = cw.shutdown().await;
        bytes
    };
    let (_a, _b) = tokio::join!(client_to_upstream, upstream_to_client);
    Ok(())
}

async fn log_decision(
    cfg: &EgressConfig,
    req: &ConnectRequest,
    in_scope: bool,
    reason: &str,
) -> Result<(), EgressError> {
    let kind = EventKind::ScopeDecisionLogged {
        in_scope,
        target: format!("{}:{}", req.host, req.port),
        reason: reason.to_owned(),
    };
    cfg.event_store
        .append(cfg.engagement_id, kind, cfg.signer.as_ref())?;
    Ok(())
}
