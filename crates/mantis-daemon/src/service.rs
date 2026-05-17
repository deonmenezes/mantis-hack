//! The Engagement service implementation.
//!
//! Each RPC maps to one or more events appended to the event store,
//! and updates an in-memory state cache keyed by engagement id. The
//! cache is rebuilt at daemon startup by replaying every known
//! engagement's log.

// `tonic::Status` is necessarily large (~176 bytes) because it
// carries headers and metadata. The clippy::result_large_err lint
// suggests boxing it, but every tonic RPC has the same signature, so
// boxing across the board would obscure the public type and provide
// no real benefit. Allow the lint module-wide.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use mantis_core::{EngagementId, OperatorId, Signer};
use mantis_egress::{EgressConfig, EgressProxy};
use mantis_event_store::{Event, EventKind, EventStore};
use mantis_posterior::Posteriors;
use mantis_primitive::Primitive;
use mantis_proto::v1::engagement_server::Engagement;

use crate::pipeline::{build_catalog, run_pipeline, PipelineOutcome};
use mantis_proto::v1::{
    AuthorizeRequest, CreateRequest, EngagementInfo, EngagementState as ProtoEngagementState,
    ExportRequest, ExportResponse, ListRequest, ListResponse, PauseRequest, ScanRequest,
    ScanResponse, StartRequest, StatusRequest,
};
use mantis_scanner_http::{HttpProbeScanner, ProbeConfig, ProbeTarget};
use mantis_scope::{BudgetTracker, ScopeEvaluator, ScopeManifest, SignedScope};
use mantis_workspace::Workspace;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use ulid::Ulid;

/// Per-engagement live runtime state populated after Authorize.
#[derive(Debug)]
pub(crate) struct EngagementRuntime {
    #[allow(dead_code)] // Retained for debugging and future use.
    pub manifest: ScopeManifest,
    pub evaluator: ScopeEvaluator,
    pub budget: Arc<BudgetTracker>,
    /// Set after `Start`. None until then.
    pub proxy: Option<ProxyHandle>,
}

#[derive(Debug)]
pub(crate) struct ProxyHandle {
    pub url: String,
    pub task: JoinHandle<()>,
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug, Clone)]
struct EngagementRow {
    id: EngagementId,
    name: String,
    state: mantis_core::EngagementState,
    created_at_unix: u64,
    scope_hash: Option<String>,
    event_count: u64,
    fingerprint: Option<String>,
}

impl EngagementRow {
    fn to_proto(&self) -> EngagementInfo {
        EngagementInfo {
            id: self.id.to_string(),
            name: self.name.clone(),
            state: state_to_proto(self.state).into(),
            created_at_unix: self.created_at_unix,
            scope_hash: self.scope_hash.clone(),
            event_count: self.event_count,
            fingerprint: self.fingerprint.clone(),
        }
    }
}

fn state_to_proto(s: mantis_core::EngagementState) -> ProtoEngagementState {
    use mantis_core::EngagementState as Es;
    match s {
        Es::Draft => ProtoEngagementState::Draft,
        Es::Authorized => ProtoEngagementState::Authorized,
        Es::Active => ProtoEngagementState::Active,
        Es::Paused => ProtoEngagementState::Paused,
        Es::Completed => ProtoEngagementState::Completed,
        Es::Archived => ProtoEngagementState::Archived,
    }
}

pub(crate) struct EngagementServiceImpl {
    workspace: Arc<Workspace>,
    event_store: Arc<EventStore>,
    state: RwLock<HashMap<EngagementId, EngagementRow>>,
    runtime: RwLock<HashMap<EngagementId, EngagementRuntime>>,
    posteriors: Arc<Posteriors>,
    catalog: Arc<Vec<Box<dyn Primitive>>>,
}

impl EngagementServiceImpl {
    pub(crate) fn new(
        workspace: Arc<Workspace>,
        event_store: Arc<EventStore>,
    ) -> Result<Self, anyhow::Error> {
        let mut state = HashMap::new();
        for id in event_store.list_engagement_ids()? {
            let events = event_store.replay(id)?;
            if let Some(row) = derive_row(id, &events) {
                state.insert(id, row);
            }
        }
        Ok(Self {
            workspace,
            event_store,
            state: RwLock::new(state),
            runtime: RwLock::new(HashMap::new()),
            posteriors: Arc::new(Posteriors::new()),
            catalog: Arc::new(build_catalog()),
        })
    }

    fn workspace_signer(&self) -> &dyn Signer {
        self.workspace.as_ref()
    }
}

fn derive_row(id: EngagementId, events: &[Event]) -> Option<EngagementRow> {
    let first = events.first()?;
    let name = match &first.kind {
        EventKind::EngagementCreated { name } => name.clone(),
        _ => return None,
    };
    let mut row = EngagementRow {
        id,
        name,
        state: mantis_core::EngagementState::Draft,
        created_at_unix: first.wall_clock_unix,
        scope_hash: None,
        event_count: 0,
        fingerprint: None,
    };
    for event in events {
        match &event.kind {
            EventKind::EngagementCreated { .. } => {
                row.state = mantis_core::EngagementState::Draft;
            }
            EventKind::EngagementAuthorized { scope_hash } => {
                row.state = mantis_core::EngagementState::Authorized;
                row.scope_hash = Some(scope_hash.clone());
            }
            EventKind::EngagementStarted => {
                row.state = mantis_core::EngagementState::Active;
            }
            EventKind::EngagementPaused => {
                row.state = mantis_core::EngagementState::Paused;
            }
            EventKind::EngagementResumed => {
                row.state = mantis_core::EngagementState::Active;
            }
            EventKind::EngagementCompleted => {
                row.state = mantis_core::EngagementState::Completed;
            }
            _ => {}
        }
    }
    row.event_count = events.len() as u64;
    Some(row)
}

fn parse_engagement_id(s: &str) -> Result<EngagementId, Status> {
    Ulid::from_str(s)
        .map(EngagementId)
        .map_err(|_| Status::invalid_argument(format!("invalid engagement id: {s}")))
}

#[tonic::async_trait]
impl Engagement for EngagementServiceImpl {
    async fn create(
        &self,
        request: Request<CreateRequest>,
    ) -> Result<Response<EngagementInfo>, Status> {
        let name = request.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("name is empty"));
        }
        let id = EngagementId(Ulid::new());
        let kind = EventKind::EngagementCreated { name: name.clone() };
        self.event_store
            .append(id, kind, self.workspace_signer())
            .map_err(|e| Status::internal(format!("event store: {e}")))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let row = EngagementRow {
            id,
            name,
            state: mantis_core::EngagementState::Draft,
            created_at_unix: now,
            scope_hash: None,
            event_count: 1,
            fingerprint: None,
        };
        let info = row.to_proto();
        self.state.write().await.insert(id, row);
        info!(engagement_id = %id, "engagement created");
        Ok(Response::new(info))
    }

    async fn authorize(
        &self,
        request: Request<AuthorizeRequest>,
    ) -> Result<Response<EngagementInfo>, Status> {
        let inner = request.into_inner();
        let id = parse_engagement_id(&inner.id)?;
        let signed: SignedScope = serde_json::from_slice(&inner.signed_scope_json)
            .map_err(|e| Status::invalid_argument(format!("signed scope: {e}")))?;

        // Verify against the authorizing operator's public key.
        let authorizer = signed.manifest.authorized_by;
        let operator_pk = self
            .workspace
            .get_operator_public_key(authorizer)
            .map_err(|e| Status::failed_precondition(format!("operator lookup: {e}")))?;
        let pk_bytes = *operator_pk.as_bytes();
        let manifest = signed
            .verify(&pk_bytes)
            .map_err(|e| Status::permission_denied(format!("scope verify: {e}")))?;

        if manifest.engagement_id != id {
            return Err(Status::invalid_argument(format!(
                "scope engagement_id {} does not match request {}",
                manifest.engagement_id, id
            )));
        }

        // Hash the canonical manifest bytes for the event record.
        let canonical = manifest
            .canonical_bytes()
            .map_err(|e| Status::internal(format!("canonical bytes: {e}")))?;
        let scope_hash = hex::encode(blake3::hash(&canonical).as_bytes());

        let evaluator = ScopeEvaluator::new(&manifest);
        let budget = Arc::new(BudgetTracker::new(manifest.budget.clone()));

        let mut state = self.state.write().await;
        let row = state
            .get_mut(&id)
            .ok_or_else(|| Status::not_found(format!("engagement {id} not found")))?;
        if !row
            .state
            .can_transition_to(mantis_core::EngagementState::Authorized)
        {
            return Err(Status::failed_precondition(format!(
                "cannot transition {:?} -> Authorized",
                row.state
            )));
        }
        self.event_store
            .append(
                id,
                EventKind::EngagementAuthorized {
                    scope_hash: scope_hash.clone(),
                },
                self.workspace_signer(),
            )
            .map_err(|e| Status::internal(format!("event store: {e}")))?;
        row.state = mantis_core::EngagementState::Authorized;
        row.scope_hash = Some(scope_hash);
        row.event_count += 1;
        drop(state);

        self.runtime.write().await.insert(
            id,
            EngagementRuntime {
                manifest,
                evaluator,
                budget,
                proxy: None,
            },
        );

        info!(engagement_id = %id, operator = %authorizer, "engagement authorized");
        let state = self.state.read().await;
        let row = state.get(&id).expect("just-inserted row");
        Ok(Response::new(row.to_proto()))
    }

    async fn start(
        &self,
        request: Request<StartRequest>,
    ) -> Result<Response<EngagementInfo>, Status> {
        let id = parse_engagement_id(&request.into_inner().id)?;
        // Spawn the egress proxy for this engagement.
        let proxy_handle = self.start_proxy(id).await?;
        let result = self
            .transition(
                id,
                mantis_core::EngagementState::Active,
                EventKind::EngagementStarted,
            )
            .await;
        if result.is_ok() {
            // Store the running proxy on the runtime.
            let mut runtime = self.runtime.write().await;
            if let Some(rt) = runtime.get_mut(&id) {
                rt.proxy = Some(proxy_handle);
            }
        }
        result
    }

    async fn pause(
        &self,
        request: Request<PauseRequest>,
    ) -> Result<Response<EngagementInfo>, Status> {
        let id = parse_engagement_id(&request.into_inner().id)?;
        let result = self
            .transition(
                id,
                mantis_core::EngagementState::Paused,
                EventKind::EngagementPaused,
            )
            .await;
        if result.is_ok() {
            // Abort the proxy task for this engagement.
            let mut runtime = self.runtime.write().await;
            if let Some(rt) = runtime.get_mut(&id) {
                rt.proxy = None; // Drop aborts.
            }
        }
        result
    }

    async fn status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<EngagementInfo>, Status> {
        let id = parse_engagement_id(&request.into_inner().id)?;
        let state = self.state.read().await;
        let row = state
            .get(&id)
            .ok_or_else(|| Status::not_found(format!("engagement {id} not found")))?;
        Ok(Response::new(row.to_proto()))
    }

    async fn list(&self, _request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        let state = self.state.read().await;
        let mut engagements: Vec<EngagementInfo> = state.values().map(|r| r.to_proto()).collect();
        engagements.sort_by_key(|e| e.created_at_unix);
        Ok(Response::new(ListResponse { engagements }))
    }

    async fn scan(&self, request: Request<ScanRequest>) -> Result<Response<ScanResponse>, Status> {
        let inner = request.into_inner();
        let id = parse_engagement_id(&inner.id)?;
        {
            let state = self.state.read().await;
            let row = state
                .get(&id)
                .ok_or_else(|| Status::not_found(format!("engagement {id} not found")))?;
            if row.state != mantis_core::EngagementState::Active {
                return Err(Status::failed_precondition(format!(
                    "engagement must be Active to scan; current state is {:?}",
                    row.state
                )));
            }
        }
        let targets = inner
            .targets
            .iter()
            .map(|t| {
                ProbeTarget::parse(t)
                    .map_err(|e| Status::invalid_argument(format!("target {t}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let signer: Arc<dyn Signer> = self.workspace.clone();
        // Look up the engagement's proxy URL so the scanner routes
        // through the scope-enforcing proxy.
        let proxy_url = {
            let runtime = self.runtime.read().await;
            runtime
                .get(&id)
                .and_then(|rt| rt.proxy.as_ref().map(|p| p.url.clone()))
        };
        let scanner = HttpProbeScanner::new(
            self.event_store.clone(),
            id,
            signer.clone(),
            ProbeConfig {
                proxy: proxy_url,
                ..Default::default()
            },
        )
        .map_err(|e| Status::internal(format!("scanner init: {e}")))?;

        let mut surfaces = Vec::with_capacity(targets.len());
        for target in &targets {
            match scanner.probe(target).await {
                Ok(surface) => surfaces.push(surface),
                Err(e) => warn!(target = %target.url(), error = %e, "probe failed"),
            }
        }
        let surfaces_recorded = surfaces.len() as u32;

        // Build a scanner-style reqwest client for primitive execution.
        // Phase 2 will route primitives through the egress proxy
        // alongside the scanner; for now they share the same config.
        let client_builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5));
        let client = client_builder
            .build()
            .map_err(|e| Status::internal(format!("client init: {e}")))?;

        let PipelineOutcome {
            hypotheses_recorded,
            primitives_executed: _,
            claims_verified: _,
            claims_rejected: _,
            claims_retained: _,
        } = run_pipeline(
            &surfaces,
            self.catalog.as_ref(),
            &self.event_store,
            id,
            &signer,
            self.posteriors.as_ref(),
            &client,
            64, // per-scan action budget
        )
        .await;

        {
            let mut state = self.state.write().await;
            if let Some(row) = state.get_mut(&id) {
                row.event_count = self
                    .event_store
                    .event_count(id)
                    .map_err(|e| Status::internal(format!("event count: {e}")))?;
            }
        }

        info!(
            engagement_id = %id,
            surfaces_recorded,
            hypotheses_recorded,
            "scan complete"
        );
        Ok(Response::new(ScanResponse {
            id: id.to_string(),
            surfaces_recorded,
            hypotheses_recorded,
        }))
    }

    async fn export(
        &self,
        request: Request<ExportRequest>,
    ) -> Result<Response<ExportResponse>, Status> {
        let id = parse_engagement_id(&request.into_inner().id)?;
        let events = self
            .event_store
            .replay(id)
            .map_err(|e| Status::internal(format!("replay: {e}")))?;
        let mut jsonl = Vec::with_capacity(events.len() * 256);
        for event in events {
            let bytes =
                serde_json::to_vec(&event).map_err(|e| Status::internal(format!("encode: {e}")))?;
            jsonl.extend_from_slice(&bytes);
            jsonl.push(b'\n');
        }
        Ok(Response::new(ExportResponse { jsonl }))
    }
}

impl EngagementServiceImpl {
    /// Bind a per-engagement egress proxy on a random localhost port
    /// and spawn its serve loop. Returns a [`ProxyHandle`] whose drop
    /// aborts the task.
    async fn start_proxy(&self, id: EngagementId) -> Result<ProxyHandle, Status> {
        let runtime = self.runtime.read().await;
        let rt = runtime
            .get(&id)
            .ok_or_else(|| Status::failed_precondition("engagement not authorized"))?;
        let cfg = EgressConfig {
            engagement_id: id,
            evaluator: rt.evaluator.clone(),
            budget: Arc::clone(&rt.budget),
            event_store: self.event_store.clone(),
            signer: self.workspace.clone() as Arc<dyn Signer>,
        };
        drop(runtime);
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let proxy = EgressProxy::bind(bind, cfg)
            .await
            .map_err(|e| Status::internal(format!("egress bind: {e}")))?;
        let url = format!(
            "http://{}",
            proxy
                .local_addr()
                .map_err(|e| Status::internal(format!("local_addr: {e}")))?
        );
        let task = tokio::spawn(async move {
            let _ = proxy.serve().await;
        });
        info!(engagement_id = %id, %url, "engagement egress proxy started");
        Ok(ProxyHandle { url, task })
    }

    async fn transition(
        &self,
        id: EngagementId,
        next: mantis_core::EngagementState,
        kind: EventKind,
    ) -> Result<Response<EngagementInfo>, Status> {
        let mut state = self.state.write().await;
        let row = state
            .get_mut(&id)
            .ok_or_else(|| Status::not_found(format!("engagement {id} not found")))?;
        if !row.state.can_transition_to(next) {
            warn!(?row.state, ?next, %id, "rejecting illegal transition");
            return Err(Status::failed_precondition(format!(
                "cannot transition {:?} -> {:?}",
                row.state, next
            )));
        }
        self.event_store
            .append(id, kind, self.workspace_signer())
            .map_err(|e| Status::internal(format!("event store: {e}")))?;
        row.state = next;
        row.event_count += 1;
        info!(engagement_id = %id, ?next, "engagement transitioned");
        Ok(Response::new(row.to_proto()))
    }
}

// Workspace doesn't directly impl Signer for &Workspace, but it does
// impl mantis_core::Signer for `Workspace` (per mantis-workspace::key).
// We pass `self.workspace.as_ref()` which dereferences `Arc<Workspace>`
// to `&Workspace`, and rely on the impl there.
// Re-declared use of OperatorId so it's not flagged as unused when
// `Authorize` is the only path that touches the workspace's operator
// helpers.
#[allow(dead_code)]
const _: fn() -> OperatorId = || OperatorId(Ulid::new());
