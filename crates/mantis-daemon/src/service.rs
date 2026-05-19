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
use mantis_fsm::{
    GradeVerdict, OverrideReason, Phase, SessionState as FsmSessionState, TransitionError,
    VerificationRound, VerificationRoundResult,
};
use mantis_posterior::Posteriors;
use mantis_primitive::Primitive;
use mantis_proto::v1::engagement_server::Engagement;

use crate::pipeline::{build_catalog, run_pipeline, PipelineOutcome};
use mantis_proto::v1::{
    AuthorizeRequest, Blocker as ProtoBlocker, BuildVerificationAdjudicationRequest,
    BuildVerificationAdjudicationResponse, CreateRequest, EngagementInfo,
    EngagementState as ProtoEngagementState, ExportRequest, ExportResponse, ListRequest,
    ListResponse, OpenVerificationAttemptRequest, OpenVerificationAttemptResponse, PauseRequest,
    ScanRequest, ScanResponse, SessionStateRequest, SessionStateResponse, StartRequest,
    StatusRequest, TransitionPhaseRequest, TransitionPhaseResponse, WriteGradeVerdictRequest,
    WriteGradeVerdictResponse, WriteVerificationRoundRequest, WriteVerificationRoundResponse,
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
    /// FSM phase + verification + grade cache. One entry per known
    /// engagement, rebuilt on startup by folding PhaseTransitioned
    /// events. The lifecycle state (above) and the FSM phase
    /// co-exist: lifecycle says "is the engagement running?"; the
    /// FSM phase says "where in the pipeline?".
    fsm: RwLock<HashMap<EngagementId, FsmSessionState>>,
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
        let mut fsm = HashMap::new();
        for id in event_store.list_engagement_ids()? {
            let events = event_store.replay(id)?;
            if let Some(row) = derive_row(id, &events) {
                let target = row.name.clone();
                state.insert(id, row);
                fsm.insert(id, derive_fsm(id, target, &events));
            }
        }
        Ok(Self {
            workspace,
            event_store,
            state: RwLock::new(state),
            fsm: RwLock::new(fsm),
            runtime: RwLock::new(HashMap::new()),
            posteriors: Arc::new(Posteriors::new()),
            catalog: Arc::new(build_catalog()),
        })
    }

    fn workspace_signer(&self) -> &dyn Signer {
        self.workspace.as_ref()
    }
}

/// Build a SessionState by folding every PhaseTransitioned event
/// for the engagement. Surfaces discovered during recon also bump
/// the FSM's `explored` set so the RECON->AUTH gate opens once at
/// least one surface lands.
fn derive_fsm(id: EngagementId, target: String, events: &[Event]) -> FsmSessionState {
    let mut s = FsmSessionState::new(id.to_string(), target);
    for event in events {
        match &event.kind {
            EventKind::SurfaceDiscovered { host, port, scheme, path, .. } => {
                let surface_id = format!("{scheme}://{host}:{port}{path}");
                if !s.explored.iter().any(|x| x == &surface_id) {
                    s.explored.push(surface_id);
                }
            }
            EventKind::PhaseTransitioned { to, .. } => {
                if let Some(p) = parse_phase(to) {
                    s.phase = p;
                }
            }
            EventKind::VerificationAttemptOpened {
                attempt_id,
                finding_ids,
                ..
            } => {
                s.findings = finding_ids.clone();
                s.open_verification_attempt(attempt_id.clone());
            }
            // The full round payload lives in handoff files on disk;
            // the merkle event carries only the fingerprint and the
            // attempt binding. Replay restores the attempt; rounds
            // are re-loaded from durable artifacts elsewhere. For
            // now, replay does not re-hydrate rounds — operators
            // who restart mid-verify call WriteVerificationRound
            // again with their captured payload.
            EventKind::AdjudicationBuilt { .. } => {
                // No-op on replay; the adjudication is recomputed
                // from the recorded rounds when the operator next
                // calls BuildVerificationAdjudication. This avoids
                // storing the full plan in the merkle log.
            }
            EventKind::GradeVerdictRecorded { verdict_json, .. } => {
                if let Ok(g) = serde_json::from_str::<GradeVerdict>(verdict_json) {
                    s.write_grade(g);
                }
            }
            _ => {}
        }
    }
    s
}

fn parse_phase(s: &str) -> Option<Phase> {
    match s {
        "RECON" => Some(Phase::Recon),
        "AUTH" => Some(Phase::Auth),
        "HUNT" => Some(Phase::Hunt),
        "CHAIN" => Some(Phase::Chain),
        "VERIFY" => Some(Phase::Verify),
        "GRADE" => Some(Phase::Grade),
        "REPORT" => Some(Phase::Report),
        _ => None,
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
        let fsm_target = name.clone();
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
        // Seed an FSM state for this engagement; it starts in RECON
        // with no surfaces and pending auth.
        self.fsm
            .write()
            .await
            .insert(id, FsmSessionState::new(id.to_string(), fsm_target));
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
            tiered_attempts: _,
            tiered_findings: _,
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

        // Mirror discovered surfaces into the FSM so the RECON->AUTH
        // gate opens once at least one surface has landed.
        {
            let mut fsm = self.fsm.write().await;
            if let Some(session) = fsm.get_mut(&id) {
                for s in &surfaces {
                    let surface_id = format!(
                        "{}://{}:{}{}",
                        s.target.scheme, s.target.host, s.target.port, s.target.path
                    );
                    if !session.explored.iter().any(|x| x == &surface_id) {
                        session.explored.push(surface_id);
                    }
                }
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

    async fn transition_phase(
        &self,
        request: Request<TransitionPhaseRequest>,
    ) -> Result<Response<TransitionPhaseResponse>, Status> {
        let inner = request.into_inner();
        let id = parse_engagement_id(&inner.engagement_id)?;
        let to = parse_phase(&inner.to_phase).ok_or_else(|| {
            Status::invalid_argument(format!(
                "to_phase {:?} is not one of RECON|AUTH|HUNT|CHAIN|VERIFY|GRADE|REPORT",
                inner.to_phase
            ))
        })?;

        let override_reason = match inner.override_reason.as_deref() {
            Some(s) => Some(OverrideReason::new(s).map_err(|e| {
                Status::invalid_argument(format!("override_reason: {e}"))
            })?),
            None => None,
        };
        let override_reason_str = inner.override_reason.clone();

        // Optional auth_status update for AUTH -> HUNT.
        let auth_status_update = match inner.auth_status.as_deref() {
            Some("authenticated") => Some(mantis_fsm::AuthStatus::Authenticated),
            Some("unauthenticated") => Some(mantis_fsm::AuthStatus::Unauthenticated),
            Some(other) => {
                return Err(Status::invalid_argument(format!(
                    "auth_status {other:?} must be authenticated|unauthenticated"
                )))
            }
            None => None,
        };

        let mut fsm = self.fsm.write().await;
        let session = fsm
            .get_mut(&id)
            .ok_or_else(|| Status::not_found(format!("engagement {id} not found")))?;
        if let Some(a) = auth_status_update {
            session.auth_status = a;
        }
        let from = session.phase;
        let outcome = session
            .transition_to(to, override_reason)
            .map_err(transition_to_status)?;
        let blockers = outcome.blockers.clone();
        let override_applied = !outcome.is_open();
        drop(fsm);

        let blocker_codes: Vec<String> = blockers.iter().map(|b| b.code.as_str().into()).collect();
        self.event_store
            .append(
                id,
                EventKind::PhaseTransitioned {
                    from: from.as_str().into(),
                    to: to.as_str().into(),
                    override_reason: override_reason_str,
                    blocker_codes,
                },
                self.workspace_signer(),
            )
            .map_err(|e| Status::internal(format!("event store: {e}")))?;

        // Bump the engagement-row event count for analytics parity.
        if let Some(row) = self.state.write().await.get_mut(&id) {
            row.event_count += 1;
        }

        let proto_blockers: Vec<ProtoBlocker> = blockers
            .into_iter()
            .map(|b| ProtoBlocker {
                code: b.code.as_str().into(),
                message: b.message,
                identifiers: b.identifiers,
            })
            .collect();

        info!(
            engagement_id = %id,
            ?from,
            ?to,
            override_applied,
            "phase transitioned"
        );

        Ok(Response::new(TransitionPhaseResponse {
            engagement_id: id.to_string(),
            from_phase: from.as_str().into(),
            to_phase: to.as_str().into(),
            transitioned: true,
            blockers: proto_blockers,
            override_applied,
        }))
    }

    async fn get_session_state(
        &self,
        request: Request<SessionStateRequest>,
    ) -> Result<Response<SessionStateResponse>, Status> {
        let id = parse_engagement_id(&request.into_inner().engagement_id)?;
        let fsm = self.fsm.read().await;
        let session = fsm
            .get(&id)
            .ok_or_else(|| Status::not_found(format!("engagement {id} not found")))?;
        let json = session
            .to_json()
            .map_err(|e| Status::internal(format!("encode session: {e}")))?;
        Ok(Response::new(SessionStateResponse {
            engagement_id: id.to_string(),
            session_json: json.into_bytes(),
        }))
    }

    async fn open_verification_attempt(
        &self,
        request: Request<OpenVerificationAttemptRequest>,
    ) -> Result<Response<OpenVerificationAttemptResponse>, Status> {
        let inner = request.into_inner();
        let id = parse_engagement_id(&inner.engagement_id)?;
        if inner.attempt_id.trim().is_empty() {
            return Err(Status::invalid_argument("attempt_id is empty"));
        }
        let attempt_id = inner.attempt_id.clone();
        let snapshot_hash = {
            let mut fsm = self.fsm.write().await;
            let session = fsm
                .get_mut(&id)
                .ok_or_else(|| Status::not_found(format!("engagement {id} not found")))?;
            // Refresh the FSM's view of findings from the caller-provided list.
            session.findings = inner.finding_ids.clone();
            let attempt = session.open_verification_attempt(attempt_id.clone());
            attempt.snapshot_hash.clone()
        };

        self.event_store
            .append(
                id,
                EventKind::VerificationAttemptOpened {
                    attempt_id: attempt_id.clone(),
                    snapshot_hash: snapshot_hash.clone(),
                    finding_ids: inner.finding_ids,
                },
                self.workspace_signer(),
            )
            .map_err(|e| Status::internal(format!("event store: {e}")))?;
        if let Some(row) = self.state.write().await.get_mut(&id) {
            row.event_count += 1;
        }

        info!(engagement_id = %id, %attempt_id, %snapshot_hash, "verification attempt opened");
        Ok(Response::new(OpenVerificationAttemptResponse {
            engagement_id: id.to_string(),
            attempt_id,
            snapshot_hash,
        }))
    }

    async fn write_verification_round(
        &self,
        request: Request<WriteVerificationRoundRequest>,
    ) -> Result<Response<WriteVerificationRoundResponse>, Status> {
        let inner = request.into_inner();
        let id = parse_engagement_id(&inner.engagement_id)?;
        let round_kind = parse_round(&inner.round).ok_or_else(|| {
            Status::invalid_argument(format!(
                "round {:?} must be brutalist|balanced|final",
                inner.round
            ))
        })?;
        let round_value: VerificationRoundResult = serde_json::from_slice(&inner.round_json)
            .map_err(|e| Status::invalid_argument(format!("round_json: {e}")))?;
        if round_value.round != round_kind {
            return Err(Status::invalid_argument(format!(
                "round field {:?} does not match payload round {:?}",
                inner.round, round_value.round
            )));
        }

        // Cross-check attempt binding. The daemon owns the canonical
        // attempt_id; the caller-supplied attempt_id must agree.
        {
            let fsm = self.fsm.read().await;
            let session = fsm
                .get(&id)
                .ok_or_else(|| Status::not_found(format!("engagement {id} not found")))?;
            let attempt = session.verification_attempt.as_ref().ok_or_else(|| {
                Status::failed_precondition("no open verification attempt; call open first")
            })?;
            if !inner.attempt_id.is_empty() && inner.attempt_id != attempt.attempt_id {
                return Err(Status::failed_precondition(format!(
                    "attempt_id {:?} stale; current is {:?}",
                    inner.attempt_id, attempt.attempt_id
                )));
            }
        }

        let canonical = serde_json::to_vec(&round_value)
            .map_err(|e| Status::internal(format!("canonicalize round: {e}")))?;
        let canonical_hash = hex::encode(blake3::hash(&canonical).as_bytes());
        let results_count = round_value.results.len() as u32;
        let references_plan_hash = round_value.references_plan_hash.clone();

        // Land the round in the FSM.
        let attempt_id = {
            let mut fsm = self.fsm.write().await;
            let session = fsm.get_mut(&id).ok_or_else(|| {
                Status::not_found(format!("engagement {id} disappeared during write"))
            })?;
            session.record_verification_round(round_value);
            session
                .verification_attempt
                .as_ref()
                .map(|a| a.attempt_id.clone())
                .unwrap_or_default()
        };

        self.event_store
            .append(
                id,
                EventKind::VerificationRoundWritten {
                    attempt_id,
                    round: round_kind.as_str().to_string(),
                    results_canonical_hash: canonical_hash.clone(),
                    results_count,
                    references_plan_hash,
                },
                self.workspace_signer(),
            )
            .map_err(|e| Status::internal(format!("event store: {e}")))?;
        if let Some(row) = self.state.write().await.get_mut(&id) {
            row.event_count += 1;
        }

        info!(
            engagement_id = %id,
            round = round_kind.as_str(),
            results_count,
            "verification round written"
        );
        Ok(Response::new(WriteVerificationRoundResponse {
            engagement_id: id.to_string(),
            round: round_kind.as_str().to_string(),
            results_canonical_hash: canonical_hash,
            results_count,
        }))
    }

    async fn build_verification_adjudication(
        &self,
        request: Request<BuildVerificationAdjudicationRequest>,
    ) -> Result<Response<BuildVerificationAdjudicationResponse>, Status> {
        let id = parse_engagement_id(&request.into_inner().engagement_id)?;
        let (attempt_id, adjudication_json, plan_hash, counts) = {
            let mut fsm = self.fsm.write().await;
            let session = fsm
                .get_mut(&id)
                .ok_or_else(|| Status::not_found(format!("engagement {id} not found")))?;
            let plan_hash = session
                .build_and_record_adjudication()
                .map_err(|e| Status::failed_precondition(format!("adjudication: {e}")))?;
            let attempt = session
                .verification_attempt
                .as_ref()
                .ok_or_else(|| Status::internal("attempt vanished after build"))?;
            let adj = attempt
                .adjudication
                .as_ref()
                .ok_or_else(|| Status::internal("adjudication vanished after build"))?;
            let counts = (
                adj.agreed.len() as u32,
                adj.disagreements.len() as u32,
                adj.replay_required.len() as u32,
                adj.qa_sample.len() as u32,
            );
            let adj_json = serde_json::to_vec(adj)
                .map_err(|e| Status::internal(format!("encode adjudication: {e}")))?;
            (attempt.attempt_id.clone(), adj_json, plan_hash, counts)
        };

        self.event_store
            .append(
                id,
                EventKind::AdjudicationBuilt {
                    attempt_id: attempt_id.clone(),
                    plan_hash: plan_hash.clone(),
                    agreed_count: counts.0,
                    disagreements_count: counts.1,
                    replay_required_count: counts.2,
                    qa_sample_count: counts.3,
                },
                self.workspace_signer(),
            )
            .map_err(|e| Status::internal(format!("event store: {e}")))?;
        if let Some(row) = self.state.write().await.get_mut(&id) {
            row.event_count += 1;
        }

        info!(
            engagement_id = %id,
            %attempt_id,
            %plan_hash,
            "adjudication built"
        );
        Ok(Response::new(BuildVerificationAdjudicationResponse {
            engagement_id: id.to_string(),
            attempt_id,
            plan_hash,
            agreed_count: counts.0,
            disagreements_count: counts.1,
            replay_required_count: counts.2,
            qa_sample_count: counts.3,
            adjudication_json,
        }))
    }

    async fn write_grade_verdict(
        &self,
        request: Request<WriteGradeVerdictRequest>,
    ) -> Result<Response<WriteGradeVerdictResponse>, Status> {
        let inner = request.into_inner();
        let id = parse_engagement_id(&inner.engagement_id)?;
        let verdict: GradeVerdict = serde_json::from_slice(&inner.verdict_json)
            .map_err(|e| Status::invalid_argument(format!("verdict_json: {e}")))?;

        let verdict_str = verdict.verdict.as_str().to_string();
        let total_score = verdict.total_score;

        let canonical = serde_json::to_vec(&verdict)
            .map_err(|e| Status::internal(format!("canonicalize verdict: {e}")))?;
        let canonical_hash = hex::encode(blake3::hash(&canonical).as_bytes());
        let canonical_str = String::from_utf8(canonical)
            .map_err(|e| Status::internal(format!("canonical to utf8: {e}")))?;

        // Persist into the in-memory FSM so the gate can open.
        {
            let mut fsm = self.fsm.write().await;
            let session = fsm
                .get_mut(&id)
                .ok_or_else(|| Status::not_found(format!("engagement {id} not found")))?;
            session.write_grade(verdict);
        }
        self.event_store
            .append(
                id,
                EventKind::GradeVerdictRecorded {
                    verdict: verdict_str.clone(),
                    total_score: total_score as u32,
                    verdict_canonical_hash: canonical_hash.clone(),
                    verdict_json: canonical_str,
                },
                self.workspace_signer(),
            )
            .map_err(|e| Status::internal(format!("event store: {e}")))?;
        if let Some(row) = self.state.write().await.get_mut(&id) {
            row.event_count += 1;
        }

        info!(
            engagement_id = %id,
            verdict = %verdict_str,
            total_score,
            "grade verdict written"
        );
        Ok(Response::new(WriteGradeVerdictResponse {
            engagement_id: id.to_string(),
            verdict: verdict_str,
            total_score: total_score as u32,
            verdict_canonical_hash: canonical_hash,
        }))
    }
}

fn parse_round(s: &str) -> Option<VerificationRound> {
    match s {
        "brutalist" => Some(VerificationRound::Brutalist),
        "balanced" => Some(VerificationRound::Balanced),
        "final" => Some(VerificationRound::Final),
        _ => None,
    }
}

fn transition_to_status(err: TransitionError) -> Status {
    match err {
        TransitionError::InvalidEdge { from, to } => Status::failed_precondition(format!(
            "invalid edge: {from} -> {to}"
        )),
        TransitionError::OverrideReasonTooShort => {
            Status::invalid_argument("override_reason must be at least 20 characters")
        }
        TransitionError::OverrideNotPermitted { from, to } => Status::failed_precondition(
            format!("override_reason not permitted for {from} -> {to}"),
        ),
        TransitionError::GateRefused(s) => Status::failed_precondition(format!("gate refused: {s}")),
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

#[cfg(test)]
mod tests {
    //! Integration tests for the FSM-driven gRPC surface. These
    //! exercise `TransitionPhase` + `GetSessionState` against a
    //! tempfile-backed workspace and event store; the gRPC layer is
    //! tested in-process by calling the trait methods directly.

    use super::*;
    use camino::Utf8PathBuf;
    use mantis_event_store::EventStore;
    use mantis_workspace::{InMemoryKeyStore, Workspace};
    use tonic::Request;

    async fn make_service() -> (tempfile::TempDir, EngagementServiceImpl) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).expect("utf8");
        let ks = InMemoryKeyStore::new();
        let workspace =
            Arc::new(Workspace::init(&root, &ks).expect("init workspace"));
        let event_store =
            Arc::new(EventStore::open(&root.join("events.rocksdb")).expect("event store"));
        let svc = EngagementServiceImpl::new(workspace, event_store).expect("svc");
        (tmp, svc)
    }

    async fn create_engagement(svc: &EngagementServiceImpl, name: &str) -> String {
        let resp = svc
            .create(Request::new(CreateRequest {
                name: name.to_string(),
            }))
            .await
            .expect("create rpc");
        resp.into_inner().id
    }

    #[tokio::test]
    async fn create_seeds_fsm_in_recon_phase() {
        let (_tmp, svc) = make_service().await;
        let id = create_engagement(&svc, "demo").await;
        let resp = svc
            .get_session_state(Request::new(SessionStateRequest {
                engagement_id: id.clone(),
            }))
            .await
            .expect("get session state");
        let payload = resp.into_inner().session_json;
        let v: serde_json::Value =
            serde_json::from_slice(&payload).expect("session json parses");
        assert_eq!(v["phase"], "RECON");
        assert_eq!(v["target"], "demo");
        assert_eq!(v["auth_status"], "pending");
    }

    #[tokio::test]
    async fn transition_to_unknown_phase_returns_invalid_argument() {
        let (_tmp, svc) = make_service().await;
        let id = create_engagement(&svc, "demo").await;
        let err = svc
            .transition_phase(Request::new(TransitionPhaseRequest {
                engagement_id: id,
                to_phase: "RECONNN".into(),
                override_reason: None,
                auth_status: None,
            }))
            .await
            .expect_err("invalid phase");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn transition_recon_to_auth_without_surfaces_is_gate_refused() {
        let (_tmp, svc) = make_service().await;
        let id = create_engagement(&svc, "demo").await;
        let err = svc
            .transition_phase(Request::new(TransitionPhaseRequest {
                engagement_id: id,
                to_phase: "AUTH".into(),
                override_reason: None,
                auth_status: None,
            }))
            .await
            .expect_err("gate should refuse");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        // The message must mention which gate refused.
        assert!(err.message().contains("gate refused"));
    }

    #[tokio::test]
    async fn full_forward_path_appends_one_event_per_transition() {
        let (_tmp, svc) = make_service().await;
        let id_str = create_engagement(&svc, "demo").await;
        let id = parse_engagement_id(&id_str).unwrap();

        // Seed an "explored" surface so RECON->AUTH passes without
        // running a real scan.
        svc.fsm
            .write()
            .await
            .get_mut(&id)
            .unwrap()
            .explored
            .push("s-1".into());

        // RECON -> AUTH (no auth_status; gate only checks surfaces)
        let resp = svc
            .transition_phase(Request::new(TransitionPhaseRequest {
                engagement_id: id_str.clone(),
                to_phase: "AUTH".into(),
                override_reason: None,
                auth_status: None,
            }))
            .await
            .expect("recon->auth");
        let resp = resp.into_inner();
        assert_eq!(resp.from_phase, "RECON");
        assert_eq!(resp.to_phase, "AUTH");
        assert!(resp.transitioned);
        assert!(!resp.override_applied);
        assert!(resp.blockers.is_empty());

        // AUTH -> HUNT with auth_status=unauthenticated.
        let resp = svc
            .transition_phase(Request::new(TransitionPhaseRequest {
                engagement_id: id_str.clone(),
                to_phase: "HUNT".into(),
                override_reason: None,
                auth_status: Some("unauthenticated".into()),
            }))
            .await
            .expect("auth->hunt");
        assert_eq!(resp.into_inner().to_phase, "HUNT");

        // Confirm one PhaseTransitioned event was appended per call.
        let events = svc.event_store.replay(id).expect("replay");
        let n = events
            .iter()
            .filter(|e| matches!(e.kind, EventKind::PhaseTransitioned { .. }))
            .count();
        assert_eq!(n, 2, "two transitions → two events");
    }

    #[tokio::test]
    async fn override_is_recorded_and_event_carries_blocker_codes() {
        let (_tmp, svc) = make_service().await;
        let id_str = create_engagement(&svc, "demo").await;
        let id = parse_engagement_id(&id_str).unwrap();

        // Advance through RECON->AUTH->HUNT cleanly with a seeded surface.
        {
            let mut fsm = svc.fsm.write().await;
            let s = fsm.get_mut(&id).unwrap();
            s.explored.push("s-1".into());
        }
        svc.transition_phase(Request::new(TransitionPhaseRequest {
            engagement_id: id_str.clone(),
            to_phase: "AUTH".into(),
            override_reason: None,
            auth_status: None,
        }))
        .await
        .unwrap();
        svc.transition_phase(Request::new(TransitionPhaseRequest {
            engagement_id: id_str.clone(),
            to_phase: "HUNT".into(),
            override_reason: None,
            auth_status: Some("unauthenticated".into()),
        }))
        .await
        .unwrap();

        // Inject an unexplored HIGH surface — HUNT->CHAIN must refuse
        // unless the operator overrides.
        {
            let mut fsm = svc.fsm.write().await;
            let s = fsm.get_mut(&id).unwrap();
            s.high_priority_surfaces.push("high-1".into());
        }
        let refused = svc
            .transition_phase(Request::new(TransitionPhaseRequest {
                engagement_id: id_str.clone(),
                to_phase: "CHAIN".into(),
                override_reason: None,
                auth_status: None,
            }))
            .await
            .expect_err("must refuse without override");
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);

        let ok = svc
            .transition_phase(Request::new(TransitionPhaseRequest {
                engagement_id: id_str.clone(),
                to_phase: "CHAIN".into(),
                override_reason: Some(
                    "operator accepted unexplored high surface for the next pass; tracked PR-1".into(),
                ),
                auth_status: None,
            }))
            .await
            .expect("override should pass");
        let ok = ok.into_inner();
        assert!(ok.override_applied);
        assert!(!ok.blockers.is_empty());
        assert!(ok
            .blockers
            .iter()
            .any(|b| b.code == "unexplored_high_surfaces"));

        // Check the audit trail in the merkle log.
        let events = svc.event_store.replay(id).unwrap();
        let last_pt = events
            .iter()
            .rev()
            .find_map(|e| match &e.kind {
                EventKind::PhaseTransitioned {
                    from,
                    to,
                    override_reason,
                    blocker_codes,
                } => Some((from, to, override_reason, blocker_codes)),
                _ => None,
            })
            .expect("PhaseTransitioned in log");
        assert_eq!(last_pt.0, "HUNT");
        assert_eq!(last_pt.1, "CHAIN");
        assert!(last_pt.2.as_ref().unwrap().contains("operator accepted"));
        assert!(last_pt.3.contains(&"unexplored_high_surfaces".to_string()));
    }

    #[tokio::test]
    async fn override_reason_too_short_is_invalid() {
        let (_tmp, svc) = make_service().await;
        let id = create_engagement(&svc, "demo").await;
        let err = svc
            .transition_phase(Request::new(TransitionPhaseRequest {
                engagement_id: id,
                to_phase: "AUTH".into(),
                override_reason: Some("nope".into()),
                auth_status: None,
            }))
            .await
            .expect_err("too-short override");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("at least 20 characters"));
    }

    #[tokio::test]
    async fn full_3_round_cascade_passes_verify_to_grade_gate() {
        let (_tmp, svc) = make_service().await;
        let id_str = create_engagement(&svc, "demo").await;
        let id = parse_engagement_id(&id_str).unwrap();

        // Park the FSM in VERIFY (without going through every gate
        // — daemon tests for that path exist already).
        {
            let mut fsm = svc.fsm.write().await;
            let session = fsm.get_mut(&id).unwrap();
            session.phase = Phase::Verify;
            session.findings = vec!["F-1".into(), "F-2".into()];
            session.chain_attempt_finding_ids = vec!["F-1".into()];
        }

        // Open attempt.
        let open = svc
            .open_verification_attempt(Request::new(OpenVerificationAttemptRequest {
                engagement_id: id_str.clone(),
                attempt_id: "att-1".into(),
                finding_ids: vec!["F-1".into(), "F-2".into()],
            }))
            .await
            .expect("open")
            .into_inner();
        assert_eq!(open.attempt_id, "att-1");
        assert!(!open.snapshot_hash.is_empty());

        // Helper to write a round.
        async fn write_round(
            svc: &EngagementServiceImpl,
            id_str: &str,
            round: VerificationRound,
            verdicts: Vec<mantis_fsm::FindingVerdict>,
            plan_hash: Option<&str>,
        ) {
            let mut r = VerificationRoundResult::new(round, verdicts);
            if let Some(h) = plan_hash {
                r = r.with_plan_hash(h);
            }
            let json = serde_json::to_vec(&r).unwrap();
            svc.write_verification_round(Request::new(WriteVerificationRoundRequest {
                engagement_id: id_str.into(),
                attempt_id: "att-1".into(),
                round: round.as_str().into(),
                round_json: json,
            }))
            .await
            .expect("write round");
        }

        let verdicts = vec![
            mantis_fsm::FindingVerdict::confirmed("F-1", mantis_fsm::Severity::High, "x"),
            mantis_fsm::FindingVerdict::confirmed("F-2", mantis_fsm::Severity::Medium, "x"),
        ];
        write_round(&svc, &id_str, VerificationRound::Brutalist, verdicts.clone(), None).await;
        write_round(&svc, &id_str, VerificationRound::Balanced, verdicts.clone(), None).await;

        // Build adjudication → get plan hash.
        let adj = svc
            .build_verification_adjudication(Request::new(
                BuildVerificationAdjudicationRequest {
                    engagement_id: id_str.clone(),
                },
            ))
            .await
            .expect("build adj")
            .into_inner();
        assert!(!adj.plan_hash.is_empty());

        // Final round with the plan hash → gate must open.
        write_round(
            &svc,
            &id_str,
            VerificationRound::Final,
            verdicts,
            Some(&adj.plan_hash),
        )
        .await;

        // Inject evidence packs for every reportable finding so the
        // VERIFY→GRADE evidence-coverage gate opens.
        {
            let mut fsm = svc.fsm.write().await;
            let session = fsm.get_mut(&id).unwrap();
            for fid in ["F-1", "F-2"] {
                session
                    .record_evidence_pack(mantis_fsm::EvidencePack {
                        finding_id: fid.into(),
                        sample_count: 1,
                        aggregate_counts: Vec::new(),
                        representative_samples: vec![mantis_fsm::EvidenceSample {
                            sample_type: "http_replay".into(),
                            payload: "PoC".into(),
                            label: "req-1".into(),
                        }],
                        sensitive_clusters: Vec::new(),
                        replay_summary: "replayed".into(),
                        redaction_notes: "x".into(),
                        report_snippet: "snippet".into(),
                    })
                    .unwrap();
            }
        }

        // Verify→Grade should now pass.
        let resp = svc
            .transition_phase(Request::new(TransitionPhaseRequest {
                engagement_id: id_str,
                to_phase: "GRADE".into(),
                override_reason: None,
                auth_status: None,
            }))
            .await
            .expect("verify->grade")
            .into_inner();
        assert_eq!(resp.to_phase, "GRADE");
        assert!(resp.transitioned);

        // Merkle log carries one VerificationAttemptOpened + 3
        // VerificationRoundWritten + 1 AdjudicationBuilt + 1
        // PhaseTransitioned (final).
        let events = svc.event_store.replay(id).unwrap();
        let mut opened = 0;
        let mut written = 0;
        let mut built = 0;
        for e in &events {
            match &e.kind {
                EventKind::VerificationAttemptOpened { .. } => opened += 1,
                EventKind::VerificationRoundWritten { .. } => written += 1,
                EventKind::AdjudicationBuilt { .. } => built += 1,
                _ => {}
            }
        }
        assert_eq!(opened, 1);
        assert_eq!(written, 3);
        assert_eq!(built, 1);
    }

    #[tokio::test]
    async fn write_round_rejects_stale_attempt_id() {
        let (_tmp, svc) = make_service().await;
        let id_str = create_engagement(&svc, "demo").await;
        let id = parse_engagement_id(&id_str).unwrap();

        // Open attempt-1.
        svc.fsm.write().await.get_mut(&id).unwrap().findings = vec!["F-1".into()];
        svc.open_verification_attempt(Request::new(OpenVerificationAttemptRequest {
            engagement_id: id_str.clone(),
            attempt_id: "att-1".into(),
            finding_ids: vec!["F-1".into()],
        }))
        .await
        .unwrap();

        // Try to write with attempt-OTHER.
        let r = VerificationRoundResult::new(
            VerificationRound::Brutalist,
            vec![mantis_fsm::FindingVerdict::confirmed(
                "F-1",
                mantis_fsm::Severity::High,
                "x",
            )],
        );
        let err = svc
            .write_verification_round(Request::new(WriteVerificationRoundRequest {
                engagement_id: id_str,
                attempt_id: "att-OTHER".into(),
                round: "brutalist".into(),
                round_json: serde_json::to_vec(&r).unwrap(),
            }))
            .await
            .expect_err("stale attempt id rejected");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("stale"));
    }

    #[tokio::test]
    async fn build_adjudication_returns_deterministic_plan_hash() {
        let (_tmp, svc) = make_service().await;
        let id_str = create_engagement(&svc, "demo").await;
        let id = parse_engagement_id(&id_str).unwrap();
        svc.fsm.write().await.get_mut(&id).unwrap().findings = vec!["F-1".into()];

        svc.open_verification_attempt(Request::new(OpenVerificationAttemptRequest {
            engagement_id: id_str.clone(),
            attempt_id: "att-1".into(),
            finding_ids: vec!["F-1".into()],
        }))
        .await
        .unwrap();

        let r = VerificationRoundResult::new(
            VerificationRound::Brutalist,
            vec![mantis_fsm::FindingVerdict::confirmed(
                "F-1",
                mantis_fsm::Severity::High,
                "x",
            )],
        );
        let json = serde_json::to_vec(&r).unwrap();
        svc.write_verification_round(Request::new(WriteVerificationRoundRequest {
            engagement_id: id_str.clone(),
            attempt_id: "att-1".into(),
            round: "brutalist".into(),
            round_json: json.clone(),
        }))
        .await
        .unwrap();
        let r2 = VerificationRoundResult::new(
            VerificationRound::Balanced,
            vec![mantis_fsm::FindingVerdict::confirmed(
                "F-1",
                mantis_fsm::Severity::High,
                "x",
            )],
        );
        svc.write_verification_round(Request::new(WriteVerificationRoundRequest {
            engagement_id: id_str.clone(),
            attempt_id: "att-1".into(),
            round: "balanced".into(),
            round_json: serde_json::to_vec(&r2).unwrap(),
        }))
        .await
        .unwrap();
        let a = svc
            .build_verification_adjudication(Request::new(
                BuildVerificationAdjudicationRequest {
                    engagement_id: id_str.clone(),
                },
            ))
            .await
            .unwrap()
            .into_inner();
        let b = svc
            .build_verification_adjudication(Request::new(
                BuildVerificationAdjudicationRequest {
                    engagement_id: id_str,
                },
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(a.plan_hash, b.plan_hash);
        assert!(!a.adjudication_json.is_empty());
    }

    #[tokio::test]
    async fn replay_restores_fsm_on_service_restart() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).expect("utf8");
        let ks = InMemoryKeyStore::new();
        let workspace =
            Arc::new(Workspace::init(&root, &ks).expect("init workspace"));
        let event_store_path = root.join("events.rocksdb");

        // First service instance: create + transition.
        let id_str = {
            let event_store = Arc::new(EventStore::open(&event_store_path).expect("open events"));
            let svc = EngagementServiceImpl::new(workspace.clone(), event_store).expect("svc");
            let id_str = create_engagement(&svc, "demo").await;
            let id = parse_engagement_id(&id_str).unwrap();
            svc.fsm
                .write()
                .await
                .get_mut(&id)
                .unwrap()
                .explored
                .push("s-1".into());
            svc.transition_phase(Request::new(TransitionPhaseRequest {
                engagement_id: id_str.clone(),
                to_phase: "AUTH".into(),
                override_reason: None,
                auth_status: None,
            }))
            .await
            .unwrap();
            id_str
        };

        // Drop the event-store handle by going out of scope; reopen.
        let event_store = Arc::new(EventStore::open(&event_store_path).expect("reopen events"));
        let svc = EngagementServiceImpl::new(workspace, event_store).expect("svc reload");

        // The new service must have replayed the PhaseTransitioned
        // event and parked the FSM in AUTH.
        let resp = svc
            .get_session_state(Request::new(SessionStateRequest {
                engagement_id: id_str,
            }))
            .await
            .expect("get session state");
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_inner().session_json).unwrap();
        assert_eq!(v["phase"], "AUTH");
    }

    #[tokio::test]
    async fn write_grade_verdict_persists_into_fsm_and_opens_grade_to_report_gate() {
        let (_tmp, svc) = make_service().await;
        let id_str = create_engagement(&svc, "skip-eng").await;
        let id = parse_engagement_id(&id_str).unwrap();

        // Set the FSM to GRADE phase directly (bypass transition gates for test speed).
        {
            let mut fsm = svc.fsm.write().await;
            let s = fsm.get_mut(&id).unwrap();
            s.explored.push("https://example.com/".into());
            s.phase = mantis_fsm::Phase::Grade;
        }

        // GRADE -> REPORT must be blocked (no verdict yet).
        let blocked = svc
            .transition_phase(Request::new(TransitionPhaseRequest {
                engagement_id: id_str.clone(),
                to_phase: "REPORT".into(),
                override_reason: None,
                auth_status: None,
            }))
            .await
            .expect_err("must block without verdict");
        assert!(blocked.message().contains("grade_missing"));

        // Write a SKIP verdict (empty findings → SKIP).
        let verdict = mantis_fsm::GradeVerdict::compute(vec![], Some("no findings".into()));
        let verdict_json = serde_json::to_vec(&verdict).unwrap();
        let write_resp = svc
            .write_grade_verdict(Request::new(WriteGradeVerdictRequest {
                engagement_id: id_str.clone(),
                verdict_json,
            }))
            .await
            .expect("write_grade_verdict");
        let wr = write_resp.into_inner();
        assert_eq!(wr.verdict, "SKIP");
        assert_eq!(wr.total_score, 0);
        assert!(!wr.verdict_canonical_hash.is_empty());

        // GRADE -> REPORT must now pass.
        svc.transition_phase(Request::new(TransitionPhaseRequest {
            engagement_id: id_str.clone(),
            to_phase: "REPORT".into(),
            override_reason: None,
            auth_status: None,
        }))
        .await
        .expect("grade->report should pass after writing SKIP verdict");

        // Verify the GradeVerdictRecorded event landed in the merkle log.
        let events = svc.event_store.replay(id).unwrap();
        assert!(events.iter().any(|e| matches!(
            &e.kind,
            mantis_event_store::EventKind::GradeVerdictRecorded { verdict, .. }
            if verdict == "SKIP"
        )));
    }
}
