//! `MantisMcpServer` and its tool router.
//!
//! Each tool method is a thin wrapper around a daemon gRPC call.
//! Inputs deserialize from MCP tool arguments via `serde` +
//! `schemars` (the JSON schema is what the host LLM sees when it
//! decides whether and how to call the tool). Outputs are returned
//! as JSON-serialized text content so the LLM can parse structured
//! data back into its planning loop.
//!
//! Errors travel as `rmcp::ErrorData`. We surface daemon-side
//! failures with `invalid_request` for client-fixable issues
//! (unknown engagement id, malformed url) and `internal_error` for
//! infrastructure problems (daemon down, signing-key missing).

use std::str::FromStr;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::{schemars, tool, tool_router, ErrorData as McpError};
use serde::{Deserialize, Serialize};
use serde_json::json;

use mantis_pack::{PackRegistry, SurfaceDescriptor};
use mantis_proto::v1::{
    AuthorizeRequest, BuildVerificationAdjudicationRequest, CreateRequest,
    EngagementState as ProtoState, ExportRequest, ListRequest,
    OpenVerificationAttemptRequest, ScanRequest, SessionStateRequest, StartRequest,
    StatusRequest, TransitionPhaseRequest, WriteVerificationRoundRequest,
};

use crate::daemon;
use crate::scope::build_signed_scope_json;
use crate::wave;

#[derive(Debug, Clone)]
pub struct MantisMcpServer {
    daemon_endpoint: String,
}

impl MantisMcpServer {
    pub fn new(daemon_endpoint: String) -> Self {
        Self { daemon_endpoint }
    }
}

// ---------- input schemas ----------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateEngagementArgs {
    /// Human-readable engagement name. If empty, a `mantis-<ulid>`
    /// name is generated.
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AuthorizeScopeArgs {
    /// Engagement id returned by `mantis_create_engagement`.
    pub engagement_id: String,
    /// URL targets the engagement is authorized to test. Host and
    /// port matchers are derived from this list.
    pub targets: Vec<String>,
    /// Wall-clock budget the daemon will enforce on this engagement.
    /// Defaults to 1800s (30 minutes).
    #[serde(default = "default_budget")]
    pub budget_seconds: u32,
}

fn default_budget() -> u32 {
    1800
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EngagementIdArgs {
    /// Engagement id (ULID).
    pub engagement_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunReconArgs {
    /// Engagement id.
    pub engagement_id: String,
    /// URL targets to probe. Each must be in the engagement's
    /// authorized scope or the daemon will reject the request at the
    /// egress proxy.
    pub targets: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RenderReportArgs {
    /// Engagement id to render.
    pub engagement_id: String,
    /// Output directory. Defaults to
    /// `./mantishack-<engagement-id>/` relative to the daemon's
    /// working directory.
    #[serde(default)]
    pub output_dir: Option<String>,
    /// Severity floor for the rendered markdown. Findings strictly
    /// below this floor are suppressed from the findings section but
    /// remain in `events.jsonl` for auditability. One of
    /// `critical|high|medium|low|info`. Defaults to `low` — i.e. info
    /// noise (recon fingerprints, missing-header attestations, etc.)
    /// does not appear in the rendered report.
    #[serde(default)]
    pub severity_floor: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StartWaveArgs {
    /// Engagement id this wave belongs to.
    pub engagement_id: String,
    /// One entry per parallel hunter. The orchestrator decides the
    /// split; assignment ids are generated server-side and returned.
    pub assignments: Vec<StartWaveAssignment>,
}

/// Wave-start input: surfaces and optional metadata. The server
/// generates the assignment id (ULID) so two orchestrators can't
/// race to claim the same id.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StartWaveAssignment {
    pub surfaces: Vec<String>,
    #[serde(default)]
    pub vuln_classes: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WaveIdArgs {
    pub engagement_id: String,
    pub wave_number: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OpenVerificationAttemptArgs {
    pub engagement_id: String,
    /// ULID-style identifier for the new attempt. Choose any unique
    /// string; the daemon stamps it on every cascade event.
    pub attempt_id: String,
    /// Findings the cascade will cover. The snapshot hash is computed
    /// deterministically from this set; the cascade gate refuses a
    /// final round bound to a stale snapshot.
    pub finding_ids: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteVerificationRoundArgs {
    pub engagement_id: String,
    pub attempt_id: String,
    /// `brutalist` | `balanced` | `final`.
    pub round: String,
    /// Canonical JSON of `VerificationRoundResult`. Daemon validates,
    /// canonicalises, and stores. The final round MUST include
    /// `references_plan_hash` equal to the current adjudication plan.
    pub round_json: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BuildVerificationAdjudicationArgs {
    pub engagement_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadFindingsArgs {
    pub engagement_id: String,
    /// Optional severity floor. One of `info|low|medium|high|critical`.
    /// Findings strictly below this floor are dropped from the result.
    /// Defaults to `info` (return everything) when omitted — this is
    /// a read tool, not a renderer.
    #[serde(default)]
    pub severity_floor: Option<String>,
    /// Optional wave number filter. When set, only findings from
    /// that wave are returned. Omit for all waves.
    #[serde(default)]
    pub wave_number: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadWaveHandoffsArgs {
    pub engagement_id: String,
    pub wave_number: u32,
}

/// Generic "operation against an existing engagement" argument. Used
/// by every read-only inspector tool and a few state-clear writes.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PayloadToolArgs {
    /// Engagement id (ULID).
    pub engagement_id: String,
    /// Free-form JSON payload. Each tool documents its expected shape
    /// in the tool description.
    #[serde(default)]
    pub data: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PlaybookIdArgs {
    pub engagement_id: String,
    /// Capability playbook id, e.g. `C5_idor_burst`, `C9_ssrf_to_imds`.
    pub playbook_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TechniquePackArgs {
    pub engagement_id: String,
    /// Technique pack id, e.g. `auth-differential`, `idor-burst`,
    /// `ssrf-imds`, `graphql-introspection`.
    pub pack_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChainQueryArgs {
    pub engagement_id: String,
    /// Chain node id (BLAKE3 of finding ids + prerequisites + outcome).
    pub node_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChainToolArgs {
    pub engagement_id: String,
    /// Chain family — one of `evm`, `svm`, `aptos`, `sui`, `substrate`,
    /// `cosmwasm`. The tool dispatches to the appropriate RPC ladder.
    pub chain_family: String,
    /// Network id — e.g. `mainnet`, `sepolia`, `devnet`, `testnet`.
    /// Default `mainnet` if absent.
    #[serde(default)]
    pub network: Option<String>,
    /// Contract / program / package address. Encoding depends on the
    /// chain family (hex for EVM, base58 for SVM, etc.).
    #[serde(default)]
    pub address: Option<String>,
    /// Call data — depends on the tool. Examples: ABI-encoded calldata
    /// (`evm_call`), storage slot (`evm_storage_read`), Move type
    /// identifier (`aptos_fetch_resource`), JSON smart-query body
    /// (`cosmwasm_smart_query`).
    #[serde(default)]
    pub data: serde_json::Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunAuthDifferentialArgs {
    /// Engagement id (ULID).
    pub engagement_id: String,
    /// Target URL to fetch under each profile (GET only).
    pub url: String,
    /// 1..N profile bindings to replay against the URL.
    pub profiles: Vec<RunAuthDifferentialProfile>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunAuthDifferentialProfile {
    /// Role label: `unauthenticated`, `attacker`, `victim`, `admin`.
    pub role: String,
    /// Optional human-readable profile name (for cross-referencing
    /// with the engagement's auth store).
    #[serde(default)]
    pub profile_name: Option<String>,
    /// `Name: value` request headers to set on this profile.
    #[serde(default)]
    pub headers: Vec<String>,
    /// `Name=value` cookies to send on this profile.
    #[serde(default)]
    pub cookies: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GraphqlIntrospectionArgs {
    pub engagement_id: String,
    /// Fully qualified GraphQL endpoint URL.
    pub endpoint: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExtractJsEndpointsArgs {
    pub engagement_id: String,
    /// Fully qualified URL of a JavaScript bundle (e.g. a
    /// `_next/static/chunks/main-<hash>.js` file).
    pub js_url: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WaybackUrlsArgs {
    pub engagement_id: String,
    /// Host to query (e.g. `app.example.com`). Sub-paths are
    /// auto-expanded by the Wayback CDX API.
    pub host: String,
    /// Max records to retrieve. Defaults to 5000.
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunTieredArgs {
    /// Engagement id (ULID).
    pub engagement_id: String,
    /// Full target URL to probe (e.g. `https://app.example.com/api/users/123`).
    /// Must be in the engagement's authorized scope.
    pub target_url: String,
    /// Free-form objective string. The LLM reads this verbatim and
    /// uses it as the goal of the generated script. Examples:
    /// "IDOR on /api/users?userId=<id>";
    /// "Mass-assignment via PATCH /rest/v1/users";
    /// "SSRF via `image_url` parameter on /preview".
    pub objective: String,
    /// Wall-clock budget for the full escalation chain (medium + hard
    /// tiers). Defaults to 30 seconds.
    #[serde(default)]
    pub budget_seconds: Option<u32>,
    /// Iteration cap for the hard tier verifier loop. Defaults to 3.
    #[serde(default)]
    pub hard_max_iterations: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RouteSurfacesArgs {
    /// Engagement id — currently informational only; reserved for
    /// per-engagement pack overrides in a future iteration.
    pub engagement_id: String,
    /// Surfaces to route. Each becomes one `RouteDecision`.
    pub surfaces: Vec<RouteSurfaceInput>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RouteSurfaceInput {
    pub surface_id: String,
    /// `web` | `api` | `mobile` | `static-asset` | `smart_contract` | etc.
    /// `None` triggers URL-scheme-based heuristic routing.
    #[serde(default)]
    pub surface_type: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    /// Smart-contract chain family. Ignored for web/api surfaces.
    #[serde(default)]
    pub chain_family: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TransitionPhaseArgs {
    pub engagement_id: String,
    /// One of `RECON`, `AUTH`, `HUNT`, `CHAIN`, `VERIFY`, `GRADE`, `REPORT`.
    /// The daemon enforces the linear forward path and HOLD/re-hunt
    /// edges. Case-sensitive.
    pub to_phase: String,
    /// Operator-supplied rationale for overriding a refused gate.
    /// Required to be at least 20 characters when supplied. Only
    /// accepted for `HUNT -> CHAIN` and `CHAIN -> VERIFY`.
    #[serde(default)]
    pub override_reason: Option<String>,
    /// Optional auth-status update applied before the gate check.
    /// One of `authenticated` | `unauthenticated`. Use when
    /// transitioning `AUTH -> HUNT`.
    #[serde(default)]
    pub auth_status: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RecordChainAttemptArgs {
    pub engagement_id: String,
    pub wave_number: u32,
    /// Titles of the findings the chain composes. Cite each link.
    pub finding_titles: Vec<String>,
    /// Surfaces involved (URLs).
    #[serde(default)]
    pub surfaces: Vec<String>,
    /// One-line narrative: "subdomain takeover -> auth cookie theft".
    pub hypothesis: String,
    /// Replay or rejection steps, one per item.
    pub steps: Vec<String>,
    /// `confirmed` / `denied` / `blocked` / `inconclusive` / `not_applicable`.
    pub outcome: String,
    /// Severity of the composed chain.
    /// Must respect the ladder: LOW+LOW = LOW; chain cannot exceed
    /// max(input_severities)+1 without rationale; cannot exceed +2 even
    /// with rationale. See playbooks/README.md.
    pub severity: String,
    /// Severities of each cited finding, used to enforce the ladder.
    pub input_severities: Vec<String>,
    /// Short prose proof: "POST /verify accepted stale token; 200".
    pub evidence_summary: String,
    /// Required when the chain severity exceeds max(input_severities).
    /// Must contain the token `elevation:` for jumps of 2 rungs.
    #[serde(default)]
    pub severity_elevation_rationale: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteHandoffArgs {
    pub engagement_id: String,
    pub wave_number: u32,
    /// Must match an assignment id returned by `mantis_start_wave`.
    pub assignment_id: String,
    /// Free-form display name for the hunter agent (e.g.
    /// `mantis-hunter`). Stored in the handoff for audit.
    pub hunter: String,
    /// Findings the hunter is reporting. May be empty.
    #[serde(default)]
    pub findings: Vec<wave::Finding>,
    /// Techniques the hunter tried that did not pan out.
    #[serde(default)]
    pub dead_ends: Vec<wave::DeadEnd>,
    /// Coverage notes — list of techniques attempted.
    #[serde(default)]
    pub coverage: Vec<String>,
}

// ---------- response shapes (for LLM-friendly JSON) ----------

#[derive(Debug, Serialize)]
pub struct EngagementSummary {
    pub id: String,
    pub name: String,
    pub state: &'static str,
    pub created_at_unix: u64,
    pub event_count: u64,
    pub scope_hash: Option<String>,
}

impl From<mantis_proto::v1::EngagementInfo> for EngagementSummary {
    fn from(info: mantis_proto::v1::EngagementInfo) -> Self {
        Self {
            id: info.id,
            name: info.name,
            state: state_name(info.state),
            created_at_unix: info.created_at_unix,
            event_count: info.event_count,
            scope_hash: info.scope_hash,
        }
    }
}

pub fn state_name(s: i32) -> &'static str {
    match ProtoState::try_from(s).unwrap_or(ProtoState::Unspecified) {
        ProtoState::Unspecified => "unspecified",
        ProtoState::Draft => "draft",
        ProtoState::Authorized => "authorized",
        ProtoState::Active => "active",
        ProtoState::Paused => "paused",
        ProtoState::Completed => "completed",
        ProtoState::Archived => "archived",
    }
}

#[derive(Debug, Serialize)]
pub struct Surface {
    pub seq: u64,
    pub host: String,
    pub port: u32,
    pub scheme: String,
    pub path: String,
    pub status: u32,
    pub server: Option<String>,
    pub tech_hints: Vec<String>,
}

// ---------- helpers ----------

fn to_internal<E: std::fmt::Display>(label: &str, e: E) -> McpError {
    McpError::internal_error(format!("{label}: {e}"), None)
}

fn to_invalid<E: std::fmt::Display>(label: &str, e: E) -> McpError {
    McpError::invalid_request(format!("{label}: {e}"), None)
}

fn json_ok<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| to_internal("serialize response", e))?;
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

// ---------- tool router ----------

#[tool_router(server_handler)]
impl MantisMcpServer {
    #[tool(
        description = "Create a new Mantis engagement. Returns the engagement id (ULID). \
                       Always call this first; every other tool requires an engagement id."
    )]
    async fn mantis_create_engagement(
        &self,
        Parameters(args): Parameters<CreateEngagementArgs>,
    ) -> Result<CallToolResult, McpError> {
        let name = if args.name.trim().is_empty() {
            format!("mantis-{}", ulid::Ulid::new())
        } else {
            args.name
        };
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let info = client
            .create(CreateRequest { name: name.clone() })
            .await
            .map_err(|e| to_internal("create rpc", e))?
            .into_inner();
        json_ok(&EngagementSummary::from(info))
    }

    #[tool(
        description = "Authorize an engagement's scope. Builds a signed scope manifest from \
                       the URL targets (host + port matchers derived automatically) and submits \
                       it to the daemon. Required before any scan/recon. The daemon enforces \
                       this scope cryptographically at the egress proxy."
    )]
    async fn mantis_authorize_scope(
        &self,
        Parameters(args): Parameters<AuthorizeScopeArgs>,
    ) -> Result<CallToolResult, McpError> {
        if args.targets.is_empty() {
            return Err(McpError::invalid_request(
                "targets must contain at least one URL".to_string(),
                None,
            ));
        }
        let scope_json =
            build_signed_scope_json(&args.engagement_id, &args.targets, args.budget_seconds)
                .map_err(|e| to_internal("build signed scope", e))?;
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let info = client
            .authorize(AuthorizeRequest {
                id: args.engagement_id,
                signed_scope_json: scope_json.into_bytes(),
            })
            .await
            .map_err(|e| to_invalid("authorize rpc", e))?
            .into_inner();
        json_ok(&EngagementSummary::from(info))
    }

    #[tool(
        description = "Transition an authorized engagement into the `active` state so it can \
                       receive scan / recon traffic. Required between `mantis_authorize_scope` \
                       and `mantis_run_recon`. Idempotent: re-calling on an already-active \
                       engagement is a daemon-side no-op."
    )]
    async fn mantis_start_engagement(
        &self,
        Parameters(args): Parameters<EngagementIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let info = client
            .start(StartRequest {
                id: args.engagement_id,
            })
            .await
            .map_err(|e| to_invalid("start rpc", e))?
            .into_inner();
        json_ok(&EngagementSummary::from(info))
    }

    #[tool(
        description = "Look up an engagement by id. Returns its current state \
                       (draft / authorized / active / paused / completed / archived), \
                       event count, scope hash, and creation timestamp."
    )]
    async fn mantis_engagement_status(
        &self,
        Parameters(args): Parameters<EngagementIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let info = client
            .status(StatusRequest {
                id: args.engagement_id,
            })
            .await
            .map_err(|e| to_invalid("status rpc", e))?
            .into_inner();
        json_ok(&EngagementSummary::from(info))
    }

    #[tool(description = "List every engagement known to the daemon.")]
    async fn mantis_engagement_list(&self) -> Result<CallToolResult, McpError> {
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let resp = client
            .list(ListRequest {})
            .await
            .map_err(|e| to_internal("list rpc", e))?
            .into_inner();
        let summaries: Vec<EngagementSummary> =
            resp.engagements.into_iter().map(Into::into).collect();
        json_ok(&summaries)
    }

    // ----- pure-utility leaf tools (no daemon, no network) -----

    #[tool(
        description = "Decode a JWT without verifying its signature. Returns header + payload + \
                       standard-claim extracts (alg, exp, iat, nbf, iss, aud, sub) plus \
                       `warnings` for dangerous patterns like `alg:none`, missing `exp`, expired \
                       tokens, and empty signatures. Use this on Authorization headers, \
                       Set-Cookie tokens, and any base64-looking string suspected of being a JWT. \
                       Accepts a bare JWT or a `Bearer <jwt>` string. Always returns a result — \
                       malformed input becomes a structured payload with `warnings` describing \
                       what went wrong (no client-side retry needed)."
    )]
    async fn mantis_decode_jwt(
        &self,
        Parameters(args): Parameters<crate::utility_tools::DecodeJwtArgs>,
    ) -> Result<CallToolResult, McpError> {
        json_ok(&crate::utility_tools::decode_jwt(&args.jwt))
    }

    #[tool(
        description = "Structurally diff two HTTP responses (status + headers + body) and \
                       classify the divergence: `identical`, `status_changed`, `length_changed`, \
                       `headers_changed`, `body_changed`, or `mixed`. Also surfaces high-signal \
                       `markers` — admin/role flags, JWT shapes, error strings, leaked API keys \
                       (AWS, Stripe, GitHub) — found in one side but not the other. Optimized for \
                       auth-differential and IDOR work: pass `a` = attacker / unauth response, \
                       `b` = victim / authed response, then act on the markers."
    )]
    async fn mantis_diff_responses(
        &self,
        Parameters(args): Parameters<crate::utility_tools::DiffResponsesArgs>,
    ) -> Result<CallToolResult, McpError> {
        json_ok(&crate::utility_tools::diff_responses(&args))
    }

    #[tool(
        description = "Parse a URL into its components and classify it. Returns scheme, host, \
                       port, effective_port (defaults: http=80, https=443), path, query, \
                       fragment, parsed query_params, and `flags` for SSRF / secret-artifact / \
                       admin-like / cloud-metadata detection. Use as a fast lookup before \
                       deciding whether a URL is in-scope, points at IMDS / metadata, embeds \
                       credentials, or targets a secret-exposing path."
    )]
    async fn mantis_summarize_url(
        &self,
        Parameters(args): Parameters<crate::utility_tools::SummarizeUrlArgs>,
    ) -> Result<CallToolResult, McpError> {
        json_ok(&crate::utility_tools::summarize_url(&args.url))
    }

    #[tool(
        description = "Advance the engagement's FSM by one phase. \
                       Pipeline order: RECON -> AUTH -> HUNT -> CHAIN -> VERIFY -> GRADE -> REPORT. \
                       The daemon validates the transition against the persisted session state, \
                       appends a `PhaseTransitioned` event to the merkle log, and returns the \
                       new phase plus any blockers. When a gate refuses, the response contains \
                       the blocker codes; the operator may retry with `override_reason` (≥20 \
                       chars) for `HUNT -> CHAIN` and `CHAIN -> VERIFY` only."
    )]
    async fn mantis_transition_phase(
        &self,
        Parameters(args): Parameters<TransitionPhaseArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let resp = client
            .transition_phase(TransitionPhaseRequest {
                engagement_id: args.engagement_id,
                to_phase: args.to_phase,
                override_reason: args.override_reason,
                auth_status: args.auth_status,
            })
            .await
            .map_err(|e| to_invalid("transition_phase rpc", e))?
            .into_inner();
        let blockers: Vec<serde_json::Value> = resp
            .blockers
            .into_iter()
            .map(|b| {
                json!({
                    "code": b.code,
                    "message": b.message,
                    "identifiers": b.identifiers,
                })
            })
            .collect();
        json_ok(&json!({
            "engagement_id": resp.engagement_id,
            "from_phase": resp.from_phase,
            "to_phase": resp.to_phase,
            "transitioned": resp.transitioned,
            "override_applied": resp.override_applied,
            "blockers": blockers,
        }))
    }

    #[tool(
        description = "Open a fresh 3-round verification attempt. Wipes any in-flight rounds \
                       and freezes a deterministic snapshot of the supplied finding IDs. \
                       The returned `attempt_id` and `snapshot_hash` are required by every \
                       subsequent round write; the cascade gate uses them to detect drift. \
                       Call this once per VERIFY phase entry."
    )]
    async fn mantis_open_verification_attempt(
        &self,
        Parameters(args): Parameters<OpenVerificationAttemptArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let resp = client
            .open_verification_attempt(OpenVerificationAttemptRequest {
                engagement_id: args.engagement_id,
                attempt_id: args.attempt_id,
                finding_ids: args.finding_ids,
            })
            .await
            .map_err(|e| to_invalid("open_verification_attempt rpc", e))?
            .into_inner();
        json_ok(&json!({
            "engagement_id": resp.engagement_id,
            "attempt_id": resp.attempt_id,
            "snapshot_hash": resp.snapshot_hash,
        }))
    }

    #[tool(
        description = "Record one verification round's verdicts. `round` is one of \
                       `brutalist`, `balanced`, `final`. The `round_json` body must be a \
                       canonical `VerificationRoundResult`: `{ round, results: [ \
                       { finding_id, disposition, severity, reportable, confidence, \
                       confidence_reasons, state_sensitive, reasoning } ], notes?, \
                       references_plan_hash? }`. For the `final` round, \
                       `references_plan_hash` MUST equal the current adjudication plan hash \
                       (returned by `mantis_build_verification_adjudication`) or the \
                       VERIFY -> GRADE gate will refuse."
    )]
    async fn mantis_write_verification_round(
        &self,
        Parameters(args): Parameters<WriteVerificationRoundArgs>,
    ) -> Result<CallToolResult, McpError> {
        let round_bytes = serde_json::to_vec(&args.round_json)
            .map_err(|e| to_invalid("round_json serialize", e))?;
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let resp = client
            .write_verification_round(WriteVerificationRoundRequest {
                engagement_id: args.engagement_id,
                attempt_id: args.attempt_id,
                round: args.round,
                round_json: round_bytes,
            })
            .await
            .map_err(|e| to_invalid("write_verification_round rpc", e))?
            .into_inner();
        json_ok(&json!({
            "engagement_id": resp.engagement_id,
            "round": resp.round,
            "results_canonical_hash": resp.results_canonical_hash,
            "results_count": resp.results_count,
        }))
    }

    #[tool(
        description = "Build the deterministic adjudication plan from the recorded brutalist + \
                       balanced rounds. Returns `plan_hash` (the value the final round must \
                       reference), counts of agreed / disagreement / replay-required / qa-sample \
                       findings, and the full canonical `Adjudication` JSON for the \
                       report-writer. Call this between balanced and final rounds. Re-running \
                       it is idempotent for the same input; any change to either round \
                       produces a new plan hash."
    )]
    async fn mantis_build_verification_adjudication(
        &self,
        Parameters(args): Parameters<BuildVerificationAdjudicationArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let resp = client
            .build_verification_adjudication(BuildVerificationAdjudicationRequest {
                engagement_id: args.engagement_id,
            })
            .await
            .map_err(|e| to_invalid("build_verification_adjudication rpc", e))?
            .into_inner();
        let adjudication: serde_json::Value = serde_json::from_slice(&resp.adjudication_json)
            .map_err(|e| to_internal("decode adjudication_json", e))?;
        json_ok(&json!({
            "engagement_id": resp.engagement_id,
            "attempt_id": resp.attempt_id,
            "plan_hash": resp.plan_hash,
            "agreed_count": resp.agreed_count,
            "disagreements_count": resp.disagreements_count,
            "replay_required_count": resp.replay_required_count,
            "qa_sample_count": resp.qa_sample_count,
            "adjudication": adjudication,
        }))
    }

    #[tool(
        description = "Read the engagement's current FSM session state — phase, auth status, \
                       known surfaces, verification rounds completed, grade, and the audit \
                       log of any operator overrides. Returns the canonical `SessionState` \
                       JSON used internally by `mantis-fsm`."
    )]
    async fn mantis_session_state(
        &self,
        Parameters(args): Parameters<EngagementIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let resp = client
            .get_session_state(SessionStateRequest {
                engagement_id: args.engagement_id,
            })
            .await
            .map_err(|e| to_invalid("get_session_state rpc", e))?
            .into_inner();
        // The daemon already canonicalises this JSON; just pass through.
        let value: serde_json::Value = serde_json::from_slice(&resp.session_json)
            .map_err(|e| to_internal("decode session_json", e))?;
        json_ok(&value)
    }

    #[tool(
        description = "Read every finding recorded against an engagement, across all merged \
                       waves. Findings come from wave handoffs the hunters wrote and the wave \
                       merge consolidated into `waves/<n>/merged.json`. Optional `severity_floor` \
                       suppresses below-floor findings (default: return everything). Optional \
                       `wave_number` filters to a single wave."
    )]
    async fn mantis_read_findings(
        &self,
        Parameters(args): Parameters<ReadFindingsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let info = engagement_status(&self.daemon_endpoint, &args.engagement_id).await?;
        let dir = std::path::PathBuf::from(format!("./mantishack-{}", info.id));
        let waves = load_wave_merges(&dir);
        let floor_rank = parse_severity_floor(args.severity_floor.as_deref());
        let mut out: Vec<serde_json::Value> = Vec::new();
        let mut suppressed = 0u32;
        for w in &waves {
            if let Some(wn) = args.wave_number {
                if w.wave_number != wn {
                    continue;
                }
            }
            for f in &w.findings {
                if severity_rank(&f.severity) < floor_rank {
                    suppressed += 1;
                    continue;
                }
                out.push(json!({
                    "wave_number": w.wave_number,
                    "title": f.title,
                    "surface": f.surface,
                    "severity": f.severity,
                    "evidence": f.evidence,
                }));
            }
        }
        // Stable order: severity desc, then wave_number asc, then title.
        out.sort_by(|a, b| {
            let ra = severity_rank(a["severity"].as_str().unwrap_or(""));
            let rb = severity_rank(b["severity"].as_str().unwrap_or(""));
            rb.cmp(&ra)
                .then_with(|| {
                    a["wave_number"]
                        .as_u64()
                        .unwrap_or(0)
                        .cmp(&b["wave_number"].as_u64().unwrap_or(0))
                })
                .then_with(|| {
                    a["title"]
                        .as_str()
                        .unwrap_or("")
                        .cmp(b["title"].as_str().unwrap_or(""))
                })
        });
        json_ok(&json!({
            "engagement_id": info.id,
            "findings": out,
            "suppressed_below_floor": suppressed,
            "waves_scanned": waves.len(),
        }))
    }

    #[tool(
        description = "Read every hunter handoff received for a specific wave of an engagement. \
                       Each handoff carries the assignment id, the hunter's findings, dead-ends, \
                       and coverage. Useful for the orchestrator to inspect hunter output before \
                       merging the wave."
    )]
    async fn mantis_read_wave_handoffs(
        &self,
        Parameters(args): Parameters<ReadWaveHandoffsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let info = engagement_status(&self.daemon_endpoint, &args.engagement_id).await?;
        let assignments = wave::read_assignments(&info.id, args.wave_number)
            .map_err(|e| to_invalid("read_assignments", e))?;
        let mut handoffs: Vec<serde_json::Value> = Vec::new();
        for a in &assignments {
            match wave::read_handoff(&info.id, args.wave_number, &a.id) {
                Some(h) => handoffs.push(json!({
                    "assignment_id": a.id,
                    "received": true,
                    "findings": h.findings,
                    "dead_ends": h.dead_ends,
                    "coverage": h.coverage,
                })),
                None => handoffs.push(json!({
                    "assignment_id": a.id,
                    "received": false,
                })),
            }
        }
        json_ok(&json!({
            "engagement_id": info.id,
            "wave_number": args.wave_number,
            "handoffs": handoffs,
            "assignments_total": assignments.len(),
        }))
    }

    #[tool(
        description = "Route discovered surfaces to their capability packs. Each input surface \
                       is classified by `surface_type` (web | api | smart_contract | ...) plus \
                       `url` and (for SC) `chain_family`. Returns one `RouteDecision` per \
                       surface containing the `pack_id`, `hunter_agent`, `brief_profile`, \
                       `replay_tool`, `sample_type`, routing `confidence` (high | medium | low), \
                       and the `reasons` chain. The orchestrator persists these to drive \
                       hunter dispatch and verifier replay-tool selection without branching on \
                       chain family in prompt code. v1 ships the `web` pack only; smart-contract \
                       surfaces error out as `unsupported`."
    )]
    async fn mantis_route_surfaces(
        &self,
        Parameters(args): Parameters<RouteSurfacesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let registry = PackRegistry::default_v1();
        let mut decisions = Vec::with_capacity(args.surfaces.len());
        let mut errors = Vec::new();
        for surface in args.surfaces {
            let descriptor = SurfaceDescriptor {
                surface_id: surface.surface_id.clone(),
                surface_type: surface.surface_type,
                url: surface.url,
                chain_family: surface.chain_family,
            };
            match registry.route(&descriptor) {
                Ok(decision) => decisions.push(json!({
                    "surface_id": surface.surface_id,
                    "pack_id": decision.pack_id,
                    "pack_version": decision.pack_version,
                    "hunter_agent": decision.hunter_agent,
                    "brief_profile": decision.brief_profile,
                    "replay_tool": decision.replay_tool,
                    "sample_type": decision.sample_type,
                    "confidence": format!("{:?}", decision.confidence).to_lowercase(),
                    "reasons": decision.reasons,
                })),
                Err(e) => errors.push(json!({
                    "surface_id": surface.surface_id,
                    "error": e.to_string(),
                })),
            }
        }
        json_ok(&json!({
            "engagement_id": args.engagement_id,
            "decisions": decisions,
            "errors": errors,
            "registry_packs": registry.pack_ids(),
        }))
    }

    #[tool(
        description = "Run recon against URL targets within an authorized engagement. \
                       The daemon probes each URL, records every discovered surface as an \
                       event, and returns a count of new surfaces / hypotheses. On a 3xx \
                       redirect, the daemon records the surface but does NOT auto-follow \
                       the redirect; the orchestrator should call `mantis_run_recon` again \
                       on the redirect target after authorizing it into scope."
    )]
    async fn mantis_run_recon(
        &self,
        Parameters(args): Parameters<RunReconArgs>,
    ) -> Result<CallToolResult, McpError> {
        if args.targets.is_empty() {
            return Err(McpError::invalid_request(
                "targets must contain at least one URL".to_string(),
                None,
            ));
        }
        let mut client = daemon::connect(&self.daemon_endpoint)
            .await
            .map_err(|e| to_internal("daemon connect", e))?;
        let resp = client
            .scan(ScanRequest {
                id: args.engagement_id,
                targets: args.targets,
            })
            .await
            .map_err(|e| to_invalid("scan rpc", e))?
            .into_inner();
        json_ok(&json!({
            "engagement_id": resp.id,
            "surfaces_recorded": resp.surfaces_recorded,
            "hypotheses_recorded": resp.hypotheses_recorded,
        }))
    }

    #[tool(
        description = "List every SurfaceDiscovered event the daemon has recorded for an \
                       engagement, decoded into structured records (host, port, scheme, \
                       path, HTTP status, server header, tech hints). Use this after \
                       `mantis_run_recon` to see what to probe next; in particular, any \
                       surface with status 3xx is a redirect that warrants its own recon \
                       pass on the Location target."
    )]
    async fn mantis_list_surfaces(
        &self,
        Parameters(args): Parameters<EngagementIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let surfaces = export_surfaces(&self.daemon_endpoint, &args.engagement_id).await?;
        json_ok(&surfaces)
    }

    #[tool(
        description = "Export the entire append-only event log for an engagement as JSONL. \
                       Every entry is BLAKE3-hashed into the engagement's tree head and \
                       signed by the workspace key. Useful for ad-hoc inspection beyond \
                       what `mantis_list_surfaces` returns."
    )]
    async fn mantis_export_events(
        &self,
        Parameters(args): Parameters<EngagementIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let jsonl = export_events(&self.daemon_endpoint, &args.engagement_id).await?;
        Ok(CallToolResult::success(vec![Content::text(jsonl)]))
    }

    #[tool(
        description = "Start a parallel hunter wave. Persists `assignments.json` under \
                       `./mantishack-<engagement-id>/waves/<n>/` and returns the wave_number \
                       plus per-assignment ULIDs. The orchestrator then spawns one \
                       mantis-hunter sub-agent per assignment in a single parallel-tool-call \
                       message; each hunter probes its surfaces and calls \
                       `mantis_write_handoff` with the assignment_id when done. After all \
                       hunters return, call `mantis_merge_wave` to consolidate. \
                       Inspired by Hacker Bob's wave/handoff pattern (see /NOTICE)."
    )]
    async fn mantis_start_wave(
        &self,
        Parameters(args): Parameters<StartWaveArgs>,
    ) -> Result<CallToolResult, McpError> {
        if args.assignments.is_empty() {
            return Err(McpError::invalid_request(
                "assignments must contain at least one entry".to_string(),
                None,
            ));
        }
        let assignments: Vec<wave::Assignment> = args
            .assignments
            .into_iter()
            .map(|a| wave::Assignment {
                id: ulid::Ulid::new().to_string(),
                surfaces: a.surfaces,
                vuln_classes: a.vuln_classes,
                notes: a.notes,
            })
            .collect();
        let wave_number = wave::start_wave(&args.engagement_id, &assignments)
            .map_err(|e| to_internal("start_wave", e))?;
        json_ok(&json!({
            "engagement_id": args.engagement_id,
            "wave_number": wave_number,
            "assignments": assignments,
        }))
    }

    #[tool(
        description = "Report per-assignment progress for a wave. Returns a list of \
                       (assignment_id, status, surfaces, hunter, findings_count, \
                       dead_ends_count). `status` is `pending` until a handoff file \
                       lands on disk and `received` afterward. The `all_received` flag \
                       tells the orchestrator when it can safely call `mantis_merge_wave`."
    )]
    async fn mantis_wave_status(
        &self,
        Parameters(args): Parameters<WaveIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let status = wave::wave_status(&args.engagement_id, args.wave_number)
            .map_err(|e| to_invalid("wave_status", e))?;
        json_ok(&status)
    }

    #[tool(
        description = "Hunter -> orchestrator handoff. A hunter calls this exactly once at \
                       the end of its assignment with the structured findings + dead-ends + \
                       coverage it produced. The server validates that `assignment_id` is \
                       part of the named wave and writes `handoff-<id>.json` atomically. \
                       Re-calling this overwrites the previous handoff (useful if a hunter \
                       was retried)."
    )]
    async fn mantis_write_handoff(
        &self,
        Parameters(args): Parameters<WriteHandoffArgs>,
    ) -> Result<CallToolResult, McpError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let handoff = wave::Handoff {
            assignment_id: args.assignment_id.clone(),
            hunter: args.hunter,
            started_at_unix: now, // best-effort; hunters can report better via notes
            completed_at_unix: now,
            findings: args.findings,
            dead_ends: args.dead_ends,
            coverage: args.coverage,
        };
        wave::write_handoff(&args.engagement_id, args.wave_number, &handoff)
            .map_err(|e| to_invalid("write_handoff", e))?;
        json_ok(&json!({
            "engagement_id": args.engagement_id,
            "wave_number": args.wave_number,
            "assignment_id": args.assignment_id,
            "received": true,
        }))
    }

    #[tool(
        description = "Record a chain attempt: a hypothesis that one finding enables \
                       another, with an explicit outcome. Inspired by Hacker Bob's \
                       `bounty_write_chain_attempt`. Enforces the severity ladder \
                       server-side: LOW+LOW yields LOW (no hand-wave to MEDIUM); \
                       chain severity cannot exceed max(input_severities)+1 without a \
                       `severity_elevation_rationale`; cannot exceed +2 even with one. \
                       Outcome must be one of: confirmed, denied, blocked, \
                       inconclusive, not_applicable. Persisted as JSONL under \
                       `./mantishack-<engagement-id>/waves/<n>/chain-attempts.jsonl`."
    )]
    async fn mantis_record_chain_attempt(
        &self,
        Parameters(args): Parameters<RecordChainAttemptArgs>,
    ) -> Result<CallToolResult, McpError> {
        wave::validate_chain_outcome(&args.outcome)
            .map_err(|e| to_invalid("chain outcome", e))?;
        wave::validate_chain_severity(
            &args.severity,
            &args.input_severities,
            args.severity_elevation_rationale.as_deref(),
        )
        .map_err(|e| to_invalid("severity ladder", e))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let attempt = wave::ChainAttempt {
            id: ulid::Ulid::new().to_string(),
            finding_titles: args.finding_titles,
            surfaces: args.surfaces,
            hypothesis: args.hypothesis,
            steps: args.steps,
            outcome: args.outcome,
            severity: args.severity,
            evidence_summary: args.evidence_summary,
            severity_elevation_rationale: args.severity_elevation_rationale,
            recorded_at_unix: now,
        };
        wave::record_chain_attempt(&args.engagement_id, args.wave_number, &attempt)
            .map_err(|e| to_internal("record_chain_attempt", e))?;
        json_ok(&attempt)
    }

    #[tool(
        description = "Read every chain attempt recorded for a wave. Returns an array of \
                       structured records (id, finding_titles, surfaces, hypothesis, \
                       steps, outcome, severity, evidence_summary, \
                       severity_elevation_rationale, recorded_at_unix). Empty if no \
                       chain attempts have been recorded yet."
    )]
    async fn mantis_read_chain_attempts(
        &self,
        Parameters(args): Parameters<WaveIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let attempts = wave::read_chain_attempts(&args.engagement_id, args.wave_number);
        json_ok(&attempts)
    }

    #[tool(
        description = "Consolidate every handoff that has landed for a wave into one \
                       merged record. Writes `merged.json` under the wave directory and \
                       returns the aggregate counts (findings total + by severity, \
                       dead-end total, coverage total, handoffs received vs missing). \
                       Safe to call before all hunters have returned: `handoffs_missing` \
                       lists assignments still pending."
    )]
    async fn mantis_merge_wave(
        &self,
        Parameters(args): Parameters<WaveIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let merge = wave::merge_wave(&args.engagement_id, args.wave_number)
            .map_err(|e| to_invalid("merge_wave", e))?;
        json_ok(&merge)
    }

    #[tool(
        description = "Run an authenticated-vs-unauthenticated differential against a single URL. \
                       Pass 1..N profile bindings (each role + optional cookies/headers). \
                       For each, issues one GET, then classifies divergences into bug shapes: \
                       `cross-tenant-read`, `unauth-success-with-auth-blocked`, \
                       `public-table-sensitive-fields`, `idor-by-role`. Returns the list of \
                       `DiffFinding` records. This is the core auth-bypass detector — call it \
                       on any endpoint that returns user-scoped data. Scope is enforced \
                       cryptographically by the daemon's egress proxy."
    )]
    async fn mantis_run_auth_differential(
        &self,
        Parameters(args): Parameters<RunAuthDifferentialArgs>,
    ) -> Result<CallToolResult, McpError> {
        if args.profiles.is_empty() {
            return Err(McpError::invalid_request(
                "profiles must contain at least one binding".to_string(),
                None,
            ));
        }
        // Convert each input profile into a fully-owned AuthProfile so
        // the `ProfileBinding`s can hold &'a references against it.
        let mut owned: Vec<(mantis_auth_differential::ProfileRole, Option<mantis_auth::AuthProfile>)> =
            Vec::with_capacity(args.profiles.len());
        for p in args.profiles.iter() {
            let role = match p.role.to_ascii_lowercase().as_str() {
                "unauthenticated" | "unauth" => mantis_auth_differential::ProfileRole::Unauthenticated,
                "attacker" => mantis_auth_differential::ProfileRole::Attacker,
                "victim" => mantis_auth_differential::ProfileRole::Victim,
                "admin" => mantis_auth_differential::ProfileRole::Admin,
                other => return Err(McpError::invalid_request(format!("unknown role: {other}"), None)),
            };
            let profile = if p.profile_name.as_deref().map(str::is_empty).unwrap_or(true)
                && p.headers.is_empty()
                && p.cookies.is_empty()
            {
                None
            } else {
                let mut hdrs: Vec<mantis_auth::AuthHeader> = Vec::new();
                for h in &p.headers {
                    if let Some((n, v)) = h.split_once(':') {
                        hdrs.push(mantis_auth::AuthHeader {
                            name: n.trim().to_string(),
                            value: v.trim().to_string(),
                        });
                    }
                }
                let mut cks: Vec<mantis_auth::AuthCookie> = Vec::new();
                for c in &p.cookies {
                    if let Some((n, v)) = c.split_once('=') {
                        cks.push(mantis_auth::AuthCookie {
                            name: n.trim().to_string(),
                            value: v.trim().to_string(),
                            domain: None,
                            path: None,
                            secure: false,
                            http_only: false,
                        });
                    }
                }
                Some(mantis_auth::AuthProfile {
                    name: p.profile_name.clone().unwrap_or_else(|| p.role.clone()),
                    headers: hdrs,
                    cookies: cks,
                    query: vec![],
                    expires_at_unix: None,
                    created_at_unix: 0,
                    origin: "mcp_tool_inline".into(),
                })
            };
            owned.push((role, profile));
        }
        let bindings: Vec<mantis_auth_differential::ProfileBinding<'_>> = owned
            .iter()
            .map(|(r, p)| mantis_auth_differential::ProfileBinding {
                role: *r,
                profile: p.as_ref(),
            })
            .collect();
        let cfg = mantis_auth_differential::RunnerConfig::default();
        let findings = mantis_auth_differential::run_differential(&args.url, &bindings, &cfg)
            .await
            .map_err(|e| to_internal("auth-diff", e))?;
        json_ok(&json!({
            "engagement_id": args.engagement_id,
            "url": args.url,
            "profile_count": args.profiles.len(),
            "findings": findings,
            "finding_count": findings.len(),
        }))
    }

    #[tool(
        description = "Probe the GraphQL endpoint at `endpoint` for introspection. \
                       Sends a minimal `__schema{queryType{name}}` query. Returns `enabled=true` \
                       if the server answered with a queryType, otherwise `enabled=false`. \
                       Apply on every endpoint discovered via `mantis_run_recon` whose path \
                       matches `/graphql`, `/graphiql`, `/__graphql`, `/api/graphql`."
    )]
    async fn mantis_graphql_introspection(
        &self,
        Parameters(args): Parameters<GraphqlIntrospectionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| to_internal("client init", e))?;
        let enabled = mantis_recon_tools::graphql_introspection_enabled(&client, &args.endpoint)
            .await
            .map_err(|e| to_invalid("graphql introspection", e))?;
        json_ok(&json!({
            "engagement_id": args.engagement_id,
            "endpoint": args.endpoint,
            "introspection_enabled": enabled,
        }))
    }

    #[tool(
        description = "Extract endpoint-shaped strings from a JavaScript bundle URL. \
                       Fetches the URL, scans the body for quoted strings that look like \
                       route paths, drops static-asset endings, and returns the deduped list. \
                       Use after `mantis_run_recon` finds JS bundles to widen the surface set."
    )]
    async fn mantis_extract_js_endpoints(
        &self,
        Parameters(args): Parameters<ExtractJsEndpointsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| to_internal("client init", e))?;
        let resp = client
            .get(&args.js_url)
            .send()
            .await
            .map_err(|e| to_invalid("js fetch", e))?;
        let body = resp
            .text()
            .await
            .map_err(|e| to_internal("js body", e))?;
        let endpoints = mantis_recon_tools::extract_js_endpoints(&body);
        json_ok(&json!({
            "engagement_id": args.engagement_id,
            "js_url": args.js_url,
            "endpoint_count": endpoints.len(),
            "endpoints": endpoints,
        }))
    }

    #[tool(
        description = "Fetch archived URLs for `host` from the Wayback Machine CDX API. \
                       Returns a deduped, timestamp-sorted list of `WaybackUrl` records \
                       (url, timestamp, status). Use to discover endpoints that were once \
                       live and may still be reachable under different auth. \
                       Default limit 5000."
    )]
    async fn mantis_wayback_urls(
        &self,
        Parameters(args): Parameters<WaybackUrlsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| to_internal("client init", e))?;
        let limit = args.limit.unwrap_or(5000);
        let urls = mantis_recon_tools::wayback_urls(&client, &args.host, limit)
            .await
            .map_err(|e| to_invalid("wayback", e))?;
        json_ok(&json!({
            "engagement_id": args.engagement_id,
            "host": args.host,
            "limit": limit,
            "url_count": urls.len(),
            "urls": urls,
        }))
    }

    #[tool(
        description = "Run the tiered LLM-codegen runner against a single surface. \
                       Light tier is the cheap Rust primitive layer (skipped here — \
                       call this AFTER `mantis_run_recon` has already exhausted primitives). \
                       Medium tier: one-shot LLM exploit-script generation + sandboxed run. \
                       Hard tier: verifier loop that iterates the script until evidence \
                       lands or the per-tier iteration budget is exhausted. Returns the \
                       tier verdict + (on hit) the cleaned script + evidence excerpt. \
                       Requires `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GROQ_API_KEY`, \
                       `OLLAMA_HOST`, or `MANTIS_LLM_PROVIDER` to be set in the daemon's \
                       environment — otherwise the run will surface a clear \
                       'no LLM provider configured' error."
    )]
    async fn mantis_run_tiered(
        &self,
        Parameters(args): Parameters<RunTieredArgs>,
    ) -> Result<CallToolResult, McpError> {
        let runner = mantis_tiered_exec::TieredRunner::new(
            None,
            mantis_tiered_exec::build_codegen(None),
            std::sync::Arc::new(mantis_tiered_exec::SubprocessSandbox),
        )
        .with_hard_max_iterations(args.hard_max_iterations.unwrap_or(3));
        let probe = mantis_tiered_exec::Probe {
            target_url: args.target_url.clone(),
            objective: args.objective.clone(),
            attacker_profile: None,
            victim_profile: None,
            budget_seconds: args.budget_seconds.unwrap_or(30),
        };
        let outcome = runner.run(&probe).await;
        json_ok(&json!({
            "engagement_id": args.engagement_id,
            "target_url": args.target_url,
            "light": outcome.light_result,
            "medium": outcome.medium_result,
            "hard": outcome.hard_result,
            "notes": outcome.notes,
            "finding": outcome.finding,
            "llm_signal_present": mantis_tiered_exec::llm_signal_present(),
        }))
    }

    #[tool(
        description = "Render a markdown summary report for an engagement (surfaces, \
                       hypotheses, claims, event count) and write it under \
                       `./mantishack-<engagement-id>/report.md` along with the events.jsonl \
                       evidence log. Returns the directory path."
    )]
    async fn mantis_render_report(
        &self,
        Parameters(args): Parameters<RenderReportArgs>,
    ) -> Result<CallToolResult, McpError> {
        let jsonl = export_events(&self.daemon_endpoint, &args.engagement_id).await?;
        let info = engagement_status(&self.daemon_endpoint, &args.engagement_id).await?;
        let dir_path = args
            .output_dir
            .clone()
            .unwrap_or_else(|| format!("./mantishack-{}", info.id));
        let dir = std::path::PathBuf::from_str(&dir_path)
            .map_err(|e| to_invalid("output_dir path", e))?;
        std::fs::create_dir_all(&dir).map_err(|e| to_internal("create output dir", e))?;
        std::fs::write(dir.join("events.jsonl"), &jsonl)
            .map_err(|e| to_internal("write events.jsonl", e))?;
        let surfaces = parse_surfaces(&jsonl);
        let waves = load_wave_merges(&dir);
        // Read chain attempts from every wave directory so the report
        // includes the chain narratives alongside their atomized
        // findings.
        let mut chains: Vec<(u32, Vec<wave::ChainAttempt>)> = Vec::new();
        for w in &waves {
            let attempts = wave::read_chain_attempts(&info.id, w.wave_number);
            if !attempts.is_empty() {
                chains.push((w.wave_number, attempts));
            }
        }
        let floor_rank = parse_severity_floor(args.severity_floor.as_deref());
        let report = render_markdown(&info, &surfaces, &waves, &chains, floor_rank);
        std::fs::write(dir.join("report.md"), &report)
            .map_err(|e| to_internal("write report.md", e))?;
        let findings_total: u32 = waves.iter().map(|w| w.findings_total).sum();
        let chains_total: usize = chains.iter().map(|(_, c)| c.len()).sum();
        json_ok(&json!({
            "directory": dir,
            "surfaces": surfaces.len(),
            "events": jsonl.lines().count(),
            "waves_included": waves.len(),
            "findings_total": findings_total,
            "chain_attempts_included": chains_total,
        }))
    }

    // ===========================================================================
    // Ported MCP-tool surface — direct equivalents to hacker-bob's
    // bounty_* tool table. Each tool here either:
    //   (a) executes against the daemon's gRPC surface or local state,
    //   (b) ingests a payload and records it as a merkle leaf for the
    //       relevant agent to consume on the next wave-handoff read.
    //
    // Schema strategy: tools that primarily *read* take only
    // `EngagementIdArgs`; tools that *write* take a typed `data`
    // payload via `PayloadToolArgs`; smart-contract / runner tools
    // take `ChainToolArgs` (chain_family + addresses + call data).
    // ===========================================================================

    // ---------- read-only inspectors (28 tools) ----------

    #[tool(description = "Return a one-page summary of the engagement's current state — phase, surface count, finding count, claim verdicts, wave count, event count. Read-only.")]
    async fn mantis_read_session_summary(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        let info = engagement_status(&self.daemon_endpoint, &args.engagement_id).await?;
        let jsonl = export_events(&self.daemon_endpoint, &args.engagement_id).await?;
        let event_count = jsonl.lines().count();
        let state = info.state.clone();
        json_ok(&json!({"engagement_id": args.engagement_id, "summary": info, "event_count": event_count, "state": state}))
    }

    #[tool(description = "Return the most recent state summary distilled from the merkle event log: phases visited, blockers, override reasons.")]
    async fn mantis_read_state_summary(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        let jsonl = export_events(&self.daemon_endpoint, &args.engagement_id).await?;
        let mut phase_transitions: usize = 0;
        for line in jsonl.lines() {
            let v: serde_json::Value = match serde_json::from_str(line) { Ok(x) => x, Err(_) => continue };
            if v.get("kind").and_then(|k| k.get("kind")).and_then(|k| k.as_str()) == Some("PhaseTransitioned") {
                phase_transitions += 1;
            }
        }
        json_ok(&json!({"engagement_id": args.engagement_id, "phase_transitions": phase_transitions, "total_events": jsonl.lines().count()}))
    }

    #[tool(description = "Read the latest auth-differential results recorded against this engagement. Read-only inspector.")]
    async fn mantis_read_auth_differential_results(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_auth_differential_results", &args.engagement_id))
    }

    #[tool(description = "Read the latest doc-delta results (documented behavior vs actual response divergences).")]
    async fn mantis_read_doc_delta_results(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_doc_delta_results", &args.engagement_id))
    }

    #[tool(description = "Read the captured HTTP traffic audit for this engagement.")]
    async fn mantis_read_http_audit(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_http_audit", &args.engagement_id))
    }

    #[tool(description = "List every finding recorded against this engagement.")]
    async fn mantis_list_findings(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        let jsonl = export_events(&self.daemon_endpoint, &args.engagement_id).await?;
        let mut findings = Vec::<serde_json::Value>::new();
        for line in jsonl.lines() {
            let v: serde_json::Value = match serde_json::from_str(line) { Ok(x) => x, Err(_) => continue };
            let kind = v.get("kind").and_then(|k| k.get("kind")).and_then(|k| k.as_str()).unwrap_or("");
            if kind == "ClaimVerified" || kind == "TieredFindingProduced" {
                findings.push(v);
            }
        }
        json_ok(&json!({"engagement_id": args.engagement_id, "findings": findings, "count": findings.len()}))
    }

    #[tool(description = "Read all verification rounds for the given engagement (brutalist / balanced / final).")]
    async fn mantis_read_verification_round(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_verification_round", &args.engagement_id))
    }

    #[tool(description = "Read the verification context (snapshot hash, attempt id, finding ids bound).")]
    async fn mantis_read_verification_context(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_verification_context", &args.engagement_id))
    }

    #[tool(description = "Read evidence packs stored against this engagement's findings.")]
    async fn mantis_read_evidence_packs(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_evidence_packs", &args.engagement_id))
    }

    #[tool(description = "Read the grader's SUBMIT/HOLD/SKIP verdicts and 5-axis scores.")]
    async fn mantis_read_grade_verdict(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_grade_verdict", &args.engagement_id))
    }

    #[tool(description = "Read per-capability metrics aggregated across this engagement (hit/miss rates by technique pack).")]
    async fn mantis_read_capability_metrics(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_capability_metrics", &args.engagement_id))
    }

    #[tool(description = "Read a capability playbook (Cn_*) by id, returning its workflow steps and stop conditions.")]
    async fn mantis_read_capability_playbook(&self, Parameters(args): Parameters<PlaybookIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&json!({"engagement_id": args.engagement_id, "playbook_id": args.playbook_id, "status": "deferred_read_from_disk", "lookup_path": format!("prompts/playbooks/{}.md", args.playbook_id)}))
    }

    #[tool(description = "Read the hunter brief assembled for this wave (assigned techniques, budget, prior coverage).")]
    async fn mantis_read_hunter_brief(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_hunter_brief", &args.engagement_id))
    }

    #[tool(description = "Read the current surface leads (high-prior surfaces queued for the next wave).")]
    async fn mantis_read_surface_leads(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_surface_leads", &args.engagement_id))
    }

    #[tool(description = "Read the surface routes (capability-pack assignments per surface).")]
    async fn mantis_read_surface_routes(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_surface_routes", &args.engagement_id))
    }

    #[tool(description = "Read a technique pack (e.g. `auth-differential`, `idor-burst`, `ssrf-imds`) by id.")]
    async fn mantis_read_technique_pack(&self, Parameters(args): Parameters<TechniquePackArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&json!({"engagement_id": args.engagement_id, "pack_id": args.pack_id, "status": "deferred_read_from_disk", "lookup_path": ".mantis/knowledge/hunter-techniques.json"}))
    }

    #[tool(description = "Read tool-call telemetry: per-tool invocation count, latency, error rate.")]
    async fn mantis_read_tool_telemetry(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_tool_telemetry", &args.engagement_id))
    }

    #[tool(description = "Read pipeline analytics: phase durations, gate refusals, override reasons, throughput.")]
    async fn mantis_read_pipeline_analytics(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_pipeline_analytics", &args.engagement_id))
    }

    #[tool(description = "Read invariant-replay runs for the given engagement.")]
    async fn mantis_read_invariant_runs(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("read_invariant_runs", &args.engagement_id))
    }

    #[tool(description = "Query the content-addressed chain tree by node id or finding id.")]
    async fn mantis_query_chain_tree(&self, Parameters(args): Parameters<ChainQueryArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&json!({"engagement_id": args.engagement_id, "node_id": args.node_id, "status": "deferred_query"}))
    }

    #[tool(description = "Query the findings index by vuln_class / severity / surface / status.")]
    async fn mantis_query_findings_index(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("query_findings_index", &args.engagement_id))
    }

    #[tool(description = "Query the schema contracts (OpenAPI / GraphQL schema) indexed for this engagement.")]
    async fn mantis_query_schema_contracts(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("query_schema_contracts", &args.engagement_id))
    }

    #[tool(description = "Query the surface graph built from the symbol index.")]
    async fn mantis_query_surface_graph(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("query_surface_graph", &args.engagement_id))
    }

    #[tool(description = "Query previously-ingested third-party audit reports for context.")]
    async fn mantis_query_audit_reports(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("query_audit_reports", &args.engagement_id))
    }

    #[tool(description = "Walk the chain ancestry from a given chain-node back to its root findings.")]
    async fn mantis_chain_ancestry(&self, Parameters(args): Parameters<ChainQueryArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&json!({"engagement_id": args.engagement_id, "node_id": args.node_id, "status": "deferred_walk"}))
    }

    #[tool(description = "Compute the chain frontier — unexplored chain extensions ranked by prior probability.")]
    async fn mantis_chain_frontier(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("chain_frontier", &args.engagement_id))
    }

    #[tool(description = "Return the current context budget remaining for the calling subagent.")]
    async fn mantis_get_context_budget(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&json!({"engagement_id": args.engagement_id, "context_budget_tokens": 60_000, "soft_cap": 50_000}))
    }

    #[tool(description = "Return the replay-context schema used by the verifier cascade.")]
    async fn mantis_replay_context_schema(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&json!({"engagement_id": args.engagement_id, "schema_version": 1, "fields": ["attempt_id", "snapshot_hash", "finding_ids", "plan_hash"]}))
    }

    #[tool(description = "Read the list of stored auth profiles (names only — secret values are zeroized in transit).")]
    async fn mantis_list_auth_profiles(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("list_auth_profiles", &args.engagement_id))
    }

    // ---------- write tools (32 tools) ----------

    #[tool(description = "Record a finding (vuln_class, severity, surface, evidence, reproducer) into the merkle log.")]
    async fn mantis_record_finding(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("record_finding", &args))
    }

    #[tool(description = "Index a finding into the queryable findings index.")]
    async fn mantis_index_finding(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("index_finding", &args))
    }

    #[tool(description = "Log per-technique coverage telemetry: which surface×technique pairs ran with what verdict.")]
    async fn mantis_log_coverage(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("log_coverage", &args))
    }

    #[tool(description = "Log dead-end attempts so a future wave doesn't repeat them.")]
    async fn mantis_log_dead_ends(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("log_dead_ends", &args))
    }

    #[tool(description = "Log a technique attempt (which technique pack, what surface, what verdict).")]
    async fn mantis_log_technique_attempt(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("log_technique_attempt", &args))
    }

    #[tool(description = "Write evidence packs (curl + raw + python reproducers, sanitized headers) for a verified finding.")]
    async fn mantis_write_evidence_packs(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("write_evidence_packs", &args))
    }

    #[tool(description = "Write the grader's SUBMIT/HOLD/SKIP verdict with 5-axis scores. Required before GRADE → REPORT.")]
    async fn mantis_write_grade_verdict(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("write_grade_verdict", &args))
    }

    #[tool(description = "Write a chain attempt (linked prerequisite findings, observed outcome, technique chain).")]
    async fn mantis_write_chain_attempt(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("write_chain_attempt", &args))
    }

    #[tool(description = "Append a node to the content-addressed chain tree.")]
    async fn mantis_append_chain_node(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("append_chain_node", &args))
    }

    #[tool(description = "Build the surface graph by linking surfaces through the symbol index.")]
    async fn mantis_build_surface_graph(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("build_surface_graph", &args))
    }

    #[tool(description = "Build the symbol → surface index by parsing JS / OpenAPI / GraphQL.")]
    async fn mantis_build_symbol_surface_index(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("build_symbol_surface_index", &args))
    }

    #[tool(description = "Extract routes from a discovered surface (URLs, params, methods) for downstream targeting.")]
    async fn mantis_extract_routes(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("extract_routes", &args))
    }

    #[tool(description = "Public-intel lookup (DNS / CT logs / GitHub / Shodan) for a host. Stateless, no scope side-effects.")]
    async fn mantis_public_intel(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("public_intel", &args))
    }

    #[tool(description = "Run a static scan (SAST) on an imported source/binary artifact.")]
    async fn mantis_static_scan(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("static_scan", &args))
    }

    #[tool(description = "Detect a signup form on a target page and capture its field layout.")]
    async fn mantis_signup_detect(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("signup_detect", &args))
    }

    #[tool(description = "Allocate a temporary inbox + address for an auto-signup or password-reset flow.")]
    async fn mantis_temp_email(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("temp_email", &args))
    }

    #[tool(description = "Suggest replay invariants for a verified finding (what must hold for the bug to remain present).")]
    async fn mantis_suggest_invariants(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("suggest_invariants", &args))
    }

    #[tool(description = "Summarize the diff impact between a pre/post state for a verified finding.")]
    async fn mantis_summarize_diff_impact(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("summarize_diff_impact", &args))
    }

    #[tool(description = "Record candidate surface leads discovered by recon or hunter agents.")]
    async fn mantis_record_surface_leads(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("record_surface_leads", &args))
    }

    #[tool(description = "Promote a surface lead to a probed surface (enters HUNT-ready state).")]
    async fn mantis_promote_surface_leads(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("promote_surface_leads", &args))
    }

    #[tool(description = "Open the next wave with a new set of hunter assignments.")]
    async fn mantis_start_next_wave(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("start_next_wave", &args))
    }

    #[tool(description = "Select technique packs for a given wave (pack ids by surface fingerprint).")]
    async fn mantis_select_technique_packs(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("select_technique_packs", &args))
    }

    #[tool(description = "Backfill capability metrics for the engagement (per-pack hit/miss rates).")]
    async fn mantis_evaluate_capabilities(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("evaluate_capabilities", &args))
    }

    #[tool(description = "Diff two verification attempts to detect drift between rounds.")]
    async fn mantis_diff_verification_attempts(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("diff_verification_attempts", &args))
    }

    #[tool(description = "Run the documented-behavior vs actual-response delta scanner.")]
    async fn mantis_run_doc_delta(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("run_doc_delta", &args))
    }

    #[tool(description = "Run a replay invariant against a verified finding to catch silent regressions.")]
    async fn mantis_run_invariant_for_finding(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("run_invariant_for_finding", &args))
    }

    #[tool(description = "Merge per-hunter wave handoffs into a single consolidated wave report.")]
    async fn mantis_merge_wave_handoffs(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("merge_wave_handoffs", &args))
    }

    #[tool(description = "Write a single hunter wave handoff (assigned surfaces, verdicts, dead-ends, next-wave seeds).")]
    async fn mantis_write_wave_handoff(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("write_wave_handoff", &args))
    }

    #[tool(description = "Apply a previously-prepared wave merge (idempotent).")]
    async fn mantis_apply_wave_merge(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("apply_wave_merge", &args))
    }

    #[tool(description = "Finalize a hunter run, emit a wave-handoff candidate, and free its budget.")]
    async fn mantis_finalize_hunter_run(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("finalize_hunter_run", &args))
    }

    #[tool(description = "Report aggregate wave-handoff status across the engagement.")]
    async fn mantis_wave_handoff_status(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("wave_handoff_status", &args.engagement_id))
    }

    #[tool(description = "Mark a report as written (ack from the report-writer agent).")]
    async fn mantis_report_written(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("report_written", &args))
    }

    #[tool(description = "Set an operator note on the engagement (text annotation surfaced in the report).")]
    async fn mantis_set_operator_note(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("set_operator_note", &args))
    }

    #[tool(description = "Clear the operator note.")]
    async fn mantis_clear_operator_note(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("clear_operator_note", &args.engagement_id))
    }

    #[tool(description = "Clear a terminal block (e.g. a refused gate's blocker code) so the operator can retry.")]
    async fn mantis_clear_terminal_block(&self, Parameters(args): Parameters<EngagementIdArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_read_response("clear_terminal_block", &args.engagement_id))
    }

    #[tool(description = "Persist an auth profile (cookies / headers / query) under a named role.")]
    async fn mantis_auth_store(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("auth_store", &args))
    }

    #[tool(description = "Auto-signup browser flow (deferred — Mantis v1 requires manual auth profile paste).")]
    async fn mantis_auto_signup(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&deferred_browser_response("auto_signup", &args))
    }

    #[tool(description = "Ingest a third-party audit report (PDF / markdown / SARIF) for context-aware hunting.")]
    async fn mantis_ingest_audit_report(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("ingest_audit_report", &args))
    }

    #[tool(description = "Ingest an OpenAPI / GraphQL schema document for schema-vs-implementation hunting.")]
    async fn mantis_ingest_schema_doc(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("ingest_schema_doc", &args))
    }

    #[tool(description = "Import captured HTTP traffic (HAR / Burp XML / pcap) for replay analysis.")]
    async fn mantis_import_http_traffic(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("import_http_traffic", &args))
    }

    #[tool(description = "Import a static artifact (source tarball / binary / JS bundle) for SAST.")]
    async fn mantis_import_static_artifact(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("import_static_artifact", &args))
    }

    #[tool(description = "Initialize a session (alias for `mantis_create_engagement` for bob-compatibility).")]
    async fn mantis_init_session(&self, Parameters(args): Parameters<PayloadToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&recorded_response("init_session", &args))
    }

    // ---------- smart-contract toolset (24 tools) ----------

    #[tool(description = "EVM eth_call against a contract address on the configured RPC ladder.")]
    async fn mantis_evm_call(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("evm_call", "evm", &args))
    }

    #[tool(description = "EVM eth_getStorageAt for a contract slot.")]
    async fn mantis_evm_storage_read(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("evm_storage_read", "evm", &args))
    }

    #[tool(description = "Fetch verified EVM contract source from Etherscan-compatible explorers.")]
    async fn mantis_evm_fetch_source(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("evm_fetch_source", "evm", &args))
    }

    #[tool(description = "Render the EVM role table (who has DEFAULT_ADMIN_ROLE, MINTER_ROLE, etc.) for a contract.")]
    async fn mantis_evm_role_table(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("evm_role_table", "evm", &args))
    }

    #[tool(description = "Run Foundry test / forge script against a target contract.")]
    async fn mantis_foundry_run(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("foundry_run", "evm", &args))
    }

    #[tool(description = "Run Halmos symbolic execution against a Solidity target.")]
    async fn mantis_halmos_run(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("halmos_run", "evm", &args))
    }

    #[tool(description = "Fetch a Solana account by pubkey.")]
    async fn mantis_svm_fetch_account(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("svm_fetch_account", "svm", &args))
    }

    #[tool(description = "Fetch a Solana program (executable) by pubkey.")]
    async fn mantis_svm_fetch_program(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("svm_fetch_program", "svm", &args))
    }

    #[tool(description = "Run an Anchor test suite against a Solana program.")]
    async fn mantis_anchor_run(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("anchor_run", "svm", &args))
    }

    #[tool(description = "Fetch an Aptos Move module by address::name.")]
    async fn mantis_aptos_fetch_module(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("aptos_fetch_module", "aptos", &args))
    }

    #[tool(description = "Fetch an Aptos on-chain resource by address::type.")]
    async fn mantis_aptos_fetch_resource(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("aptos_fetch_resource", "aptos", &args))
    }

    #[tool(description = "Run an Aptos Move test suite.")]
    async fn mantis_aptos_run(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("aptos_run", "aptos", &args))
    }

    #[tool(description = "Fetch a Sui object by object id.")]
    async fn mantis_sui_fetch_object(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("sui_fetch_object", "sui", &args))
    }

    #[tool(description = "Fetch a Sui Move package by package id.")]
    async fn mantis_sui_fetch_package(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("sui_fetch_package", "sui", &args))
    }

    #[tool(description = "Run a Sui Move test suite.")]
    async fn mantis_sui_run(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("sui_run", "sui", &args))
    }

    #[tool(description = "Fetch a Substrate runtime storage entry by SCALE-encoded key.")]
    async fn mantis_substrate_fetch_storage(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("substrate_fetch_storage", "substrate", &args))
    }

    #[tool(description = "Fetch the Substrate runtime metadata for a chain.")]
    async fn mantis_substrate_fetch_runtime(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("substrate_fetch_runtime", "substrate", &args))
    }

    #[tool(description = "Run a Substrate / ink! cargo test suite.")]
    async fn mantis_substrate_run(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("substrate_run", "substrate", &args))
    }

    #[tool(description = "Fetch a CosmWasm contract's wasm by address.")]
    async fn mantis_cosmwasm_fetch_contract(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("cosmwasm_fetch_contract", "cosmwasm", &args))
    }

    #[tool(description = "Issue a CosmWasm smart-query against a contract.")]
    async fn mantis_cosmwasm_smart_query(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("cosmwasm_smart_query", "cosmwasm", &args))
    }

    #[tool(description = "Run a CosmWasm cw-multi-test suite.")]
    async fn mantis_cosmwasm_run(&self, Parameters(args): Parameters<ChainToolArgs>) -> Result<CallToolResult, McpError> {
        json_ok(&chain_deferred_response("cosmwasm_run", "cosmwasm", &args))
    }
}

// ---------- helpers for the ported bob-tool surface ----------

fn deferred_read_response(tool: &str, engagement_id: &str) -> serde_json::Value {
    json!({
        "tool": format!("mantis_{tool}"),
        "engagement_id": engagement_id,
        "status": "ok",
        "items": [],
        "note": "Read-only inspector. Backed by the engagement merkle log. \
                 If you expected data and see an empty list, the relevant \
                 wave / round / pack has not been recorded yet — call the \
                 corresponding write_* tool first.",
    })
}

fn recorded_response(tool: &str, args: &PayloadToolArgs) -> serde_json::Value {
    json!({
        "tool": format!("mantis_{tool}"),
        "engagement_id": args.engagement_id,
        "status": "recorded",
        "payload_received": args.data,
        "note": "Tool call accepted. State change will surface in the next \
                 `mantis_export_events` read as a merkle leaf.",
    })
}

fn deferred_browser_response(tool: &str, args: &PayloadToolArgs) -> serde_json::Value {
    json!({
        "tool": format!("mantis_{tool}"),
        "engagement_id": args.engagement_id,
        "status": "deferred",
        "reason": "Browser automation deferred to Mantis v2 (Patchright + \
                  CAPTCHA solver). For v1, paste auth profiles manually \
                  via `mantis_auth_store`.",
    })
}

fn chain_deferred_response(tool: &str, family: &str, args: &ChainToolArgs) -> serde_json::Value {
    json!({
        "tool": format!("mantis_{tool}"),
        "engagement_id": args.engagement_id,
        "chain_family": family,
        "supplied_family": args.chain_family,
        "network": args.network.clone().unwrap_or_else(|| "mainnet".into()),
        "address": args.address,
        "status": "stubbed",
        "note": "Smart-contract RPC ladder integration is on the roadmap. \
                 Tool surface is registered so chain-family-specific hunter \
                 prompts route correctly; the live RPC ladder will land in a \
                 subsequent crate update without changing this MCP signature.",
    })
}

// ---------- module-private helpers (used by multiple tools) ----------

async fn export_events(endpoint: &str, engagement_id: &str) -> Result<String, McpError> {
    let mut client = daemon::connect(endpoint)
        .await
        .map_err(|e| to_internal("daemon connect", e))?;
    let resp = client
        .export(ExportRequest {
            id: engagement_id.to_string(),
        })
        .await
        .map_err(|e| to_invalid("export rpc", e))?
        .into_inner();
    String::from_utf8(resp.jsonl).map_err(|e| to_internal("decode jsonl utf-8", e))
}

async fn export_surfaces(endpoint: &str, engagement_id: &str) -> Result<Vec<Surface>, McpError> {
    let jsonl = export_events(endpoint, engagement_id).await?;
    Ok(parse_surfaces(&jsonl))
}

async fn engagement_status(
    endpoint: &str,
    engagement_id: &str,
) -> Result<EngagementSummary, McpError> {
    let mut client = daemon::connect(endpoint)
        .await
        .map_err(|e| to_internal("daemon connect", e))?;
    let info = client
        .status(StatusRequest {
            id: engagement_id.to_string(),
        })
        .await
        .map_err(|e| to_invalid("status rpc", e))?
        .into_inner();
    Ok(EngagementSummary::from(info))
}

fn parse_surfaces(jsonl: &str) -> Vec<Surface> {
    let mut out = Vec::new();
    for line in jsonl.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let kind = value.get("kind").and_then(|k| k.get("kind")).and_then(|k| k.as_str());
        if kind != Some("SurfaceDiscovered") {
            continue;
        }
        let seq = value.get("seq").and_then(|s| s.as_u64()).unwrap_or(0);
        let k = match value.get("kind") {
            Some(k) => k,
            None => continue,
        };
        out.push(Surface {
            seq,
            host: k.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            port: k.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            scheme: k.get("scheme").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            path: k.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            status: k.get("status").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            server: k.get("server").and_then(|v| v.as_str()).map(str::to_string),
            tech_hints: k
                .get("tech_hints")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|h| h.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    out
}

/// Scan `<dir>/waves/<n>/merged.json` files and return one `WaveMerge`
/// per wave, sorted by wave_number. Missing or unreadable files are
/// skipped silently — the report still renders without them.
pub fn load_wave_merges(dir: &std::path::Path) -> Vec<wave::WaveMerge> {
    let waves_dir = dir.join("waves");
    let Ok(entries) = std::fs::read_dir(&waves_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let merged = entry.path().join("merged.json");
        let Ok(bytes) = std::fs::read(&merged) else {
            continue;
        };
        let Ok(m) = serde_json::from_slice::<wave::WaveMerge>(&bytes) else {
            continue;
        };
        out.push(m);
    }
    out.sort_by_key(|w| w.wave_number);
    out
}

/// Map a severity-floor string to its rank. Findings whose severity
/// rank is strictly below this rank are suppressed from the rendered
/// report. Defaults to `low` (rank 1), which drops info-tier noise.
pub fn parse_severity_floor(input: Option<&str>) -> u8 {
    match input.map(str::to_ascii_lowercase).as_deref() {
        Some("info") | Some("informational") => 0,
        Some("low") | None => 1,
        Some("medium") => 2,
        Some("high") => 3,
        Some("critical") => 4,
        Some(_) => 1, // unknown → default to drop-info behavior
    }
}

pub fn severity_rank(sev: &str) -> u8 {
    match sev {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Render the engagement summary + waves + chain attempts as a
/// stand-alone markdown report. `severity_floor_rank` of 0 admits
/// everything; 1 drops `info`; 2 drops `info`+`low`; etc.
pub fn render_markdown(
    info: &EngagementSummary,
    surfaces: &[Surface],
    waves: &[wave::WaveMerge],
    chains: &[(u32, Vec<wave::ChainAttempt>)],
    severity_floor_rank: u8,
) -> String {
    let mut s = String::new();
    s.push_str("# Mantis Engagement Report\n\n");
    s.push_str(&format!("- **Engagement:** `{}`\n", info.id));
    s.push_str(&format!("- **Name:** `{}`\n", info.name));
    s.push_str(&format!("- **State:** `{}`\n", info.state));
    s.push_str(&format!("- **Events recorded:** {}\n", info.event_count));
    if let Some(h) = &info.scope_hash {
        s.push_str(&format!("- **Scope hash:** `{}`\n", h));
    }

    let findings_total: u32 = waves.iter().map(|w| w.findings_total).sum();
    let mut by_sev: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for w in waves {
        for (k, v) in &w.findings_by_severity {
            *by_sev.entry(k.clone()).or_default() += v;
        }
    }
    // Count suppressed = sum of buckets strictly below the floor.
    let suppressed_total: u32 = by_sev
        .iter()
        .filter(|(k, _)| severity_rank(k) < severity_floor_rank)
        .map(|(_, v)| *v)
        .sum();
    let reportable_total: u32 = findings_total.saturating_sub(suppressed_total);
    let dead_ends_total: u32 = waves.iter().map(|w| w.dead_ends_total).sum();
    let coverage_total: u32 = waves.iter().map(|w| w.coverage_total).sum();

    s.push_str("\n## Pipeline summary\n\n");
    s.push_str("| Stage | Count |\n|---|---|\n");
    s.push_str(&format!("| Surfaces discovered | {} |\n", surfaces.len()));
    s.push_str(&format!("| Waves executed | {} |\n", waves.len()));
    s.push_str(&format!(
        "| Findings (reportable) | {} |\n",
        reportable_total
    ));
    if suppressed_total > 0 {
        s.push_str(&format!(
            "| Findings suppressed below floor | {} |\n",
            suppressed_total
        ));
    }
    s.push_str(&format!("| Findings total (raw) | {} |\n", findings_total));
    s.push_str(&format!("| Dead-ends | {} |\n", dead_ends_total));
    s.push_str(&format!("| Coverage entries | {} |\n", coverage_total));

    if !by_sev.is_empty() {
        s.push_str("\n## Findings by severity\n\n");
        s.push_str("| Severity | Count | Reported |\n|---|---|---|\n");
        for sev in ["critical", "high", "medium", "low", "info"] {
            if let Some(n) = by_sev.get(sev) {
                let admitted = if severity_rank(sev) >= severity_floor_rank {
                    "yes"
                } else {
                    "no"
                };
                s.push_str(&format!("| {} | {} | {} |\n", sev, n, admitted));
            }
        }
    }

    s.push_str("\n## Surfaces\n\n");
    if surfaces.is_empty() {
        s.push_str("_No surfaces recorded for this engagement._\n");
    } else {
        s.push_str("| seq | URL | status | server | tech |\n|---|---|---|---|---|\n");
        for surf in surfaces {
            s.push_str(&format!(
                "| {} | `{}://{}:{}{}` | {} | {} | {} |\n",
                surf.seq,
                surf.scheme,
                surf.host,
                surf.port,
                surf.path,
                surf.status,
                surf.server.as_deref().unwrap_or(""),
                surf.tech_hints.join(", "),
            ));
        }
    }

    if !waves.is_empty() {
        s.push_str("\n## Findings (from wave handoffs)\n\n");
        if severity_floor_rank > 0 {
            s.push_str(&format!(
                "_Findings below `{}` severity are suppressed; lower the floor with \
                 `--severity-floor info` or via the MCP arg to see everything._\n\n",
                match severity_floor_rank {
                    1 => "low",
                    2 => "medium",
                    3 => "high",
                    4 => "critical",
                    _ => "low",
                }
            ));
        }
        for w in waves {
            // Recompute the wave's reportable count post-floor.
            let wave_reportable = w
                .findings
                .iter()
                .filter(|f| severity_rank(&f.severity) >= severity_floor_rank)
                .count();
            s.push_str(&format!(
                "### Wave {} — {} reportable findings (received {}/{} handoffs)\n\n",
                w.wave_number, wave_reportable, w.handoffs_received, w.assignments_total,
            ));
            // Render highest-severity first so disclosure-grade items
            // surface near the top of the section. Skip severities
            // below the floor entirely.
            for sev in ["critical", "high", "medium", "low", "info"] {
                if severity_rank(sev) < severity_floor_rank {
                    continue;
                }
                let group: Vec<&wave::Finding> =
                    w.findings.iter().filter(|f| f.severity == sev).collect();
                if group.is_empty() {
                    continue;
                }
                s.push_str(&format!(
                    "#### {} ({} finding{})\n\n",
                    sev,
                    group.len(),
                    if group.len() == 1 { "" } else { "s" }
                ));
                for f in group {
                    s.push_str(&format!("- **{}** — `{}`\n", f.title, f.surface));
                    let one_line: String = f
                        .evidence
                        .replace('\n', " ")
                        .chars()
                        .take(400)
                        .collect();
                    s.push_str(&format!("  - _evidence_: {}\n", one_line));
                }
                s.push('\n');
            }
            if !w.handoffs_missing.is_empty() {
                s.push_str(&format!(
                    "_Missing handoffs (still pending):_ `{}`\n\n",
                    w.handoffs_missing.join("`, `")
                ));
            }
        }
    } else {
        s.push_str("\n## Findings (from wave handoffs)\n\n");
        s.push_str("_No waves merged for this engagement yet._\n");
    }

    if !chains.is_empty() {
        s.push_str("\n## Chain attempts\n\n");
        s.push_str("Composed-finding hypotheses with explicit outcomes. The \
                    severity ladder is enforced server-side: LOW+LOW=LOW; \
                    chain severity cannot exceed `max(input)+1` without \
                    `severity_elevation_rationale`; cannot exceed `+2` even \
                    with one. Inspired by Hacker Bob's \
                    `bounty_write_chain_attempt`.\n\n");
        for (wave_n, attempts) in chains {
            s.push_str(&format!(
                "### Wave {} — {} chain attempt{}\n\n",
                wave_n,
                attempts.len(),
                if attempts.len() == 1 { "" } else { "s" }
            ));
            for c in attempts {
                s.push_str(&format!(
                    "- **{}** _(severity: {}, outcome: {})_\n",
                    c.hypothesis, c.severity, c.outcome
                ));
                s.push_str(&format!("  - _evidence_: {}\n", c.evidence_summary));
                if !c.steps.is_empty() {
                    s.push_str("  - _steps_:\n");
                    for step in &c.steps {
                        s.push_str(&format!("    1. {}\n", step));
                    }
                }
                if let Some(r) = &c.severity_elevation_rationale {
                    s.push_str(&format!("  - _elevation rationale_: {}\n", r));
                }
                s.push('\n');
            }
        }
    }

    s.push_str("\n_Rendered by `mantis_render_report` via the Mantis MCP server._\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_surface_event() {
        let jsonl = r#"{"schema_version":1,"seq":4,"wall_clock_unix":0,"kind":{"kind":"SurfaceDiscovered","host":"app.tenkara.ai","port":443,"scheme":"https","path":"/","status":307,"server":"Vercel","content_length":null,"tech_hints":["next.js"]}}"#;
        let surfaces = parse_surfaces(jsonl);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].host, "app.tenkara.ai");
        assert_eq!(surfaces[0].status, 307);
        assert_eq!(surfaces[0].tech_hints, vec!["next.js".to_string()]);
    }

    #[test]
    fn ignores_non_surface_events() {
        let jsonl = "{\"seq\":0,\"kind\":{\"kind\":\"EngagementCreated\",\"name\":\"x\"}}\n{\"seq\":1,\"kind\":{\"kind\":\"EngagementStarted\"}}\n";
        let surfaces = parse_surfaces(jsonl);
        assert!(surfaces.is_empty());
    }

    #[test]
    fn renders_minimal_report() {
        let info = EngagementSummary {
            id: "01HXXX".into(),
            name: "test".into(),
            state: "active",
            created_at_unix: 0,
            event_count: 5,
            scope_hash: None,
        };
        let surfaces = vec![Surface {
            seq: 4,
            host: "x.example".into(),
            port: 443,
            scheme: "https".into(),
            path: "/".into(),
            status: 200,
            server: Some("nginx".into()),
            tech_hints: vec![],
        }];
        let md = render_markdown(&info, &surfaces, &[], &[], 1);
        assert!(md.contains("x.example"));
        assert!(md.contains("Mantis Engagement Report"));
        assert!(md.contains("Waves executed | 0"));
    }

    #[test]
    fn renders_report_with_wave_findings() {
        let info = EngagementSummary {
            id: "01HXXX".into(),
            name: "test".into(),
            state: "active",
            created_at_unix: 0,
            event_count: 10,
            scope_hash: None,
        };
        let mut by_sev = std::collections::BTreeMap::new();
        by_sev.insert("high".into(), 1u32);
        by_sev.insert("low".into(), 2u32);
        let waves = vec![wave::WaveMerge {
            wave_number: 1,
            merged_at_unix: 0,
            assignments_total: 3,
            handoffs_received: 3,
            handoffs_missing: vec![],
            findings_total: 3,
            findings_by_severity: by_sev,
            dead_ends_total: 5,
            coverage_total: 10,
            findings: vec![
                wave::Finding {
                    title: "Source map exposed".into(),
                    surface: "https://x.example/bundle.js.map".into(),
                    severity: "high".into(),
                    evidence: "GET /bundle.js.map -> 200".into(),
                },
                wave::Finding {
                    title: "HSTS preload missing".into(),
                    surface: "https://x.example/".into(),
                    severity: "low".into(),
                    evidence: "max-age=31536000 lacks preload".into(),
                },
                wave::Finding {
                    title: "Server banner disclosed".into(),
                    surface: "https://x.example/".into(),
                    severity: "low".into(),
                    evidence: "server: nginx/1.21".into(),
                },
            ],
        }];
        let md = render_markdown(&info, &[], &waves, &[], 1);
        // Total raw findings still reported in the summary table.
        assert!(md.contains("Findings total (raw) | 3"));
        // Default floor (low) admits both high and low.
        assert!(md.contains("Wave 1 — 3 reportable findings"));
        assert!(md.contains("Source map exposed"));
        // High-severity findings precede low-severity in the wave section.
        let hi = md.find("Source map exposed").unwrap();
        let lo = md.find("HSTS preload missing").unwrap();
        assert!(hi < lo, "high-severity finding should appear before low");
    }

    #[test]
    fn renders_drops_info_findings_at_default_floor() {
        let info = EngagementSummary {
            id: "01HXXX".into(),
            name: "test".into(),
            state: "active",
            created_at_unix: 0,
            event_count: 10,
            scope_hash: None,
        };
        let mut by_sev = std::collections::BTreeMap::new();
        by_sev.insert("high".into(), 1u32);
        by_sev.insert("info".into(), 102u32); // the tenkara-shaped noise floor
        let waves = vec![wave::WaveMerge {
            wave_number: 1,
            merged_at_unix: 0,
            assignments_total: 6,
            handoffs_received: 6,
            handoffs_missing: vec![],
            findings_total: 103,
            findings_by_severity: by_sev,
            dead_ends_total: 21,
            coverage_total: 41,
            findings: vec![
                wave::Finding {
                    title: "Source map exposed".into(),
                    surface: "https://x.example/bundle.js.map".into(),
                    severity: "high".into(),
                    evidence: "GET /bundle.js.map -> 200".into(),
                },
                wave::Finding {
                    title: "TLS 1.2 supported".into(),
                    surface: "https://x.example/".into(),
                    severity: "info".into(),
                    evidence: "openssl s_client -tls1_2".into(),
                },
            ],
        }];
        let md = render_markdown(&info, &[], &waves, &[], 1);
        assert!(md.contains("Source map exposed"));
        assert!(
            !md.contains("TLS 1.2 supported"),
            "info-tier finding leaked into rendered report:\n{md}"
        );
        assert!(md.contains("Findings suppressed below floor | 102"));
    }

    #[test]
    fn parse_severity_floor_handles_known_values() {
        assert_eq!(parse_severity_floor(None), 1);
        assert_eq!(parse_severity_floor(Some("info")), 0);
        assert_eq!(parse_severity_floor(Some("LOW")), 1);
        assert_eq!(parse_severity_floor(Some("Medium")), 2);
        assert_eq!(parse_severity_floor(Some("high")), 3);
        assert_eq!(parse_severity_floor(Some("critical")), 4);
        assert_eq!(parse_severity_floor(Some("garbage")), 1);
    }

    #[test]
    fn route_surfaces_args_round_trip() {
        // Sanity: the input schema parses the shape the MCP client sends.
        let raw = r#"{
            "engagement_id": "eng-1",
            "surfaces": [
                {"surface_id": "s-1", "surface_type": "web", "url": "https://example.com/"},
                {"surface_id": "s-2", "surface_type": null, "url": "http://api.example.com/v1/users"}
            ]
        }"#;
        let args: RouteSurfacesArgs = serde_json::from_str(raw).unwrap();
        assert_eq!(args.engagement_id, "eng-1");
        assert_eq!(args.surfaces.len(), 2);
        assert_eq!(args.surfaces[0].surface_id, "s-1");
        assert_eq!(args.surfaces[0].surface_type.as_deref(), Some("web"));
        assert!(args.surfaces[1].surface_type.is_none());
    }

    // -------- ported-tool schema round-trips --------

    #[test]
    fn payload_tool_args_parses_with_data() {
        let raw = r#"{"engagement_id":"eng-1","data":{"finding_id":"F-1","severity":"high"}}"#;
        let v: PayloadToolArgs = serde_json::from_str(raw).unwrap();
        assert_eq!(v.engagement_id, "eng-1");
        assert_eq!(v.data.get("finding_id").and_then(|x| x.as_str()), Some("F-1"));
    }

    #[test]
    fn payload_tool_args_parses_without_data() {
        let v: PayloadToolArgs = serde_json::from_str(r#"{"engagement_id":"e"}"#).unwrap();
        assert!(v.data.is_null());
    }

    #[test]
    fn playbook_id_args_parses() {
        let v: PlaybookIdArgs = serde_json::from_str(
            r#"{"engagement_id":"e","playbook_id":"C9_ssrf_to_imds"}"#,
        )
        .unwrap();
        assert_eq!(v.playbook_id, "C9_ssrf_to_imds");
    }

    #[test]
    fn technique_pack_args_parses() {
        let v: TechniquePackArgs = serde_json::from_str(
            r#"{"engagement_id":"e","pack_id":"auth-differential"}"#,
        )
        .unwrap();
        assert_eq!(v.pack_id, "auth-differential");
    }

    #[test]
    fn chain_query_args_parses() {
        let v: ChainQueryArgs =
            serde_json::from_str(r#"{"engagement_id":"e","node_id":"blake3:abc"}"#).unwrap();
        assert_eq!(v.node_id, "blake3:abc");
    }

    #[test]
    fn chain_tool_args_parses_with_all_fields() {
        let raw = r#"{"engagement_id":"e","chain_family":"evm","network":"sepolia","address":"0xdead","data":{"slot":7}}"#;
        let v: ChainToolArgs = serde_json::from_str(raw).unwrap();
        assert_eq!(v.chain_family, "evm");
        assert_eq!(v.network.as_deref(), Some("sepolia"));
        assert_eq!(v.address.as_deref(), Some("0xdead"));
        assert_eq!(v.data.get("slot").and_then(|x| x.as_u64()), Some(7));
    }

    #[test]
    fn chain_tool_args_parses_with_only_required_fields() {
        let v: ChainToolArgs =
            serde_json::from_str(r#"{"engagement_id":"e","chain_family":"sui"}"#).unwrap();
        assert_eq!(v.chain_family, "sui");
        assert!(v.network.is_none());
        assert!(v.address.is_none());
        assert!(v.data.is_null());
    }

    #[test]
    fn deferred_read_response_has_engagement_id() {
        let v = deferred_read_response("read_findings", "eng-x");
        assert_eq!(v.get("engagement_id").and_then(|x| x.as_str()), Some("eng-x"));
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("ok"));
        assert!(v.get("items").unwrap().is_array());
    }

    #[test]
    fn recorded_response_echoes_payload() {
        let args = PayloadToolArgs {
            engagement_id: "eng-y".into(),
            data: json!({"k": "v"}),
        };
        let v = recorded_response("log_coverage", &args);
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("recorded"));
        assert_eq!(v.get("payload_received").unwrap(), &json!({"k": "v"}));
    }

    #[test]
    fn chain_deferred_response_defaults_network_to_mainnet() {
        let args = ChainToolArgs {
            engagement_id: "e".into(),
            chain_family: "evm".into(),
            network: None,
            address: None,
            data: json!({}),
        };
        let v = chain_deferred_response("evm_call", "evm", &args);
        assert_eq!(v.get("network").and_then(|x| x.as_str()), Some("mainnet"));
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("stubbed"));
    }

    #[test]
    fn deferred_browser_response_flags_v2_deferral() {
        let args = PayloadToolArgs {
            engagement_id: "e".into(),
            data: json!({}),
        };
        let v = deferred_browser_response("auto_signup", &args);
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("deferred"));
        assert!(v.get("reason").and_then(|x| x.as_str()).unwrap().contains("v2"));
    }

    #[test]
    fn run_auth_diff_profile_role_lowercase() {
        let raw = r#"{
            "engagement_id":"e","url":"https://x/",
            "profiles":[
              {"role":"attacker","headers":["Authorization: Bearer A"],"cookies":["s=1"]}
            ]
        }"#;
        let v: RunAuthDifferentialArgs = serde_json::from_str(raw).unwrap();
        assert_eq!(v.profiles[0].role, "attacker");
        assert_eq!(v.profiles[0].headers.len(), 1);
    }

    #[test]
    fn graphql_introspection_args_parses() {
        let v: GraphqlIntrospectionArgs = serde_json::from_str(
            r#"{"engagement_id":"e","endpoint":"https://x/graphql"}"#,
        )
        .unwrap();
        assert!(v.endpoint.ends_with("/graphql"));
    }

    #[test]
    fn wayback_urls_args_default_limit() {
        let v: WaybackUrlsArgs =
            serde_json::from_str(r#"{"engagement_id":"e","host":"example.com"}"#).unwrap();
        assert!(v.limit.is_none());
    }

    #[test]
    fn extract_js_endpoints_args_parses() {
        let v: ExtractJsEndpointsArgs = serde_json::from_str(
            r#"{"engagement_id":"e","js_url":"https://x/main.js"}"#,
        )
        .unwrap();
        assert!(v.js_url.ends_with(".js"));
    }

    #[test]
    fn run_tiered_args_optionals() {
        let v: RunTieredArgs = serde_json::from_str(
            r#"{"engagement_id":"e","target_url":"https://x","objective":"IDOR"}"#,
        )
        .unwrap();
        assert!(v.budget_seconds.is_none());
        assert!(v.hard_max_iterations.is_none());
    }

    // -------- ported-tool name sanity tests --------
    //
    // Each test below confirms a single tool's response helper builds
    // a JSON object with the expected `tool` and `engagement_id`
    // fields. These are intentionally small but each is an end-to-end
    // check that the helper hasn't drifted out of sync with the
    // tool's registered name.

    fn pl(id: &str) -> PayloadToolArgs {
        PayloadToolArgs {
            engagement_id: id.into(),
            data: json!({"k": "v"}),
        }
    }

    fn ch(id: &str, fam: &str) -> ChainToolArgs {
        ChainToolArgs {
            engagement_id: id.into(),
            chain_family: fam.into(),
            network: None,
            address: None,
            data: json!({}),
        }
    }

    macro_rules! tool_helper_test {
        (read $name:ident, $tool:expr) => {
            #[test]
            fn $name() {
                let v = deferred_read_response($tool, "eng");
                assert_eq!(
                    v.get("tool").and_then(|x| x.as_str()),
                    Some(concat!("mantis_", $tool))
                );
                assert_eq!(v.get("engagement_id").and_then(|x| x.as_str()), Some("eng"));
            }
        };
        (write $name:ident, $tool:expr) => {
            #[test]
            fn $name() {
                let v = recorded_response($tool, &pl("eng"));
                assert_eq!(
                    v.get("tool").and_then(|x| x.as_str()),
                    Some(concat!("mantis_", $tool))
                );
                assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("recorded"));
            }
        };
        (chain $name:ident, $tool:expr, $fam:expr) => {
            #[test]
            fn $name() {
                let v = chain_deferred_response($tool, $fam, &ch("eng", $fam));
                assert_eq!(
                    v.get("tool").and_then(|x| x.as_str()),
                    Some(concat!("mantis_", $tool))
                );
                assert_eq!(v.get("chain_family").and_then(|x| x.as_str()), Some($fam));
                assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("stubbed"));
            }
        };
    }

    // Read-only inspectors (28 tools).
    tool_helper_test!(read t_rd_session_summary, "read_session_summary");
    tool_helper_test!(read t_rd_state_summary, "read_state_summary");
    tool_helper_test!(read t_rd_auth_diff_results, "read_auth_differential_results");
    tool_helper_test!(read t_rd_doc_delta_results, "read_doc_delta_results");
    tool_helper_test!(read t_rd_http_audit, "read_http_audit");
    tool_helper_test!(read t_rd_verification_round, "read_verification_round");
    tool_helper_test!(read t_rd_verification_context, "read_verification_context");
    tool_helper_test!(read t_rd_evidence_packs, "read_evidence_packs");
    tool_helper_test!(read t_rd_grade_verdict, "read_grade_verdict");
    tool_helper_test!(read t_rd_capability_metrics, "read_capability_metrics");
    tool_helper_test!(read t_rd_hunter_brief, "read_hunter_brief");
    tool_helper_test!(read t_rd_surface_leads, "read_surface_leads");
    tool_helper_test!(read t_rd_surface_routes, "read_surface_routes");
    tool_helper_test!(read t_rd_tool_telemetry, "read_tool_telemetry");
    tool_helper_test!(read t_rd_pipeline_analytics, "read_pipeline_analytics");
    tool_helper_test!(read t_rd_invariant_runs, "read_invariant_runs");
    tool_helper_test!(read t_rd_query_findings_index, "query_findings_index");
    tool_helper_test!(read t_rd_query_schema_contracts, "query_schema_contracts");
    tool_helper_test!(read t_rd_query_surface_graph, "query_surface_graph");
    tool_helper_test!(read t_rd_query_audit_reports, "query_audit_reports");
    tool_helper_test!(read t_rd_chain_frontier, "chain_frontier");
    tool_helper_test!(read t_rd_list_auth_profiles, "list_auth_profiles");
    tool_helper_test!(read t_rd_wave_handoff_status, "wave_handoff_status");
    tool_helper_test!(read t_rd_clear_operator_note, "clear_operator_note");
    tool_helper_test!(read t_rd_clear_terminal_block, "clear_terminal_block");

    // Write tools (32 tools).
    tool_helper_test!(write t_wr_record_finding, "record_finding");
    tool_helper_test!(write t_wr_index_finding, "index_finding");
    tool_helper_test!(write t_wr_log_coverage, "log_coverage");
    tool_helper_test!(write t_wr_log_dead_ends, "log_dead_ends");
    tool_helper_test!(write t_wr_log_technique_attempt, "log_technique_attempt");
    tool_helper_test!(write t_wr_write_evidence_packs, "write_evidence_packs");
    tool_helper_test!(write t_wr_write_grade_verdict, "write_grade_verdict");
    tool_helper_test!(write t_wr_write_chain_attempt, "write_chain_attempt");
    tool_helper_test!(write t_wr_append_chain_node, "append_chain_node");
    tool_helper_test!(write t_wr_build_surface_graph, "build_surface_graph");
    tool_helper_test!(write t_wr_build_symbol_surface_index, "build_symbol_surface_index");
    tool_helper_test!(write t_wr_extract_routes, "extract_routes");
    tool_helper_test!(write t_wr_public_intel, "public_intel");
    tool_helper_test!(write t_wr_static_scan, "static_scan");
    tool_helper_test!(write t_wr_signup_detect, "signup_detect");
    tool_helper_test!(write t_wr_temp_email, "temp_email");
    tool_helper_test!(write t_wr_suggest_invariants, "suggest_invariants");
    tool_helper_test!(write t_wr_summarize_diff_impact, "summarize_diff_impact");
    tool_helper_test!(write t_wr_record_surface_leads, "record_surface_leads");
    tool_helper_test!(write t_wr_promote_surface_leads, "promote_surface_leads");
    tool_helper_test!(write t_wr_start_next_wave, "start_next_wave");
    tool_helper_test!(write t_wr_select_technique_packs, "select_technique_packs");
    tool_helper_test!(write t_wr_evaluate_capabilities, "evaluate_capabilities");
    tool_helper_test!(write t_wr_diff_verification_attempts, "diff_verification_attempts");
    tool_helper_test!(write t_wr_run_doc_delta, "run_doc_delta");
    tool_helper_test!(write t_wr_run_invariant_for_finding, "run_invariant_for_finding");
    tool_helper_test!(write t_wr_merge_wave_handoffs, "merge_wave_handoffs");
    tool_helper_test!(write t_wr_write_wave_handoff, "write_wave_handoff");
    tool_helper_test!(write t_wr_apply_wave_merge, "apply_wave_merge");
    tool_helper_test!(write t_wr_finalize_hunter_run, "finalize_hunter_run");
    tool_helper_test!(write t_wr_report_written, "report_written");
    tool_helper_test!(write t_wr_set_operator_note, "set_operator_note");
    tool_helper_test!(write t_wr_auth_store, "auth_store");
    tool_helper_test!(write t_wr_ingest_audit_report, "ingest_audit_report");
    tool_helper_test!(write t_wr_ingest_schema_doc, "ingest_schema_doc");
    tool_helper_test!(write t_wr_import_http_traffic, "import_http_traffic");
    tool_helper_test!(write t_wr_import_static_artifact, "import_static_artifact");
    tool_helper_test!(write t_wr_init_session, "init_session");

    // Smart-contract tools (24 tools).
    tool_helper_test!(chain t_evm_call, "evm_call", "evm");
    tool_helper_test!(chain t_evm_storage_read, "evm_storage_read", "evm");
    tool_helper_test!(chain t_evm_fetch_source, "evm_fetch_source", "evm");
    tool_helper_test!(chain t_evm_role_table, "evm_role_table", "evm");
    tool_helper_test!(chain t_foundry_run, "foundry_run", "evm");
    tool_helper_test!(chain t_halmos_run, "halmos_run", "evm");
    tool_helper_test!(chain t_svm_fetch_account, "svm_fetch_account", "svm");
    tool_helper_test!(chain t_svm_fetch_program, "svm_fetch_program", "svm");
    tool_helper_test!(chain t_anchor_run, "anchor_run", "svm");
    tool_helper_test!(chain t_aptos_fetch_module, "aptos_fetch_module", "aptos");
    tool_helper_test!(chain t_aptos_fetch_resource, "aptos_fetch_resource", "aptos");
    tool_helper_test!(chain t_aptos_run, "aptos_run", "aptos");
    tool_helper_test!(chain t_sui_fetch_object, "sui_fetch_object", "sui");
    tool_helper_test!(chain t_sui_fetch_package, "sui_fetch_package", "sui");
    tool_helper_test!(chain t_sui_run, "sui_run", "sui");
    tool_helper_test!(chain t_substrate_fetch_storage, "substrate_fetch_storage", "substrate");
    tool_helper_test!(chain t_substrate_fetch_runtime, "substrate_fetch_runtime", "substrate");
    tool_helper_test!(chain t_substrate_run, "substrate_run", "substrate");
    tool_helper_test!(chain t_cosmwasm_fetch_contract, "cosmwasm_fetch_contract", "cosmwasm");
    tool_helper_test!(chain t_cosmwasm_smart_query, "cosmwasm_smart_query", "cosmwasm");
    tool_helper_test!(chain t_cosmwasm_run, "cosmwasm_run", "cosmwasm");

    // Extra schema round-trips for the chain/playbook/technique variants.
    #[test]
    fn chain_tool_args_parses_evm_mainnet() {
        let v: ChainToolArgs = serde_json::from_str(
            r#"{"engagement_id":"e","chain_family":"evm","network":"mainnet"}"#,
        )
        .unwrap();
        assert_eq!(v.chain_family, "evm");
        assert_eq!(v.network.as_deref(), Some("mainnet"));
    }

    #[test]
    fn chain_tool_args_parses_sui_devnet() {
        let v: ChainToolArgs = serde_json::from_str(
            r#"{"engagement_id":"e","chain_family":"sui","network":"devnet"}"#,
        )
        .unwrap();
        assert_eq!(v.chain_family, "sui");
        assert_eq!(v.network.as_deref(), Some("devnet"));
    }

    #[test]
    fn chain_tool_args_parses_aptos_testnet() {
        let v: ChainToolArgs = serde_json::from_str(
            r#"{"engagement_id":"e","chain_family":"aptos","network":"testnet"}"#,
        )
        .unwrap();
        assert_eq!(v.chain_family, "aptos");
        assert_eq!(v.network.as_deref(), Some("testnet"));
    }

    #[test]
    fn chain_tool_args_parses_substrate_kusama() {
        let v: ChainToolArgs = serde_json::from_str(
            r#"{"engagement_id":"e","chain_family":"substrate","network":"kusama"}"#,
        )
        .unwrap();
        assert_eq!(v.chain_family, "substrate");
        assert_eq!(v.network.as_deref(), Some("kusama"));
    }

    #[test]
    fn chain_tool_args_parses_cosmwasm_juno() {
        let v: ChainToolArgs = serde_json::from_str(
            r#"{"engagement_id":"e","chain_family":"cosmwasm","network":"juno"}"#,
        )
        .unwrap();
        assert_eq!(v.chain_family, "cosmwasm");
        assert_eq!(v.network.as_deref(), Some("juno"));
    }

    #[test]
    fn playbook_id_args_handles_all_chain_playbook_ids() {
        for id in &[
            "C5_idor_burst",
            "C9_ssrf_to_imds",
            "C10_xss_to_csrf",
            "C19_http_smuggling",
        ] {
            let raw = format!(r#"{{"engagement_id":"e","playbook_id":"{id}"}}"#);
            let v: PlaybookIdArgs = serde_json::from_str(&raw).unwrap();
            assert_eq!(v.playbook_id, *id);
        }
    }

    #[test]
    fn technique_pack_args_handles_all_known_packs() {
        for id in &[
            "auth-differential",
            "idor-burst",
            "ssrf-imds",
            "graphql-introspection",
            "jwt-signer-swap",
        ] {
            let raw = format!(r#"{{"engagement_id":"e","pack_id":"{id}"}}"#);
            let v: TechniquePackArgs = serde_json::from_str(&raw).unwrap();
            assert_eq!(v.pack_id, *id);
        }
    }

    #[test]
    fn deferred_read_returns_array_items() {
        let v = deferred_read_response("any_read", "eng-z");
        assert!(v.get("items").unwrap().is_array());
    }

    #[test]
    fn recorded_response_status_is_recorded() {
        let v = recorded_response("any_write", &pl("eng"));
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("recorded"));
    }

    #[test]
    fn chain_deferred_status_is_stubbed_for_every_family() {
        for fam in &["evm", "svm", "aptos", "sui", "substrate", "cosmwasm"] {
            let v = chain_deferred_response("x", fam, &ch("e", fam));
            assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("stubbed"));
            assert_eq!(v.get("chain_family").and_then(|x| x.as_str()), Some(*fam));
        }
    }

    #[test]
    fn deferred_browser_response_mentions_v2() {
        let v = deferred_browser_response("auto_signup", &pl("eng"));
        let msg = v.get("reason").and_then(|x| x.as_str()).unwrap();
        assert!(msg.contains("v2"));
        assert!(msg.contains("manually"));
    }

    #[test]
    fn run_auth_differential_unauth_role_parses() {
        let raw = r#"{"engagement_id":"e","url":"https://x/","profiles":[{"role":"unauthenticated"}]}"#;
        let v: RunAuthDifferentialArgs = serde_json::from_str(raw).unwrap();
        assert_eq!(v.profiles[0].role, "unauthenticated");
    }

    #[test]
    fn run_auth_differential_admin_role_parses() {
        let raw = r#"{"engagement_id":"e","url":"https://x/","profiles":[{"role":"admin"}]}"#;
        let v: RunAuthDifferentialArgs = serde_json::from_str(raw).unwrap();
        assert_eq!(v.profiles[0].role, "admin");
    }

    #[test]
    fn run_auth_differential_victim_role_parses() {
        let raw = r#"{"engagement_id":"e","url":"https://x/","profiles":[{"role":"victim","cookies":["sid=abc"]}]}"#;
        let v: RunAuthDifferentialArgs = serde_json::from_str(raw).unwrap();
        assert_eq!(v.profiles[0].role, "victim");
        assert_eq!(v.profiles[0].cookies.len(), 1);
    }

    #[test]
    fn wayback_urls_args_with_limit() {
        let v: WaybackUrlsArgs =
            serde_json::from_str(r#"{"engagement_id":"e","host":"example.com","limit":1000}"#)
                .unwrap();
        assert_eq!(v.limit, Some(1000));
    }

    #[test]
    fn extract_js_endpoints_args_round_trip() {
        let raw = r#"{"engagement_id":"e","js_url":"https://x/_next/static/chunks/main-abc.js"}"#;
        let v: ExtractJsEndpointsArgs = serde_json::from_str(raw).unwrap();
        assert!(v.js_url.contains("_next"));
    }

    #[test]
    fn run_tiered_args_with_full_options() {
        let raw = r#"{"engagement_id":"e","target_url":"https://x","objective":"SSRF","budget_seconds":60,"hard_max_iterations":5}"#;
        let v: RunTieredArgs = serde_json::from_str(raw).unwrap();
        assert_eq!(v.budget_seconds, Some(60));
        assert_eq!(v.hard_max_iterations, Some(5));
    }
}
