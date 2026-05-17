//! End-to-end engagement pipeline.
//!
//! Drives the loop that connects scanner → planner → primitive →
//! verifier → posterior update → event log. Phase 1 M1.7's central
//! integration. The pipeline runs synchronously per scan request;
//! Phase 2 will move it behind an `Engagement.Subscribe` streaming
//! RPC so the operator sees progress live.

use std::sync::Arc;

use mantis_claim::{verify_claim, Claim, ClaimState, SurfaceSnapshot};
use mantis_core::{EngagementId, Signer};
use mantis_event_store::{EventKind, EventStore};
use mantis_hypothesis::generate_for;
use mantis_planner::{Planner, SurfaceKey};
use mantis_posterior::Posteriors;
use mantis_primitive::{
    CorsWildcard, Idor, MissingSecurityHeaders, OpenRedirect, Primitive, PrimitiveResult,
    SqliErrorBased, XssReflected,
};
use mantis_scanner_http::Surface;
use reqwest::Client;
use tracing::{info, warn};

/// Build the static primitive catalog. Order doesn't matter — the
/// planner picks via UCB1.
pub(crate) fn build_catalog() -> Vec<Box<dyn Primitive>> {
    vec![
        Box::new(MissingSecurityHeaders),
        Box::new(OpenRedirect),
        Box::new(CorsWildcard),
        Box::new(Idor),
        Box::new(XssReflected),
        Box::new(SqliErrorBased),
    ]
}

/// Outcome counts returned to the RPC caller.
#[derive(Debug, Default)]
pub(crate) struct PipelineOutcome {
    pub hypotheses_recorded: u32,
    pub primitives_executed: u32,
    pub claims_verified: u32,
    pub claims_rejected: u32,
    pub claims_retained: u32,
}

/// Run the full pipeline over a list of discovered surfaces. Writes
/// events to the event store and updates the workspace posterior
/// store.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_pipeline(
    surfaces: &[Surface],
    catalog: &[Box<dyn Primitive>],
    event_store: &Arc<EventStore>,
    engagement_id: EngagementId,
    signer: &Arc<dyn Signer>,
    posteriors: &Posteriors,
    client: &Client,
    request_budget: u32,
) -> PipelineOutcome {
    let mut outcome = PipelineOutcome::default();
    let mut planner = Planner::new();

    // Hypothesis generation + planner registration.
    for surface in surfaces {
        for h in generate_for(surface) {
            let stack = surface
                .tech_hints
                .first()
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            let prior = posteriors.blended_prior(stack, &h.vuln_class, h.prior_pp10k);
            let surface_id = surface.target.url();
            let kind = EventKind::HypothesisGenerated {
                surface_id: surface_id.clone(),
                vuln_class: h.vuln_class.clone(),
                summary: h.summary.clone(),
                prior,
            };
            if let Err(e) = event_store.append(engagement_id, kind, signer.as_ref()) {
                warn!(error = %e, "failed to append HypothesisGenerated");
                continue;
            }
            outcome.hypotheses_recorded += 1;
            for primitive in catalog {
                if primitive.vuln_class() == h.vuln_class && primitive.matches_surface(surface) {
                    planner.register_action(
                        SurfaceKey(surface_id.clone()),
                        primitive.id().to_string(),
                        prior,
                    );
                }
            }
        }
    }

    // Drive the planner up to the budget.
    let surface_by_url: std::collections::HashMap<String, &Surface> =
        surfaces.iter().map(|s| (s.target.url(), s)).collect();

    for _ in 0..request_budget {
        let Some(action) = planner.next_action() else {
            break;
        };
        let action_id = action.id;
        let surface_url = action.surface_key.0.clone();
        let primitive_id = action.primitive_id.to_string();

        let Some(surface) = surface_by_url.get(surface_url.as_str()).copied() else {
            warn!(%surface_url, "planner returned action for unknown surface");
            planner.record_outcome(action_id, 0.0);
            continue;
        };
        let Some(primitive) = catalog.iter().find(|p| p.id() == primitive_id) else {
            warn!(%primitive_id, "planner returned action for unknown primitive");
            planner.record_outcome(action_id, 0.0);
            continue;
        };

        let result = match primitive.execute(surface, client).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, %primitive_id, "primitive execution error");
                planner.record_outcome(action_id, 0.0);
                continue;
            }
        };
        outcome.primitives_executed += 1;
        let verdict_kind = match &result {
            PrimitiveResult::Confirmed { .. } => "confirmed",
            PrimitiveResult::Denied { .. } => "denied",
            PrimitiveResult::Inconclusive { .. } => "inconclusive",
        };
        let _ = event_store.append(
            engagement_id,
            EventKind::PrimitiveExecuted {
                surface_id: surface_url.clone(),
                primitive_id: primitive_id.clone(),
                vuln_class: primitive.vuln_class().to_owned(),
                verdict: verdict_kind.to_owned(),
            },
            signer.as_ref(),
        );

        let stack = surface
            .tech_hints
            .first()
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        let (success, reward): (Option<bool>, f64) = match result {
            PrimitiveResult::Denied { .. } => (Some(false), 0.0),
            PrimitiveResult::Inconclusive { .. } => (None, 0.0),
            PrimitiveResult::Confirmed {
                evidence,
                reproducer,
            } => {
                // Build a Claim and run the verifier.
                let claim = Claim::pending(
                    primitive.id().to_string(),
                    primitive.vuln_class().to_string(),
                    SurfaceSnapshot::from(surface),
                    evidence,
                    reproducer,
                );
                match verify_claim(&claim, client).await {
                    Ok(ClaimState::Verified { verifier_id }) => {
                        outcome.claims_verified += 1;
                        let _ = event_store.append(
                            engagement_id,
                            EventKind::ClaimVerified {
                                surface_id: surface_url.clone(),
                                primitive_id: primitive_id.clone(),
                                verifier_id,
                            },
                            signer.as_ref(),
                        );
                        (Some(true), 1.0)
                    }
                    Ok(ClaimState::Rejected { reason }) => {
                        outcome.claims_rejected += 1;
                        let _ = event_store.append(
                            engagement_id,
                            EventKind::ClaimRejected {
                                surface_id: surface_url.clone(),
                                primitive_id: primitive_id.clone(),
                                reason,
                            },
                            signer.as_ref(),
                        );
                        (Some(false), 0.0)
                    }
                    Ok(ClaimState::Retained { reason }) => {
                        outcome.claims_retained += 1;
                        let _ = event_store.append(
                            engagement_id,
                            EventKind::ClaimRetained {
                                surface_id: surface_url.clone(),
                                primitive_id: primitive_id.clone(),
                                reason,
                            },
                            signer.as_ref(),
                        );
                        (None, 0.0)
                    }
                    Ok(ClaimState::Pending) | Err(_) => (None, 0.0),
                }
            }
        };

        if let Some(s) = success {
            posteriors.record_outcome(stack, primitive.vuln_class(), s);
        }
        planner.record_outcome(action_id, reward);
    }

    info!(
        hypotheses = outcome.hypotheses_recorded,
        primitives = outcome.primitives_executed,
        verified = outcome.claims_verified,
        rejected = outcome.claims_rejected,
        retained = outcome.claims_retained,
        "pipeline complete"
    );
    outcome
}
