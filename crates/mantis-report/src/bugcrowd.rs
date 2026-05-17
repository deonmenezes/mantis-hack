//! Bugcrowd VRT-style JSON report.
//!
//! Bugcrowd uses the Vulnerability Rating Taxonomy (VRT) to classify
//! findings. This emitter maps each Verified claim to a VRT-shaped
//! object. Operators paste the file into the Bugcrowd submission
//! form to pre-fill the fields.

use serde::Serialize;

use crate::Report;
use mantis_claim::{Claim, ClaimState};

pub fn render(report: &Report<'_>) -> String {
    let mut submissions: Vec<BcSubmission> = report
        .claims
        .iter()
        .filter(|c| matches!(c.state, ClaimState::Verified { .. }))
        .map(claim_to_submission)
        .collect();
    submissions.sort_by_key(|s| std::cmp::Reverse(s.severity));
    let envelope = BcEnvelope {
        engagement_id: report.metadata.engagement_id.clone(),
        generated_at_unix: report.metadata.generated_at_unix,
        submissions,
    };
    serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| "{}".to_owned())
}

fn claim_to_submission(claim: &Claim) -> BcSubmission {
    BcSubmission {
        title: format!(
            "{} on {}",
            crate::pretty_class(&claim.vuln_class),
            claim.surface.url()
        ),
        vrt_id: vrt_id_for(&claim.vuln_class),
        severity: severity_score(crate::severity::severity_for(&claim.vuln_class)),
        description: claim
            .evidence
            .iter()
            .map(|e| format!("- {}: {}", e.kind, e.detail))
            .collect::<Vec<_>>()
            .join("\n"),
        extra_info: format!(
            "cURL reproducer:\n{}\n\nRaw HTTP reproducer:\n{}",
            claim.reproducer.curl, claim.reproducer.raw_http
        ),
        target: claim.surface.url(),
        kind: "vulnerability".into(),
    }
}

fn severity_score(s: crate::Severity) -> u8 {
    match s {
        crate::Severity::Critical => 1,
        crate::Severity::High => 2,
        crate::Severity::Medium => 3,
        crate::Severity::Low => 4,
        crate::Severity::Informational => 5,
    }
}

/// Map an internal vuln class to the closest VRT identifier.
/// These are placeholders for Phase 2 M2.5; M2.5b refines them
/// once we have ground-truth examples from real engagements.
fn vrt_id_for(vuln_class: &str) -> String {
    match vuln_class {
        "sqli" => "server_side_injection.sql_injection".into(),
        "idor" => "broken_access_control.idor".into(),
        "open-redirect" => "unvalidated_redirects_and_forwards.open_redirect".into(),
        "xss-reflected" => "cross_site_scripting_xss.reflected".into(),
        "xss-stored" => "cross_site_scripting_xss.stored".into(),
        "cors-misconfig" => "broken_access_control.cors_misconfiguration".into(),
        "auth-bypass" => "broken_authentication_and_session_management.bypass".into(),
        "info-disclosure" => "sensitive_data_exposure.missing_security_headers".into(),
        "ssrf" => "server_side_request_forgery.basic".into(),
        "rce" => "server_side_injection.remote_code_execution".into(),
        other => format!("other.{other}"),
    }
}

#[derive(Debug, Serialize)]
struct BcEnvelope {
    engagement_id: String,
    generated_at_unix: u64,
    submissions: Vec<BcSubmission>,
}

#[derive(Debug, Serialize)]
struct BcSubmission {
    title: String,
    vrt_id: String,
    severity: u8,
    description: String,
    extra_info: String,
    target: String,
    #[serde(rename = "type")]
    kind: String,
}
