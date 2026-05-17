//! HackerOne disclosure JSON.
//!
//! Each Verified claim becomes one report-like object. The exact
//! HackerOne API for submitting reports differs by programme; the
//! shape here matches their disclosure JSON export format so an
//! operator can paste the file into the report editor.

use serde::Serialize;

use crate::Report;
use mantis_claim::{Claim, ClaimState};

pub fn render(report: &Report<'_>) -> String {
    let mut findings: Vec<HoneFinding> = report
        .claims
        .iter()
        .filter(|c| matches!(c.state, ClaimState::Verified { .. }))
        .map(claim_to_finding)
        .collect();
    findings.sort_by_key(|f| std::cmp::Reverse(severity_rank(&f.severity.rating)));
    let envelope = HoneEnvelope {
        program: "mantis-engagement".into(),
        engagement_id: report.metadata.engagement_id.clone(),
        generated_at_unix: report.metadata.generated_at_unix,
        findings,
    };
    serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| "{}".to_owned())
}

fn claim_to_finding(claim: &Claim) -> HoneFinding {
    let severity_rating = crate::severity::severity_for(&claim.vuln_class);
    HoneFinding {
        title: format!(
            "{} on {}",
            crate::pretty_class(&claim.vuln_class),
            claim.surface.url()
        ),
        severity: HoneSeverity {
            rating: severity_label(severity_rating),
        },
        weakness: HoneWeakness {
            name: claim.vuln_class.clone(),
        },
        vulnerability_information: claim
            .evidence
            .iter()
            .map(|e| format!("- {}: {}", e.kind, e.detail))
            .collect::<Vec<_>>()
            .join("\n"),
        proof_of_concept: format!(
            "## cURL\n```\n{}\n```\n\n## Raw HTTP\n```\n{}\n```",
            claim.reproducer.curl, claim.reproducer.raw_http
        ),
        structured_scope: HoneScope {
            asset_identifier: claim.surface.url(),
            asset_type: "URL".into(),
        },
        references: vec![],
    }
}

fn severity_label(s: crate::Severity) -> String {
    match s {
        crate::Severity::Critical => "critical".into(),
        crate::Severity::High => "high".into(),
        crate::Severity::Medium => "medium".into(),
        crate::Severity::Low => "low".into(),
        crate::Severity::Informational => "none".into(),
    }
}

fn severity_rank(label: &str) -> u32 {
    match label {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[derive(Debug, Serialize)]
struct HoneEnvelope {
    program: String,
    engagement_id: String,
    generated_at_unix: u64,
    findings: Vec<HoneFinding>,
}

#[derive(Debug, Serialize)]
struct HoneFinding {
    title: String,
    severity: HoneSeverity,
    weakness: HoneWeakness,
    vulnerability_information: String,
    proof_of_concept: String,
    structured_scope: HoneScope,
    references: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HoneSeverity {
    rating: String,
}

#[derive(Debug, Serialize)]
struct HoneWeakness {
    name: String,
}

#[derive(Debug, Serialize)]
struct HoneScope {
    asset_identifier: String,
    asset_type: String,
}
