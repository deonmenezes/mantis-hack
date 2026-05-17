//! Markdown report integration tests.

#![allow(clippy::unwrap_used)]

use mantis_claim::{Claim, ClaimState, SurfaceSnapshot};
use mantis_primitive::{EvidenceItem, Reproducer};
use mantis_report::{ProofBundle, Report, ReportMetadata};

fn sample_claim(
    primitive_id: &str,
    vuln_class: &str,
    state: ClaimState,
    evidence_count: usize,
) -> Claim {
    let evidence = (0..evidence_count)
        .map(|i| EvidenceItem {
            kind: "missing-header".into(),
            detail: format!("header-{i}"),
        })
        .collect();
    Claim {
        primitive_id: primitive_id.into(),
        vuln_class: vuln_class.into(),
        surface: SurfaceSnapshot {
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: 443,
            path: "/v1/users".into(),
            status: 200,
        },
        evidence,
        reproducer: Reproducer::from_curl_and_raw(
            "curl https://api.example.com/v1/users",
            "GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        ),
        state,
    }
}

fn sample_metadata() -> ReportMetadata {
    ReportMetadata {
        engagement_id: "01HXXXXXX".into(),
        engagement_name: "demo".into(),
        operator_name: Some("alice".into()),
        generated_at_unix: 1_700_000_000,
        workspace_fingerprint: Some("deadbeefcafebabe".into()),
    }
}

#[test]
fn empty_report_renders_no_findings_section() {
    let report = Report::new(sample_metadata(), &[]);
    let md = report.to_markdown();
    assert!(md.contains("# Mantis Engagement Report"));
    assert!(md.contains("**Verified findings:** 0"));
    assert!(md.contains("_No verified findings in this engagement._"));
    assert!(!md.contains("## Appendix"));
}

#[test]
fn single_verified_claim_appears_in_findings() {
    let claims = vec![sample_claim(
        "info-disclosure.missing-security-headers",
        "info-disclosure",
        ClaimState::Verified {
            verifier_id: "v.test".into(),
        },
        4,
    )];
    let report = Report::new(sample_metadata(), &claims);
    let md = report.to_markdown();
    assert!(md.contains("### Finding 1:"));
    assert!(md.contains("info-disclosure"));
    assert!(md.contains("Severity:** Low"));
    assert!(md.contains("Verified by:** `v.test`"));
    assert!(md.contains("```bash"));
    assert!(md.contains("```http"));
    // All four evidence items must appear.
    for i in 0..4 {
        assert!(md.contains(&format!("header-{i}")));
    }
}

#[test]
fn findings_ordered_by_severity_descending() {
    let claims = vec![
        sample_claim(
            "info-disclosure.x",
            "info-disclosure",
            ClaimState::Verified {
                verifier_id: "v".into(),
            },
            1,
        ),
        sample_claim(
            "sqli.union-select",
            "sqli",
            ClaimState::Verified {
                verifier_id: "v".into(),
            },
            1,
        ),
        sample_claim(
            "idor.numeric",
            "idor",
            ClaimState::Verified {
                verifier_id: "v".into(),
            },
            1,
        ),
    ];
    let report = Report::new(sample_metadata(), &claims);
    let md = report.to_markdown();
    let sqli_pos = md.find("`sqli`").unwrap();
    let idor_pos = md.find("`idor`").unwrap();
    let info_pos = md.find("`info-disclosure`").unwrap();
    // Critical (sqli) must appear before High (idor) before Low (info).
    assert!(sqli_pos < idor_pos);
    assert!(idor_pos < info_pos);
}

#[test]
fn rejected_and_retained_appear_in_appendix() {
    let claims = vec![
        sample_claim(
            "p.verified",
            "info-disclosure",
            ClaimState::Verified {
                verifier_id: "v".into(),
            },
            1,
        ),
        sample_claim(
            "p.rejected",
            "info-disclosure",
            ClaimState::Rejected {
                reason: "header now present".into(),
            },
            1,
        ),
        sample_claim(
            "p.retained",
            "info-disclosure",
            ClaimState::Retained {
                reason: "timeout".into(),
            },
            1,
        ),
    ];
    let report = Report::new(sample_metadata(), &claims);
    let md = report.to_markdown();
    assert!(md.contains("## Appendix"));
    assert!(md.contains("Rejected by verifier (1)"));
    assert!(md.contains("Retained (verifier inconclusive, 1)"));
    assert!(md.contains("header now present"));
    assert!(md.contains("timeout"));
    // Verified claim appears in findings, NOT appendix.
    assert!(md.contains("### Finding 1:"));
}

#[test]
fn pending_claims_are_omitted() {
    let claims = vec![sample_claim(
        "p.pending",
        "info-disclosure",
        ClaimState::Pending,
        1,
    )];
    let report = Report::new(sample_metadata(), &claims);
    let md = report.to_markdown();
    assert!(md.contains("**Verified findings:** 0"));
    assert!(!md.contains("p.pending"));
}

#[test]
fn metadata_renders_in_header() {
    let report = Report::new(sample_metadata(), &[]);
    let md = report.to_markdown();
    assert!(md.contains("`01HXXXXXX`"));
    assert!(md.contains("**Name:** demo"));
    assert!(md.contains("**Operator:** alice"));
    assert!(md.contains("`deadbeefcafebabe`"));
}

#[test]
fn proofs_appendix_renders_when_proofs_supplied() {
    let proofs = vec![ProofBundle {
        claim_ref: "info-disclosure.missing-security-headers".into(),
        workspace_public_key_hex: "deadbeef".repeat(8),
        proof_json: r#"{"leaf_index":3,"leaf_count":12}"#.into(),
    }];
    let claims = vec![];
    let report = Report::new(sample_metadata(), &claims).with_proofs(&proofs);
    let md = report.to_markdown();
    assert!(md.contains("## Appendix: Merkle inclusion proofs"));
    assert!(md.contains("mantis-verify --proof"));
    assert!(md.contains("info-disclosure.missing-security-headers"));
    assert!(md.contains(&"deadbeef".repeat(8)));
    // JSON pretty-printed inside fence
    assert!(md.contains("\"leaf_index\": 3"));
    assert!(md.contains("\"leaf_count\": 12"));
}

#[test]
fn proofs_appendix_absent_when_no_proofs() {
    let report = Report::new(sample_metadata(), &[]);
    let md = report.to_markdown();
    assert!(!md.contains("Merkle inclusion proofs"));
}

#[test]
fn proofs_appendix_handles_malformed_json_gracefully() {
    let proofs = vec![ProofBundle {
        claim_ref: "test".into(),
        workspace_public_key_hex: "00".repeat(32),
        proof_json: "not valid json {{{".into(),
    }];
    let claims = vec![];
    let report = Report::new(sample_metadata(), &claims).with_proofs(&proofs);
    let md = report.to_markdown();
    // The malformed string falls through; we don't crash.
    assert!(md.contains("Merkle inclusion proofs"));
    assert!(md.contains("not valid json"));
}

#[test]
fn hackerone_json_contains_finding_envelope() {
    let claims = vec![sample_claim(
        "sqli.error-based",
        "sqli",
        ClaimState::Verified {
            verifier_id: "v".into(),
        },
        2,
    )];
    let report = Report::new(sample_metadata(), &claims);
    let json = report.to_hackerone_json();
    assert!(json.contains("\"program\""));
    assert!(json.contains("\"findings\""));
    assert!(json.contains("\"severity\""));
    assert!(json.contains("\"critical\"")); // sqli → Critical
    assert!(json.contains("\"weakness\""));
    assert!(json.contains("\"proof_of_concept\""));
    assert!(json.contains("\"asset_identifier\""));
}

#[test]
fn bugcrowd_json_contains_vrt_id() {
    let claims = vec![sample_claim(
        "idor.numeric-id-enumeration",
        "idor",
        ClaimState::Verified {
            verifier_id: "v".into(),
        },
        1,
    )];
    let report = Report::new(sample_metadata(), &claims);
    let json = report.to_bugcrowd_json();
    assert!(json.contains("\"vrt_id\""));
    assert!(json.contains("broken_access_control.idor"));
    assert!(json.contains("\"severity\": 2")); // High = 2
    assert!(json.contains("\"submissions\""));
}

#[test]
fn sarif_uses_v2_1_0_schema() {
    let claims = vec![sample_claim(
        "xss-reflected.query-param-mirror",
        "xss-reflected",
        ClaimState::Verified {
            verifier_id: "v".into(),
        },
        1,
    )];
    let report = Report::new(sample_metadata(), &claims);
    let sarif = report.to_sarif();
    assert!(sarif.contains("\"version\": \"2.1.0\""));
    assert!(sarif.contains("\"$schema\""));
    assert!(sarif.contains("\"runs\""));
    assert!(sarif.contains("\"Mantis\""));
    assert!(sarif.contains("\"ruleId\""));
    assert!(sarif.contains("\"level\": \"warning\"")); // xss-reflected = Medium → warning
    assert!(sarif.contains("xss-reflected.query-param-mirror"));
}

#[test]
fn rejected_claims_omitted_from_all_formats() {
    let claims = vec![sample_claim(
        "sqli.error-based",
        "sqli",
        ClaimState::Rejected { reason: "x".into() },
        1,
    )];
    let report = Report::new(sample_metadata(), &claims);
    let h1 = report.to_hackerone_json();
    let bc = report.to_bugcrowd_json();
    let sarif = report.to_sarif();
    assert!(!h1.contains("sqli.error-based"));
    assert!(!bc.contains("sqli.error-based"));
    assert!(!sarif.contains("sqli.error-based"));
}
