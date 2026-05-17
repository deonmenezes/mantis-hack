//! OpenVEX (Vulnerability Exploitability eXchange) report.
//!
//! VEX statements communicate the exploitability status of a
//! product/component combination. Mantis emits one VEX statement
//! per verified claim, marking the claim's vuln_class as
//! `affected` for the engagement's target surface.

use serde::Serialize;

use crate::Report;
use mantis_claim::{Claim, ClaimState};

pub fn render(report: &Report<'_>) -> String {
    let verified: Vec<&Claim> = report
        .claims
        .iter()
        .filter(|c| matches!(c.state, ClaimState::Verified { .. }))
        .collect();

    let statements: Vec<VexStatement> = verified
        .iter()
        .map(|c| VexStatement {
            vulnerability: VexVulnerability {
                name: c.vuln_class.clone(),
                description: format!(
                    "Mantis primitive {} confirmed and independently verified",
                    c.primitive_id
                ),
            },
            timestamp_unix: report.metadata.generated_at_unix,
            products: vec![VexProduct {
                identifier: c.surface.url(),
            }],
            status: "affected".into(),
            justification: None,
        })
        .collect();

    let envelope = VexEnvelope {
        context: "https://openvex.dev/ns/v0.2.0".into(),
        id: format!("mantis-engagement-{}", report.metadata.engagement_id),
        author: report
            .metadata
            .operator_name
            .clone()
            .unwrap_or_else(|| "mantis".into()),
        version: 1,
        statements,
    };

    serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| "{}".to_owned())
}

#[derive(Debug, Serialize)]
struct VexEnvelope {
    #[serde(rename = "@context")]
    context: String,
    #[serde(rename = "@id")]
    id: String,
    author: String,
    version: u32,
    statements: Vec<VexStatement>,
}

#[derive(Debug, Serialize)]
struct VexStatement {
    vulnerability: VexVulnerability,
    timestamp_unix: u64,
    products: Vec<VexProduct>,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<String>,
}

#[derive(Debug, Serialize)]
struct VexVulnerability {
    name: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct VexProduct {
    identifier: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_claim::{ClaimState, SurfaceSnapshot};
    use mantis_primitive::{EvidenceItem, Reproducer};

    fn make_claim(state: ClaimState, vuln_class: &str) -> Claim {
        Claim {
            primitive_id: format!("{vuln_class}.example"),
            vuln_class: vuln_class.into(),
            surface: SurfaceSnapshot {
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/v1/users".into(),
                status: 200,
            },
            evidence: vec![EvidenceItem {
                kind: "marker".into(),
                detail: "x".into(),
            }],
            reproducer: Reproducer::from_curl_and_raw(
                "curl https://api.example.com/v1/users",
                "GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            ),
            state,
        }
    }

    fn metadata() -> crate::ReportMetadata {
        crate::ReportMetadata {
            engagement_id: "01HVEX".into(),
            engagement_name: "demo".into(),
            operator_name: Some("alice".into()),
            generated_at_unix: 1_700_000_000,
            workspace_fingerprint: None,
        }
    }

    #[test]
    fn envelope_emits_valid_json_with_required_fields() {
        let claims = vec![make_claim(
            ClaimState::Verified {
                verifier_id: "v.test".into(),
            },
            "info-disclosure",
        )];
        let report = Report::new(metadata(), &claims);
        let json = render(&report);
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["@context"], "https://openvex.dev/ns/v0.2.0");
        assert_eq!(value["@id"], "mantis-engagement-01HVEX");
        assert_eq!(value["author"], "alice");
        assert_eq!(value["version"], 1);
        assert!(value["statements"].is_array());
    }

    #[test]
    fn one_statement_per_verified_claim() {
        let claims = vec![
            make_claim(
                ClaimState::Verified {
                    verifier_id: "v.test".into(),
                },
                "sqli",
            ),
            make_claim(
                ClaimState::Verified {
                    verifier_id: "v.test".into(),
                },
                "xss",
            ),
        ];
        let report = Report::new(metadata(), &claims);
        let value: serde_json::Value = serde_json::from_str(&render(&report)).unwrap();
        let stmts = value["statements"].as_array().unwrap();
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn rejected_and_retained_claims_excluded() {
        let claims = vec![
            make_claim(
                ClaimState::Verified {
                    verifier_id: "v.test".into(),
                },
                "sqli",
            ),
            make_claim(
                ClaimState::Rejected {
                    reason: "no reproduction".into(),
                },
                "xss",
            ),
            make_claim(
                ClaimState::Retained {
                    reason: "inconclusive".into(),
                },
                "csrf",
            ),
        ];
        let report = Report::new(metadata(), &claims);
        let value: serde_json::Value = serde_json::from_str(&render(&report)).unwrap();
        let stmts = value["statements"].as_array().unwrap();
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0]["vulnerability"]["name"], "sqli");
        assert_eq!(stmts[0]["status"], "affected");
    }

    #[test]
    fn author_falls_back_to_mantis_when_no_operator() {
        let claims = vec![];
        let mut meta = metadata();
        meta.operator_name = None;
        let report = Report::new(meta, &claims);
        let value: serde_json::Value = serde_json::from_str(&render(&report)).unwrap();
        assert_eq!(value["author"], "mantis");
    }

    #[test]
    fn product_identifier_is_full_surface_url() {
        let claims = vec![make_claim(
            ClaimState::Verified {
                verifier_id: "v.test".into(),
            },
            "info-disclosure",
        )];
        let report = Report::new(metadata(), &claims);
        let value: serde_json::Value = serde_json::from_str(&render(&report)).unwrap();
        let id = value["statements"][0]["products"][0]["identifier"]
            .as_str()
            .unwrap();
        assert!(id.starts_with("https://api.example.com"));
        assert!(id.contains("/v1/users"));
    }
}
