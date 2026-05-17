//! SARIF v2.1.0 report.
//!
//! Static Analysis Results Interchange Format — the standard
//! interchange for security findings consumed by GitHub Code
//! Scanning, Azure DevOps, IDE integrations, and most other
//! security-tooling sinks.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::Report;
use mantis_claim::{Claim, ClaimState};

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0-rtm.6.json";
const VERSION: &str = "2.1.0";

pub fn render(report: &Report<'_>) -> String {
    let verified: Vec<&Claim> = report
        .claims
        .iter()
        .filter(|c| matches!(c.state, ClaimState::Verified { .. }))
        .collect();

    // Distinct primitive IDs become the rules section.
    let rule_ids: BTreeSet<String> = verified.iter().map(|c| c.primitive_id.clone()).collect();
    let rules: Vec<SarifRule> = rule_ids
        .into_iter()
        .map(|id| SarifRule {
            id: id.clone(),
            name: id.split('.').next_back().unwrap_or(&id).to_owned(),
            short_description: SarifText {
                text: format!("Mantis primitive: {id}"),
            },
            default_configuration: SarifConfig {
                level: "warning".into(),
            },
        })
        .collect();

    let results: Vec<SarifResult> = verified
        .iter()
        .map(|c| SarifResult {
            rule_id: c.primitive_id.clone(),
            level: sarif_level(crate::severity::severity_for(&c.vuln_class)),
            message: SarifText {
                text: format!(
                    "{}: {}",
                    crate::pretty_class(&c.vuln_class),
                    c.evidence
                        .iter()
                        .map(|e| format!("{}={}", e.kind, e.detail))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: c.surface.url(),
                    },
                },
            }],
        })
        .collect();

    let envelope = SarifEnvelope {
        schema: SCHEMA.into(),
        version: VERSION.into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Mantis".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    information_uri: "https://github.com/deonmenezes/mantishack".into(),
                    rules,
                },
            },
            results,
        }],
    };
    serde_json::to_string_pretty(&envelope).unwrap_or_else(|_| "{}".to_owned())
}

fn sarif_level(s: crate::Severity) -> String {
    match s {
        crate::Severity::Critical | crate::Severity::High => "error".into(),
        crate::Severity::Medium | crate::Severity::Low => "warning".into(),
        crate::Severity::Informational => "note".into(),
    }
}

#[derive(Debug, Serialize)]
struct SarifEnvelope {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifText,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifConfig,
}

#[derive(Debug, Serialize)]
struct SarifConfig {
    level: String,
}

#[derive(Debug, Serialize)]
struct SarifText {
    text: String,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifText,
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}
