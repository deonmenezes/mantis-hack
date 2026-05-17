//! Verifier for `sqli.error-based`.
//!
//! Independent reproduction: re-injects the same quote payload on
//! the same parameter and confirms a SQL-error fingerprint is still
//! present. Distinct from the primitive in that the verifier
//! short-circuits on the first known fingerprint match — it does
//! not iterate every payload type.

use async_trait::async_trait;
use reqwest::Client;

use crate::error::ClaimError;
use crate::verifier::Verifier;
use crate::{Claim, ClaimState};

const SQL_ERROR_FINGERPRINTS: &[&str] = &[
    "you have an error in your sql syntax",
    "mysql_fetch",
    "pg_query()",
    "postgresql query failed",
    "syntax error at or near",
    "ora-00933",
    "ora-00921",
    "unclosed quotation mark",
    "sqlite3.operationalerror",
    "near \"'\" syntax error",
];

pub struct SqliErrorBasedVerifier;

#[async_trait]
impl Verifier for SqliErrorBasedVerifier {
    fn id(&self) -> &'static str {
        "verifier.sqli.error-based"
    }

    fn vuln_class(&self) -> &'static str {
        "sqli"
    }

    async fn verify(&self, claim: &Claim, _client: &Client) -> Result<ClaimState, ClaimError> {
        if claim.primitive_id != "sqli.error-based" {
            return Err(ClaimError::Malformed(format!(
                "verifier dispatched for wrong primitive id: {}",
                claim.primitive_id
            )));
        }
        let param = claim
            .evidence
            .iter()
            .find(|e| e.kind == "injection-param")
            .map(|e| e.detail.clone())
            .ok_or_else(|| ClaimError::Malformed("missing injection-param evidence".into()))?;
        let payload = claim
            .evidence
            .iter()
            .find(|e| e.kind == "payload")
            .map(|e| e.detail.clone())
            .ok_or_else(|| ClaimError::Malformed("missing payload evidence".into()))?;

        let payload_enc = urlencoding(&payload);
        let url = format!(
            "{}://{}:{}{}?{param}={payload_enc}",
            claim.surface.scheme, claim.surface.host, claim.surface.port, claim.surface.path
        );

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(ClaimError::Http)?;

        let response = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                return Ok(ClaimState::Retained {
                    reason: format!("network error: {e}"),
                });
            }
        };
        let body = match response.text().await {
            Ok(b) => b.to_ascii_lowercase(),
            Err(e) => {
                return Ok(ClaimState::Retained {
                    reason: format!("read body: {e}"),
                });
            }
        };
        if SQL_ERROR_FINGERPRINTS.iter().any(|fp| body.contains(fp)) {
            Ok(ClaimState::Verified {
                verifier_id: self.id().to_string(),
            })
        } else {
            Ok(ClaimState::Rejected {
                reason: format!(
                    "verifier saw no SQL-error fingerprint on param {param} with payload {payload:?}"
                ),
            })
        }
    }
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            out.push(c);
        } else {
            for b in c.to_string().bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}
