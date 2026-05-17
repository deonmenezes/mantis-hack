//! Verifier for `cors.reflect-with-credentials`.
//!
//! Independent of the primitive: re-issues the request with a
//! different attacker-origin placeholder and confirms the response
//! still reflects it back. The primitive used
//! `https://mantis-cors-probe.example`; the verifier uses
//! `https://mantis-cors-verify.example` so a match proves the
//! server actually reflects arbitrary origins rather than echoing a
//! hardcoded value.

use async_trait::async_trait;
use reqwest::Client;

use crate::error::ClaimError;
use crate::verifier::Verifier;
use crate::{Claim, ClaimState};

const VERIFIER_ORIGIN: &str = "https://mantis-cors-verify.example";

pub struct CorsWildcardVerifier;

#[async_trait]
impl Verifier for CorsWildcardVerifier {
    fn id(&self) -> &'static str {
        "verifier.cors.reflect-with-credentials"
    }

    fn vuln_class(&self) -> &'static str {
        "cors-misconfig"
    }

    async fn verify(&self, claim: &Claim, _client: &Client) -> Result<ClaimState, ClaimError> {
        if claim.primitive_id != "cors.reflect-with-credentials" {
            return Err(ClaimError::Malformed(format!(
                "verifier dispatched for wrong primitive id: {}",
                claim.primitive_id
            )));
        }
        let pattern = claim
            .evidence
            .iter()
            .find(|e| e.kind == "cors-pattern")
            .map(|e| e.detail.clone())
            .ok_or_else(|| ClaimError::Malformed("missing cors-pattern evidence".into()))?;

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(ClaimError::Http)?;

        let origin_to_send = if pattern == "null-origin" {
            "null".to_string()
        } else {
            VERIFIER_ORIGIN.to_string()
        };
        let url = claim.surface.url();
        let response = match client
            .get(&url)
            .header("Origin", &origin_to_send)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return Ok(ClaimState::Retained {
                    reason: format!("network error: {e}"),
                });
            }
        };
        let allow_origin = response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let allow_credentials = response
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        match (pattern.as_str(), allow_origin) {
            ("reflected", Some(ref o)) if o == VERIFIER_ORIGIN && allow_credentials => {
                Ok(ClaimState::Verified {
                    verifier_id: self.id().to_string(),
                })
            }
            ("null-origin", Some(ref o)) if o == "null" => Ok(ClaimState::Verified {
                verifier_id: self.id().to_string(),
            }),
            (_, Some(o)) => Ok(ClaimState::Rejected {
                reason: format!(
                    "verifier saw access-control-allow-origin={o:?}; primitive claimed pattern {pattern}"
                ),
            }),
            (_, None) => Ok(ClaimState::Rejected {
                reason: "verifier saw no access-control-allow-origin header".into(),
            }),
        }
    }
}
