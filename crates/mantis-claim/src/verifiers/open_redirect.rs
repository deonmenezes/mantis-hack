//! Verifier for `open-redirect.query-param`.
//!
//! Re-issues the redirect-param probe and confirms the response
//! still 3xx-redirects to a host the verifier provides. Uses a
//! distinct attacker-host placeholder so the verifier is genuinely
//! independent of the primitive's payload.

use async_trait::async_trait;
use reqwest::redirect::Policy;
use reqwest::Client;

use crate::error::ClaimError;
use crate::verifier::Verifier;
use crate::{Claim, ClaimState};

const VERIFIER_HOST: &str = "mantis-verify.example";

pub struct OpenRedirectVerifier;

#[async_trait]
impl Verifier for OpenRedirectVerifier {
    fn id(&self) -> &'static str {
        "verifier.open-redirect.query-param"
    }

    fn vuln_class(&self) -> &'static str {
        "open-redirect"
    }

    async fn verify(&self, claim: &Claim, _client: &Client) -> Result<ClaimState, ClaimError> {
        if claim.primitive_id != "open-redirect.query-param" {
            return Err(ClaimError::Malformed(format!(
                "verifier dispatched for wrong primitive id: {}",
                claim.primitive_id
            )));
        }
        let param = claim
            .evidence
            .iter()
            .find(|e| e.kind == "redirect-param")
            .map(|e| e.detail.clone())
            .ok_or_else(|| ClaimError::Malformed("missing redirect-param evidence".into()))?;

        // Build our own client with a different attacker-host
        // placeholder so we don't just replay the primitive's bytes.
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(ClaimError::Http)?;

        let url = format!(
            "{}://{}:{}{}?{param}=https://{VERIFIER_HOST}/",
            claim.surface.scheme, claim.surface.host, claim.surface.port, claim.surface.path
        );
        let response = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                return Ok(ClaimState::Retained {
                    reason: format!("network error: {e}"),
                });
            }
        };
        if !response.status().is_redirection() {
            return Ok(ClaimState::Rejected {
                reason: format!(
                    "verifier received {} on {param}; primitive saw a redirect",
                    response.status()
                ),
            });
        }
        let Some(location) = response.headers().get(reqwest::header::LOCATION) else {
            return Ok(ClaimState::Rejected {
                reason: "redirect response missing Location header".into(),
            });
        };
        let location_str = match location.to_str() {
            Ok(s) => s,
            Err(_) => {
                return Ok(ClaimState::Rejected {
                    reason: "Location header not valid UTF-8".into(),
                });
            }
        };
        if !location_str.contains(VERIFIER_HOST) {
            return Ok(ClaimState::Rejected {
                reason: format!(
                    "Location {location_str:?} did not reflect verifier host {VERIFIER_HOST}"
                ),
            });
        }
        Ok(ClaimState::Verified {
            verifier_id: self.id().to_string(),
        })
    }
}
