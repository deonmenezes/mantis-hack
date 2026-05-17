//! Verifier for `xss-reflected.query-param-mirror`.
//!
//! Independent reproduction: re-issues the probe with a *new*
//! canary (different from the one the primitive captured). If the
//! new canary appears in the response body, reflection is
//! confirmed. A primitive that observed a coincidental matching
//! string would fail this re-check.

use async_trait::async_trait;
use rand::RngCore;
use reqwest::Client;

use crate::error::ClaimError;
use crate::verifier::Verifier;
use crate::{Claim, ClaimState};

pub struct XssReflectedVerifier;

#[async_trait]
impl Verifier for XssReflectedVerifier {
    fn id(&self) -> &'static str {
        "verifier.xss-reflected.query-param-mirror"
    }

    fn vuln_class(&self) -> &'static str {
        "xss-reflected"
    }

    async fn verify(&self, claim: &Claim, _client: &Client) -> Result<ClaimState, ClaimError> {
        if claim.primitive_id != "xss-reflected.query-param-mirror" {
            return Err(ClaimError::Malformed(format!(
                "verifier dispatched for wrong primitive id: {}",
                claim.primitive_id
            )));
        }
        let param = claim
            .evidence
            .iter()
            .find(|e| e.kind == "reflected-param")
            .map(|e| e.detail.clone())
            .ok_or_else(|| ClaimError::Malformed("missing reflected-param evidence".into()))?;

        let canary = make_verifier_canary();
        let url = format!(
            "{}://{}:{}{}?{param}={canary}",
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
        if !response.status().is_success() {
            return Ok(ClaimState::Rejected {
                reason: format!(
                    "verifier got status {} on reflected-param {param}",
                    response.status()
                ),
            });
        }
        let body = match response.text().await {
            Ok(b) => b,
            Err(e) => {
                return Ok(ClaimState::Retained {
                    reason: format!("read body: {e}"),
                });
            }
        };
        if body.contains(&canary) {
            Ok(ClaimState::Verified {
                verifier_id: self.id().to_string(),
            })
        } else {
            Ok(ClaimState::Rejected {
                reason: format!(
                    "verifier canary {canary:.32} did not appear in response body on param {param}"
                ),
            })
        }
    }
}

fn make_verifier_canary() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("MANTISVERIFYXSS{}", hex::encode(bytes))
}
