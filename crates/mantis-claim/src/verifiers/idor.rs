//! Verifier for `idor.numeric-id-enumeration`.
//!
//! Independent reproduction: pick a *third* candidate ID (different
//! from both the primitive's original and candidate) and confirm it
//! still returns content materially different from the baseline.
//! Two-axis independence — the verifier uses its own ID and rechecks
//! the divergence claim from scratch.

use async_trait::async_trait;
use reqwest::Client;

use crate::error::ClaimError;
use crate::verifier::Verifier;
use crate::{Claim, ClaimState};

pub struct IdorVerifier;

#[async_trait]
impl Verifier for IdorVerifier {
    fn id(&self) -> &'static str {
        "verifier.idor.numeric-id-enumeration"
    }

    fn vuln_class(&self) -> &'static str {
        "idor"
    }

    async fn verify(&self, claim: &Claim, _client: &Client) -> Result<ClaimState, ClaimError> {
        if claim.primitive_id != "idor.numeric-id-enumeration" {
            return Err(ClaimError::Malformed(format!(
                "verifier dispatched for wrong primitive id: {}",
                claim.primitive_id
            )));
        }
        let original_id = claim
            .evidence
            .iter()
            .find(|e| e.kind == "original-id")
            .map(|e| e.detail.clone())
            .ok_or_else(|| ClaimError::Malformed("missing original-id evidence".into()))?;
        let candidate_from_primitive = claim
            .evidence
            .iter()
            .find(|e| e.kind == "candidate-id")
            .map(|e| e.detail.clone())
            .ok_or_else(|| ClaimError::Malformed("missing candidate-id evidence".into()))?;

        // Pick a third ID different from both.
        let verifier_candidate = pick_third_id(&original_id, &candidate_from_primitive);

        let path = &claim.surface.path;
        let prefix = path.trim_end_matches('/');
        let prefix = &prefix[..prefix.rfind('/').map(|i| i + 1).unwrap_or(0)];
        let scheme = &claim.surface.scheme;
        let host = &claim.surface.host;
        let port = claim.surface.port;

        let baseline_url = claim.surface.url();
        let verify_url = format!("{scheme}://{host}:{port}{prefix}{verifier_candidate}");

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(ClaimError::Http)?;

        let baseline = match fetch(&client, &baseline_url).await {
            Some(b) => b,
            None => {
                return Ok(ClaimState::Retained {
                    reason: "could not fetch baseline".into(),
                });
            }
        };
        let candidate = match fetch(&client, &verify_url).await {
            Some(c) => c,
            None => {
                return Ok(ClaimState::Retained {
                    reason: format!("could not fetch verifier candidate {verify_url}"),
                });
            }
        };
        let materially_different = baseline.status == 200
            && candidate.status == 200
            && !baseline.body.is_empty()
            && !candidate.body.is_empty()
            && baseline.body != candidate.body;

        if materially_different {
            Ok(ClaimState::Verified {
                verifier_id: self.id().to_string(),
            })
        } else {
            Ok(ClaimState::Rejected {
                reason: format!(
                    "verifier's third candidate ({verifier_candidate}) did not reproduce divergence: statuses {}/{} lengths {}/{}",
                    baseline.status,
                    candidate.status,
                    baseline.body.len(),
                    candidate.body.len()
                ),
            })
        }
    }
}

fn pick_third_id(a: &str, b: &str) -> String {
    for candidate in ["3", "10", "100", "999"] {
        if candidate != a && candidate != b {
            return candidate.into();
        }
    }
    "42".into()
}

struct Fetched {
    status: u16,
    body: String,
}

async fn fetch(client: &Client, url: &str) -> Option<Fetched> {
    let response = client.get(url).send().await.ok()?;
    let status = response.status().as_u16();
    let body = response.text().await.ok()?;
    Some(Fetched { status, body })
}
