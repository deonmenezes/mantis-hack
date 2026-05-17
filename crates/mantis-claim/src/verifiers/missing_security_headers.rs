//! Verifier for `info-disclosure.missing-security-headers`.
//!
//! Independent of the primitive: re-issues a GET to the surface URL
//! and checks that every header named in the claim's evidence is
//! still absent in the new response. Any change in the response (a
//! previously-missing header is now present, or the host became
//! unreachable) downgrades the claim.

use async_trait::async_trait;
use reqwest::Client;

use crate::error::ClaimError;
use crate::verifier::Verifier;
use crate::{Claim, ClaimState};

pub struct MissingSecurityHeadersVerifier;

#[async_trait]
impl Verifier for MissingSecurityHeadersVerifier {
    fn id(&self) -> &'static str {
        "verifier.info-disclosure.missing-security-headers"
    }

    fn vuln_class(&self) -> &'static str {
        "info-disclosure"
    }

    async fn verify(&self, claim: &Claim, client: &Client) -> Result<ClaimState, ClaimError> {
        if claim.primitive_id != "info-disclosure.missing-security-headers" {
            return Err(ClaimError::Malformed(format!(
                "verifier dispatched for wrong primitive id: {}",
                claim.primitive_id
            )));
        }
        let url = claim.surface.url();
        let response = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                return Ok(ClaimState::Retained {
                    reason: format!("network error: {e}"),
                });
            }
        };
        let headers = response.headers();
        let mut still_missing: Vec<&str> = vec![];
        let mut now_present: Vec<&str> = vec![];
        for ev in &claim.evidence {
            if ev.kind != "missing-header" {
                continue;
            }
            if headers.contains_key(ev.detail.as_str()) {
                now_present.push(&ev.detail);
            } else {
                still_missing.push(&ev.detail);
            }
        }
        if !now_present.is_empty() {
            return Ok(ClaimState::Rejected {
                reason: format!(
                    "{} header(s) now present that were missing in the primitive: {}",
                    now_present.len(),
                    now_present.join(", ")
                ),
            });
        }
        if still_missing.is_empty() {
            return Ok(ClaimState::Rejected {
                reason: "claim carried no missing-header evidence to verify".into(),
            });
        }
        Ok(ClaimState::Verified {
            verifier_id: self.id().to_string(),
        })
    }
}
