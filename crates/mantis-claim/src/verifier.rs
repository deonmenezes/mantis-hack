//! Verifier dispatch.
//!
//! [`verify_claim`] selects a per-vuln-class [`Verifier`] from the
//! catalog and runs it against the claim. The verifier receives
//! only the [`Claim`] (which carries the reproducer and evidence
//! summary). It does not see the primitive that produced the claim.

use async_trait::async_trait;
use reqwest::Client;

use crate::error::ClaimError;
use crate::verifiers::cors_wildcard::CorsWildcardVerifier;
use crate::verifiers::missing_security_headers::MissingSecurityHeadersVerifier;
use crate::verifiers::open_redirect::OpenRedirectVerifier;
use crate::{Claim, ClaimState};

/// Trait every per-vuln-class verifier implements.
#[async_trait]
pub trait Verifier: Send + Sync {
    fn id(&self) -> &'static str;
    fn vuln_class(&self) -> &'static str;
    async fn verify(&self, claim: &Claim, client: &Client) -> Result<ClaimState, ClaimError>;
}

/// Run the appropriate verifier for `claim` and return the new
/// state. The returned state replaces the claim's current state.
pub async fn verify_claim(claim: &Claim, client: &Client) -> Result<ClaimState, ClaimError> {
    let verifier: Box<dyn Verifier> = match claim.vuln_class.as_str() {
        "info-disclosure" => Box::new(MissingSecurityHeadersVerifier),
        "open-redirect" => Box::new(OpenRedirectVerifier),
        "cors-misconfig" => Box::new(CorsWildcardVerifier),
        other => return Err(ClaimError::NoVerifier(other.to_string())),
    };
    verifier.verify(claim, client).await
}
