//! Exploit primitives.
//!
//! A [`Primitive`] takes a discovered [`Surface`] and runs a single
//! targeted check against it, returning a [`PrimitiveResult`] that is
//! one of:
//!
//! - [`PrimitiveResult::Confirmed`] — the issue is present, with
//!   evidence and a reproducer.
//! - [`PrimitiveResult::Denied`] — the check explicitly rules the
//!   issue out.
//! - [`PrimitiveResult::Inconclusive`] — the check could not decide,
//!   with a reason (network failure, unexpected response shape).
//!
//! Every primitive must produce a [`Reproducer`] when the verdict is
//! Confirmed. The reproducer is the artifact the operator hands to a
//! disclosure program. Currently the reproducer ships in two
//! dialects (cURL one-liner + raw HTTP); Phase 1 will add Python,
//! Burp/Caido, and Rust dialects per PRD §5.7.10.

pub mod error;
pub mod primitives;
pub mod reproducer;

pub use crate::error::PrimitiveError;
pub use crate::primitives::cors_wildcard::CorsWildcard;
pub use crate::primitives::idor::Idor;
pub use crate::primitives::missing_security_headers::MissingSecurityHeaders;
pub use crate::primitives::open_redirect::OpenRedirect;
pub use crate::primitives::sqli_error::SqliErrorBased;
pub use crate::primitives::xss_reflected::XssReflected;
pub use crate::reproducer::Reproducer;

use async_trait::async_trait;
use mantis_scanner_http::Surface;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Trait every exploit primitive implements.
#[async_trait]
pub trait Primitive: Send + Sync {
    /// Globally unique identifier (`vuln_class.specific-name`).
    fn id(&self) -> &'static str;

    /// Broad vulnerability class this primitive targets.
    fn vuln_class(&self) -> &'static str;

    /// Cheap pre-check that decides whether this primitive applies to
    /// the surface. Should not do I/O. The planner uses this to skip
    /// primitives that can't possibly apply.
    fn matches_surface(&self, surface: &Surface) -> bool;

    /// Run the primitive against `surface` using `client` (which is
    /// configured to route through the engagement's egress proxy).
    async fn execute(
        &self,
        surface: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError>;
}

/// One piece of evidence supporting a Confirmed verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceItem {
    /// Short tag describing the kind of evidence
    /// (e.g. `missing-header`, `reflected-payload`).
    pub kind: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Result of running a [`Primitive`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum PrimitiveResult {
    /// The issue is present. The verifier should re-run `reproducer`
    /// independently to confirm.
    Confirmed {
        evidence: Vec<EvidenceItem>,
        reproducer: Reproducer,
    },
    /// The issue is explicitly absent.
    Denied { reason: String },
    /// The primitive could not decide.
    Inconclusive { reason: String },
}

impl PrimitiveResult {
    pub fn is_confirmed(&self) -> bool {
        matches!(self, PrimitiveResult::Confirmed { .. })
    }
}
