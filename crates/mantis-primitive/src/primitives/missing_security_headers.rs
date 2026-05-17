//! Detects absence of standard HTTP security headers.
//!
//! Checks for: Strict-Transport-Security (HSTS),
//! Content-Security-Policy (CSP), X-Frame-Options (XFO),
//! X-Content-Type-Options (XCTO). A response missing any of these is
//! a low-severity finding most disclosure programs accept.

use async_trait::async_trait;
use mantis_scanner_http::Surface;
use reqwest::Client;

use crate::reproducer::Reproducer;
use crate::{EvidenceItem, Primitive, PrimitiveError, PrimitiveResult};

const CHECKED_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
];

pub struct MissingSecurityHeaders;

#[async_trait]
impl Primitive for MissingSecurityHeaders {
    fn id(&self) -> &'static str {
        "info-disclosure.missing-security-headers"
    }

    fn vuln_class(&self) -> &'static str {
        "info-disclosure"
    }

    fn matches_surface(&self, surface: &Surface) -> bool {
        // Successful response that returned content. Errors and
        // redirects are skipped because the headers are often
        // intentionally minimal on those.
        (200..400).contains(&surface.status)
    }

    async fn execute(
        &self,
        surface: &Surface,
        client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let response = client.get(surface.target.url()).send().await?;
        let headers = response.headers();

        let mut missing: Vec<&'static str> = vec![];
        for name in CHECKED_HEADERS {
            if !headers.contains_key(*name) {
                missing.push(name);
            }
        }

        if missing.is_empty() {
            return Ok(PrimitiveResult::Denied {
                reason: "all four checked security headers present".into(),
            });
        }

        let evidence: Vec<EvidenceItem> = missing
            .iter()
            .map(|h| EvidenceItem {
                kind: "missing-header".into(),
                detail: (*h).to_string(),
            })
            .collect();

        let curl = format!("curl -sI {} | grep -iE 'strict-transport-security|content-security-policy|x-frame-options|x-content-type-options' || echo MISSING-HEADERS", surface.target.url());
        let raw_http = format!(
            "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: mantis/0\r\nConnection: close\r\n\r\n",
            surface.target.path, surface.target.host
        );
        Ok(PrimitiveResult::Confirmed {
            evidence,
            reproducer: Reproducer::from_curl_and_raw(curl, raw_http),
        })
    }
}
