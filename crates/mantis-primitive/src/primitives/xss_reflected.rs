//! Reflected XSS primitive.
//!
//! Injects a randomized canary into common query parameters. If the
//! canary appears verbatim in an HTML response body, the endpoint
//! likely reflects user-controlled input without escaping — a
//! reflected-XSS candidate.
//!
//! The canary is randomized per probe so two scans don't collide.
//! The pattern is intentionally rare (`MANTISXSS<32-hex>`) to keep
//! false-positive matches against natural prose negligible.

use async_trait::async_trait;
use mantis_scanner_http::Surface;
use rand::RngCore;
use reqwest::Client;

use crate::reproducer::Reproducer;
use crate::{EvidenceItem, Primitive, PrimitiveError, PrimitiveResult};

const XSS_PARAMS: &[&str] = &[
    "q", "query", "search", "s", "name", "user", "msg", "text", "input",
];

pub struct XssReflected;

#[async_trait]
impl Primitive for XssReflected {
    fn id(&self) -> &'static str {
        "xss-reflected.query-param-mirror"
    }

    fn vuln_class(&self) -> &'static str {
        "xss-reflected"
    }

    fn matches_surface(&self, surface: &Surface) -> bool {
        if !(200..400).contains(&surface.status) {
            return false;
        }
        surface.tech_hints.iter().any(|h| h == "content:html")
    }

    async fn execute(
        &self,
        surface: &Surface,
        _client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(PrimitiveError::Http)?;

        let canary = make_canary();
        for param in XSS_PARAMS {
            let url = format!(
                "{}://{}:{}{}?{param}={canary}",
                surface.target.scheme,
                surface.target.host,
                surface.target.port,
                surface.target.path
            );
            let Ok(response) = client.get(&url).send().await else {
                continue;
            };
            if !response.status().is_success() {
                continue;
            }
            let Ok(body) = response.text().await else {
                continue;
            };
            if !body.contains(&canary) {
                continue;
            }
            let evidence = vec![
                EvidenceItem {
                    kind: "reflected-param".into(),
                    detail: (*param).into(),
                },
                EvidenceItem {
                    kind: "canary".into(),
                    detail: canary.clone(),
                },
            ];
            let curl = format!(
                "curl -s '{url}' | grep -F '{canary}'  # if canary appears, parameter is reflected"
            );
            let raw_http = format!(
                "GET {}?{param}={canary} HTTP/1.1\r\nHost: {}\r\nUser-Agent: mantis/0\r\nConnection: close\r\n\r\n",
                surface.target.path, surface.target.host
            );
            return Ok(PrimitiveResult::Confirmed {
                evidence,
                reproducer: Reproducer::from_curl_and_raw(curl, raw_http),
            });
        }
        Ok(PrimitiveResult::Denied {
            reason: "no probed parameter reflected the canary into the response body".into(),
        })
    }
}

fn make_canary() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("MANTISXSS{}", hex::encode(bytes))
}
