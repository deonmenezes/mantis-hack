//! CORS misconfiguration primitive.
//!
//! Detects two browser-exploitable patterns:
//!
//! 1. `Access-Control-Allow-Origin` reflects the attacker's Origin AND
//!    `Access-Control-Allow-Credentials: true` is present. This is
//!    the dangerous case — the browser will send the victim's cookies
//!    to an attacker-controlled page that fetches the endpoint.
//! 2. `Access-Control-Allow-Origin: null`. Apps that accept the
//!    literal "null" origin can be exploited from a sandboxed iframe
//!    (the `null` origin is what the browser sends from
//!    sandbox-attribute iframes and some redirects).
//!
//! The case `Access-Control-Allow-Origin: *` plus
//! `Access-Control-Allow-Credentials: true` is browser-rejected by
//! spec, so we don't flag it as exploitable.

use async_trait::async_trait;
use mantis_scanner_http::Surface;
use reqwest::header::HeaderValue;
use reqwest::Client;

use crate::reproducer::Reproducer;
use crate::{EvidenceItem, Primitive, PrimitiveError, PrimitiveResult};

const ATTACKER_ORIGIN: &str = "https://mantis-cors-probe.example";

pub struct CorsWildcard;

#[async_trait]
impl Primitive for CorsWildcard {
    fn id(&self) -> &'static str {
        "cors.reflect-with-credentials"
    }

    fn vuln_class(&self) -> &'static str {
        "cors-misconfig"
    }

    fn matches_surface(&self, surface: &Surface) -> bool {
        if !(200..400).contains(&surface.status) {
            return false;
        }
        // JSON APIs are the highest-value CORS targets.
        if surface.tech_hints.iter().any(|h| h == "content:json") {
            return true;
        }
        let lower = surface.target.path.to_ascii_lowercase();
        lower.contains("/api/") || lower.starts_with("/api")
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

        // Probe 1: reflected origin + credentials.
        let response = client
            .get(surface.target.url())
            .header("Origin", ATTACKER_ORIGIN)
            .send()
            .await?;
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

        if let Some(origin) = &allow_origin {
            if origin == ATTACKER_ORIGIN && allow_credentials {
                return confirmed(surface, "reflected", origin, true);
            }
        }

        // Probe 2: null origin.
        let response = client
            .get(surface.target.url())
            .header("Origin", HeaderValue::from_static("null"))
            .send()
            .await?;
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

        if let Some(origin) = &allow_origin {
            if origin == "null" {
                return confirmed(surface, "null-origin", origin, allow_credentials);
            }
        }

        Ok(PrimitiveResult::Denied {
            reason: "neither reflected-origin nor null-origin CORS misconfiguration observed"
                .into(),
        })
    }
}

fn confirmed(
    surface: &Surface,
    pattern: &str,
    origin: &str,
    credentials: bool,
) -> Result<PrimitiveResult, PrimitiveError> {
    let mut evidence = vec![
        EvidenceItem {
            kind: "cors-pattern".into(),
            detail: pattern.into(),
        },
        EvidenceItem {
            kind: "access-control-allow-origin".into(),
            detail: origin.into(),
        },
    ];
    if credentials {
        evidence.push(EvidenceItem {
            kind: "access-control-allow-credentials".into(),
            detail: "true".into(),
        });
    }
    let curl = match pattern {
        "reflected" => format!(
            "curl -sI -H 'Origin: {ATTACKER_ORIGIN}' {} | grep -i 'access-control-'",
            surface.target.url()
        ),
        _ => format!(
            "curl -sI -H 'Origin: null' {} | grep -i 'access-control-'",
            surface.target.url()
        ),
    };
    let origin_hdr = if pattern == "reflected" {
        ATTACKER_ORIGIN
    } else {
        "null"
    };
    let raw_http = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nOrigin: {origin_hdr}\r\nUser-Agent: mantis/0\r\nConnection: close\r\n\r\n",
        surface.target.path, surface.target.host
    );
    Ok(PrimitiveResult::Confirmed {
        evidence,
        reproducer: Reproducer::from_curl_and_raw(curl, raw_http),
    })
}
