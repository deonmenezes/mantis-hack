//! Open-redirect primitive.
//!
//! Many web apps accept a destination URL in a query parameter
//! (`?next=`, `?return_to=`, `?url=`, etc.) and 3xx-redirect to it
//! after some action (typically login). When the destination is not
//! validated, an attacker can host a phishing page on
//! `evil.attacker.tld` and craft a link like
//! `https://victim.com/login?next=https://evil.attacker.tld` that
//! looks legitimate.
//!
//! This primitive probes a set of common redirect-parameter names
//! with attacker-controlled payloads and inspects the
//! `Location:` response header to see if the host has changed.

use async_trait::async_trait;
use mantis_scanner_http::Surface;
use reqwest::redirect::Policy;
use reqwest::Client;

use crate::reproducer::Reproducer;
use crate::{EvidenceItem, Primitive, PrimitiveError, PrimitiveResult};

const REDIRECT_PARAMS: &[&str] = &[
    "next",
    "redirect",
    "redirect_to",
    "redirect_uri",
    "return",
    "return_to",
    "returnurl",
    "url",
    "dest",
    "destination",
    "target",
    "rurl",
    "u",
];

const ATTACKER_HOST: &str = "mantis-probe.example";

pub struct OpenRedirect;

#[async_trait]
impl Primitive for OpenRedirect {
    fn id(&self) -> &'static str {
        "open-redirect.query-param"
    }

    fn vuln_class(&self) -> &'static str {
        "open-redirect"
    }

    fn matches_surface(&self, surface: &Surface) -> bool {
        // Heuristic: 2xx/3xx responses that look like they accept
        // redirect parameters. We can't see request params from
        // scanner output, so we attempt on any non-error endpoint
        // whose path looks login/auth/oauth shaped.
        if !(200..400).contains(&surface.status) {
            return false;
        }
        let lower = surface.target.path.to_ascii_lowercase();
        lower.contains("login")
            || lower.contains("signin")
            || lower.contains("auth")
            || lower.contains("logout")
            || lower.contains("oauth")
            || lower.contains("redirect")
            || lower == "/"
    }

    async fn execute(
        &self,
        surface: &Surface,
        _client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        // Use a client that does NOT follow redirects so we can
        // inspect the Location header on the very first response.
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(PrimitiveError::Http)?;

        for param in REDIRECT_PARAMS {
            let url = format!(
                "{}://{}:{}{}?{param}=https://{ATTACKER_HOST}/",
                surface.target.scheme,
                surface.target.host,
                surface.target.port,
                surface.target.path
            );
            let response = match client.get(&url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            if !response.status().is_redirection() {
                continue;
            }
            let Some(location) = response.headers().get(reqwest::header::LOCATION) else {
                continue;
            };
            let Ok(location_str) = location.to_str() else {
                continue;
            };
            if !location_str.contains(ATTACKER_HOST) {
                continue;
            }
            let evidence = vec![
                EvidenceItem {
                    kind: "redirect-param".into(),
                    detail: (*param).into(),
                },
                EvidenceItem {
                    kind: "location-header".into(),
                    detail: location_str.to_owned(),
                },
                EvidenceItem {
                    kind: "status".into(),
                    detail: response.status().as_u16().to_string(),
                },
            ];
            let curl = format!("curl -sI '{url}' | head -1; curl -sI '{url}' | grep -i ^Location");
            let raw_http = format!(
                "GET {}?{param}=https://{ATTACKER_HOST}/ HTTP/1.1\r\nHost: {}\r\nUser-Agent: mantis/0\r\nConnection: close\r\n\r\n",
                surface.target.path, surface.target.host
            );
            return Ok(PrimitiveResult::Confirmed {
                evidence,
                reproducer: Reproducer::from_curl_and_raw(curl, raw_http),
            });
        }
        Ok(PrimitiveResult::Denied {
            reason: format!(
                "no redirect-param produced an off-host Location on {}",
                surface.target.url()
            ),
        })
    }
}
