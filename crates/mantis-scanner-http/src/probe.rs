//! HTTP probe scanner.
//!
//! Issues a single GET against each target URL, captures status, server
//! header, content length, and a small set of tech fingerprints. Each
//! probe result is written to the event log as a
//! [`EventKind::SurfaceDiscovered`].
//!
//! In production the [`ProbeConfig::proxy`] field is set to the local
//! egress proxy's URL so every request routes through the scope
//! enforcement layer. Phase 0 unit tests omit the proxy and hit
//! localhost mock servers directly.

use std::sync::Arc;
use std::time::Duration;

use mantis_core::{EngagementId, Signer};
use mantis_event_store::{EventKind, EventStore};
use reqwest::Client;
use tracing::{debug, warn};

use crate::error::ScannerError;

/// A single probe target — `scheme://host:port/path`.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl ProbeTarget {
    pub fn parse(url: &str) -> Result<Self, ScannerError> {
        let parsed =
            reqwest::Url::parse(url).map_err(|e| ScannerError::InvalidTarget(e.to_string()))?;
        let scheme = parsed.scheme().to_owned();
        let host = parsed
            .host_str()
            .ok_or_else(|| ScannerError::InvalidTarget("no host".into()))?
            .to_owned();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| ScannerError::InvalidTarget(format!("no port for scheme {scheme}")))?;
        let path = if parsed.path().is_empty() {
            "/".to_owned()
        } else {
            parsed.path().to_owned()
        };
        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    pub fn url(&self) -> String {
        format!("{}://{}:{}{}", self.scheme, self.host, self.port, self.path)
    }
}

/// Captured response data plus inferred fingerprints.
#[derive(Debug, Clone)]
pub struct Surface {
    pub target: ProbeTarget,
    pub status: u16,
    pub server: Option<String>,
    pub content_length: Option<u64>,
    pub tech_hints: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Optional proxy URL (e.g. `http://127.0.0.1:8080`). When set,
    /// reqwest tunnels every request through this proxy.
    pub proxy: Option<String>,
    /// Per-request timeout.
    pub timeout: Duration,
    /// User-Agent header value.
    pub user_agent: String,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            proxy: None,
            timeout: Duration::from_secs(10),
            user_agent: format!("mantis/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

/// Probe scanner that records each result into the event log.
pub struct HttpProbeScanner {
    client: Client,
    event_store: Arc<EventStore>,
    engagement_id: EngagementId,
    signer: Arc<dyn Signer>,
}

impl std::fmt::Debug for HttpProbeScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpProbeScanner")
            .field("engagement_id", &self.engagement_id)
            .finish_non_exhaustive()
    }
}

impl HttpProbeScanner {
    pub fn new(
        event_store: Arc<EventStore>,
        engagement_id: EngagementId,
        signer: Arc<dyn Signer>,
        config: ProbeConfig,
    ) -> Result<Self, ScannerError> {
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(config.user_agent)
            .redirect(reqwest::redirect::Policy::none())
            // Phase 0: scanners may hit self-signed certs in test
            // environments. Production engagements should re-evaluate.
            .danger_accept_invalid_certs(true);
        if let Some(proxy_url) = config.proxy {
            let proxy = reqwest::Proxy::all(&proxy_url)
                .map_err(|e| ScannerError::InvalidProxy(e.to_string()))?;
            builder = builder.proxy(proxy);
        }
        let client = builder.build()?;
        Ok(Self {
            client,
            event_store,
            engagement_id,
            signer,
        })
    }

    /// Probe one target, return the parsed [`Surface`] without writing
    /// to the event store. Used by tests.
    pub async fn probe_no_log(&self, target: &ProbeTarget) -> Result<Surface, ScannerError> {
        let response = self.client.get(target.url()).send().await?;
        let status = response.status().as_u16();
        let server = response
            .headers()
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());
        let content_length = response.content_length();
        let tech_hints = fingerprint(&response, server.as_deref());
        Ok(Surface {
            target: target.clone(),
            status,
            server,
            content_length,
            tech_hints,
        })
    }

    /// Probe one target and persist the result as a `SurfaceDiscovered`
    /// event.
    pub async fn probe(&self, target: &ProbeTarget) -> Result<Surface, ScannerError> {
        let surface = self.probe_no_log(target).await?;
        let event = EventKind::SurfaceDiscovered {
            host: surface.target.host.clone(),
            port: surface.target.port,
            scheme: surface.target.scheme.clone(),
            path: surface.target.path.clone(),
            status: surface.status,
            server: surface.server.clone(),
            content_length: surface.content_length,
            tech_hints: surface.tech_hints.clone(),
        };
        self.event_store
            .append(self.engagement_id, event, self.signer.as_ref())?;
        Ok(surface)
    }

    /// Probe every target sequentially. Errors on individual targets
    /// are logged and skipped; the rest continue.
    pub async fn probe_all(&self, targets: &[ProbeTarget]) -> Vec<Surface> {
        let mut out = Vec::with_capacity(targets.len());
        for target in targets {
            match self.probe(target).await {
                Ok(s) => {
                    debug!(host = %target.host, status = s.status, "probe ok");
                    out.push(s);
                }
                Err(e) => warn!(host = %target.host, error = %e, "probe failed"),
            }
        }
        out
    }
}

/// Best-effort technology fingerprint based on response headers and
/// server identity. Phase 0 catalog covers the most common cases;
/// later milestones move to a richer signature library.
fn fingerprint(response: &reqwest::Response, server: Option<&str>) -> Vec<String> {
    let mut hints = vec![];
    let lower_server = server.map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    for needle in [
        "nginx",
        "apache",
        "iis",
        "caddy",
        "envoy",
        "cloudflare",
        "fastly",
        "akamai",
        "node",
        "gunicorn",
        "uvicorn",
        "tomcat",
        "jetty",
    ] {
        if lower_server.contains(needle) {
            hints.push(format!("server:{needle}"));
        }
    }
    for header in [
        "x-powered-by",
        "x-aspnet-version",
        "x-runtime",
        "x-drupal-cache",
        "x-generator",
    ] {
        if response.headers().contains_key(header) {
            hints.push(format!("header:{header}"));
        }
    }
    if let Some(ct) = response.headers().get(reqwest::header::CONTENT_TYPE) {
        let s = ct.to_str().unwrap_or("");
        if s.contains("application/json") {
            hints.push("content:json".into());
        }
        if s.contains("text/html") {
            hints.push("content:html".into());
        }
        if s.contains("graphql") {
            hints.push("content:graphql".into());
        }
    }
    hints
}
