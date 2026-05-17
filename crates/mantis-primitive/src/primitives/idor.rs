//! IDOR (Insecure Direct Object Reference) primitive.
//!
//! Detects endpoints whose path ends with a numeric segment that
//! determines which object is returned, without an apparent
//! authorization check. The primitive mutates the numeric segment
//! and compares response bodies — if different IDs return materially
//! different content without intervening auth, the endpoint is
//! likely IDOR-vulnerable.

use async_trait::async_trait;
use mantis_scanner_http::Surface;
use reqwest::Client;

use crate::reproducer::Reproducer;
use crate::{EvidenceItem, Primitive, PrimitiveError, PrimitiveResult};

pub struct Idor;

#[async_trait]
impl Primitive for Idor {
    fn id(&self) -> &'static str {
        "idor.numeric-id-enumeration"
    }

    fn vuln_class(&self) -> &'static str {
        "idor"
    }

    fn matches_surface(&self, surface: &Surface) -> bool {
        if !(200..400).contains(&surface.status) {
            return false;
        }
        // Last path segment is purely numeric.
        last_numeric_segment(&surface.target.path).is_some()
    }

    async fn execute(
        &self,
        surface: &Surface,
        _client: &Client,
    ) -> Result<PrimitiveResult, PrimitiveError> {
        let original_id = last_numeric_segment(&surface.target.path)
            .ok_or(PrimitiveError::DoesNotApply(self.id()))?;
        let prefix = &surface.target.path[..surface.target.path.rfind(&original_id).unwrap_or(0)];

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(PrimitiveError::Http)?;

        let baseline_url = surface.target.url();
        let baseline = match fetch(&client, &baseline_url).await {
            Some(b) => b,
            None => {
                return Ok(PrimitiveResult::Inconclusive {
                    reason: "could not fetch baseline".into(),
                });
            }
        };
        // Try a candidate ID different from the original.
        let candidate_id = if original_id == "1" { "2" } else { "1" };
        let candidate_url = format!(
            "{}://{}:{}{prefix}{candidate_id}",
            surface.target.scheme, surface.target.host, surface.target.port
        );
        let candidate = match fetch(&client, &candidate_url).await {
            Some(c) => c,
            None => {
                return Ok(PrimitiveResult::Inconclusive {
                    reason: "could not fetch candidate id".into(),
                });
            }
        };

        // Both responses 2xx and content differs => IDOR signal.
        let materially_different = baseline.status == 200
            && candidate.status == 200
            && !baseline.body.is_empty()
            && !candidate.body.is_empty()
            && baseline.body != candidate.body;

        if !materially_different {
            return Ok(PrimitiveResult::Denied {
                reason: format!(
                    "id mutation did not change response materially (statuses {}/{}, lengths {}/{})",
                    baseline.status,
                    candidate.status,
                    baseline.body.len(),
                    candidate.body.len()
                ),
            });
        }

        let evidence = vec![
            EvidenceItem {
                kind: "original-id".into(),
                detail: original_id.clone(),
            },
            EvidenceItem {
                kind: "candidate-id".into(),
                detail: candidate_id.to_string(),
            },
            EvidenceItem {
                kind: "response-divergence".into(),
                detail: format!(
                    "baseline {} bytes, candidate {} bytes",
                    baseline.body.len(),
                    candidate.body.len()
                ),
            },
        ];
        let curl = format!(
            "curl -s {candidate_url}  # compare to {baseline_url}; differing bodies suggest IDOR"
        );
        let raw_http = format!(
            "GET {prefix}{candidate_id} HTTP/1.1\r\nHost: {}\r\nUser-Agent: mantis/0\r\nConnection: close\r\n\r\n",
            surface.target.host
        );
        Ok(PrimitiveResult::Confirmed {
            evidence,
            reproducer: Reproducer::from_curl_and_raw(curl, raw_http),
        })
    }
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

/// Return the last path segment if it is purely numeric.
pub(crate) fn last_numeric_segment(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    let last = trimmed.rsplit('/').next()?;
    if !last.is_empty() && last.chars().all(|c| c.is_ascii_digit()) {
        Some(last.to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_numeric_segment() {
        assert_eq!(last_numeric_segment("/users/42"), Some("42".into()));
        assert_eq!(
            last_numeric_segment("/api/v1/users/1234/"),
            Some("1234".into())
        );
        assert!(last_numeric_segment("/users").is_none());
        assert!(last_numeric_segment("/users/abc").is_none());
    }
}
