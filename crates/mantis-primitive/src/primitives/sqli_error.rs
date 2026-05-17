//! Error-based SQL injection primitive.
//!
//! Injects single-quote and double-quote payloads into common
//! query parameters and inspects the response body for known SQL
//! engine error fingerprints. Detects classic MySQL/PostgreSQL/SQL
//! Server/SQLite/Oracle error messages that leak into the response.
//!
//! This is a *low-impact* probe — single-quote injection on a
//! parameter is the standard first step a manual tester takes.
//! It doesn't attempt UNION SELECT or any data-extraction payload.

use async_trait::async_trait;
use mantis_scanner_http::Surface;
use reqwest::Client;

use crate::reproducer::Reproducer;
use crate::{EvidenceItem, Primitive, PrimitiveError, PrimitiveResult};

const SQLI_PARAMS: &[&str] = &[
    "id", "user", "username", "email", "search", "q", "filter", "sort", "name",
];

const SQL_ERROR_FINGERPRINTS: &[&str] = &[
    "you have an error in your sql syntax",
    "mysql_fetch_assoc",
    "mysql_fetch_array",
    "mysql_num_rows",
    "mysqli_fetch_array",
    "pg_query()",
    "pg_exec()",
    "postgresql query failed",
    "syntax error at or near",
    "unterminated quoted string",
    "warning: pg_",
    "ora-00933",
    "ora-00921",
    "ora-00936",
    "ora-01756",
    "quoted string not properly terminated",
    "sql server",
    "microsoft ole db provider for",
    "unclosed quotation mark",
    "incorrect syntax near",
    "sqlite3.operationalerror",
    "sqlite_master",
    "sqlitexception",
    "near \"'\" syntax error",
];

pub struct SqliErrorBased;

#[async_trait]
impl Primitive for SqliErrorBased {
    fn id(&self) -> &'static str {
        "sqli.error-based"
    }

    fn vuln_class(&self) -> &'static str {
        "sqli"
    }

    fn matches_surface(&self, surface: &Surface) -> bool {
        if !(200..400).contains(&surface.status) {
            return false;
        }
        // API or HTML endpoints; we cannot see request params in the
        // surface, so we attempt on every non-static endpoint.
        let lower = surface.target.path.to_ascii_lowercase();
        !lower.ends_with(".css")
            && !lower.ends_with(".js")
            && !lower.ends_with(".png")
            && !lower.ends_with(".jpg")
            && !lower.ends_with(".svg")
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

        for param in SQLI_PARAMS {
            for payload in ["'", "\"", "')", "\")"] {
                let payload_enc = urlencoding(payload);
                let url = format!(
                    "{}://{}:{}{}?{param}={payload_enc}",
                    surface.target.scheme,
                    surface.target.host,
                    surface.target.port,
                    surface.target.path
                );
                let Ok(response) = client.get(&url).send().await else {
                    continue;
                };
                // Even 500 responses can leak SQL errors; check body
                // regardless of status.
                let Ok(body) = response.text().await else {
                    continue;
                };
                let body_lower = body.to_ascii_lowercase();
                let Some(fingerprint) = SQL_ERROR_FINGERPRINTS
                    .iter()
                    .find(|fp| body_lower.contains(*fp))
                else {
                    continue;
                };
                let evidence = vec![
                    EvidenceItem {
                        kind: "injection-param".into(),
                        detail: (*param).into(),
                    },
                    EvidenceItem {
                        kind: "payload".into(),
                        detail: (*payload).into(),
                    },
                    EvidenceItem {
                        kind: "sql-error-fingerprint".into(),
                        detail: (*fingerprint).into(),
                    },
                ];
                let curl = format!(
                    "curl -s '{url}' | grep -i -F '{fingerprint}'  # SQL engine error leaked into response"
                );
                let raw_http = format!(
                    "GET {}?{param}={payload_enc} HTTP/1.1\r\nHost: {}\r\nUser-Agent: mantis/0\r\nConnection: close\r\n\r\n",
                    surface.target.path, surface.target.host
                );
                return Ok(PrimitiveResult::Confirmed {
                    evidence,
                    reproducer: Reproducer::from_curl_and_raw(curl, raw_http),
                });
            }
        }
        Ok(PrimitiveResult::Denied {
            reason: "no quote-injection payload triggered a known SQL error fingerprint".into(),
        })
    }
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            out.push(c);
        } else {
            for b in c.to_string().bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encoding_handles_quotes() {
        assert_eq!(urlencoding("'"), "%27");
        assert_eq!(urlencoding("\""), "%22");
        assert_eq!(urlencoding("')"), "%27%29");
    }
}
