//! Reproducer artifact.
//!
//! A reproducer is what an operator hands to a disclosure program:
//! a self-contained command (or program) that demonstrates the
//! finding when run against the same target. Phase 1 ships cURL +
//! raw HTTP dialects; later milestones add Python, Burp/Caido, and
//! Rust per PRD §5.7.10.

use serde::{Deserialize, Serialize};

/// Multi-dialect reproducer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reproducer {
    /// One-liner cURL command.
    pub curl: String,
    /// Raw HTTP/1.1 request the operator can paste into Burp.
    pub raw_http: String,
    /// Optional Python `requests` snippet. None until M1.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python: Option<String>,
}

impl Reproducer {
    pub fn from_curl_and_raw(curl: impl Into<String>, raw_http: impl Into<String>) -> Self {
        Self {
            curl: curl.into(),
            raw_http: raw_http.into(),
            python: None,
        }
    }
}
