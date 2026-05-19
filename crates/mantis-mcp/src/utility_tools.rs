//! Pure-Rust helpers backing the leaf utility MCP tools:
//! `mantis_decode_jwt`, `mantis_diff_responses`, `mantis_summarize_url`.
//!
//! These tools don't talk to the daemon — they're stateless local
//! transformations that save hunters from shelling out to base64,
//! diff, or python urlparse. Keeping the logic out of `server.rs`
//! keeps that file focused on tool registration + daemon plumbing.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// mantis_decode_jwt
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DecodeJwtArgs {
    /// The JWT to decode. Compact serialization, three dot-separated
    /// base64url-encoded segments: `header.payload.signature`. The
    /// signature is **not** verified — this tool decodes and
    /// inspects, it does not authenticate.
    pub jwt: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DecodedJwt {
    /// Header JSON (e.g. `{"alg":"HS256","typ":"JWT"}`).
    pub header: serde_json::Value,
    /// Payload (claims) JSON.
    pub payload: serde_json::Value,
    /// Raw base64url-encoded signature segment (not decoded — useful
    /// for length-based heuristics).
    pub signature_b64: String,
    /// Length of the decoded signature in bytes (0 on parse failure
    /// or empty signature).
    pub signature_bytes: usize,
    /// Sorted alphabetical list of claim keys present in the payload.
    pub claims_present: Vec<String>,
    /// Standard-claim convenience fields, when present. Decoded from
    /// `exp` / `nbf` / `iat` as unix seconds; left null otherwise.
    pub exp_unix: Option<i64>,
    pub nbf_unix: Option<i64>,
    pub iat_unix: Option<i64>,
    /// `iss` claim (string) when present.
    pub iss: Option<String>,
    /// `aud` claim, raw value (may be string or array).
    pub aud: Option<serde_json::Value>,
    /// `sub` claim when present.
    pub sub: Option<String>,
    /// `alg` from the header (e.g. `"HS256"`, `"RS256"`, `"none"`).
    pub alg: Option<String>,
    /// One-line warnings about dangerous patterns: `alg:none`,
    /// `signature:empty`, `exp:missing`, `exp:expired`, etc.
    pub warnings: Vec<String>,
}

/// Decode a JWT without verifying its signature. Always returns a
/// result — even malformed input becomes a structured payload with
/// `warnings` describing what went wrong. The caller (an LLM) gets
/// to reason about the failure modes instead of having to retry.
pub fn decode_jwt(jwt: &str) -> DecodedJwt {
    let mut out = DecodedJwt {
        header: serde_json::Value::Null,
        payload: serde_json::Value::Null,
        signature_b64: String::new(),
        signature_bytes: 0,
        claims_present: vec![],
        exp_unix: None,
        nbf_unix: None,
        iat_unix: None,
        iss: None,
        aud: None,
        sub: None,
        alg: None,
        warnings: vec![],
    };

    let trimmed = jwt.trim();
    let stripped = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
        .unwrap_or(trimmed);

    let parts: Vec<&str> = stripped.split('.').collect();
    if parts.len() != 3 {
        out.warnings.push(format!(
            "format:invalid (expected 3 dot-separated segments, got {})",
            parts.len()
        ));
        return out;
    }

    out.signature_b64 = parts[2].to_string();
    out.signature_bytes = b64url_decode(parts[2]).map(|v| v.len()).unwrap_or(0);
    if parts[2].is_empty() || out.signature_bytes == 0 {
        out.warnings.push("signature:empty".into());
    }

    match decode_segment_json(parts[0]) {
        Ok(h) => {
            out.alg = h.get("alg").and_then(|v| v.as_str()).map(str::to_owned);
            if matches!(out.alg.as_deref(), Some("none") | Some("None") | Some("NONE")) {
                out.warnings.push("alg:none — unauthenticated JWT".into());
            }
            out.header = h;
        }
        Err(e) => out.warnings.push(format!("header:{e}")),
    }

    match decode_segment_json(parts[1]) {
        Ok(p) => {
            // Standard claims.
            out.exp_unix = p.get("exp").and_then(json_as_i64);
            out.nbf_unix = p.get("nbf").and_then(json_as_i64);
            out.iat_unix = p.get("iat").and_then(json_as_i64);
            out.iss = p.get("iss").and_then(|v| v.as_str()).map(str::to_owned);
            out.sub = p.get("sub").and_then(|v| v.as_str()).map(str::to_owned);
            out.aud = p.get("aud").cloned();
            if let Some(obj) = p.as_object() {
                out.claims_present = obj.keys().cloned().collect();
                out.claims_present.sort();
            }
            // Warnings.
            if out.exp_unix.is_none() {
                out.warnings.push("exp:missing".into());
            } else if let Some(exp) = out.exp_unix {
                if exp < now_unix() {
                    out.warnings.push("exp:expired".into());
                }
            }
            if out.iss.is_none() {
                out.warnings.push("iss:missing".into());
            }
            out.payload = p;
        }
        Err(e) => out.warnings.push(format!("payload:{e}")),
    }
    out
}

fn json_as_i64(v: &serde_json::Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_u64().and_then(|u| i64::try_from(u).ok()))
        .or_else(|| v.as_f64().map(|f| f as i64))
}

fn decode_segment_json(seg: &str) -> Result<serde_json::Value, String> {
    let bytes = b64url_decode(seg).ok_or_else(|| "base64url:invalid".to_string())?;
    let s = std::str::from_utf8(&bytes).map_err(|_| "utf8:invalid".to_string())?;
    serde_json::from_str::<serde_json::Value>(s).map_err(|e| format!("json:invalid({e})"))
}

/// Tiny base64url decoder (RFC 7515 §2). No padding required. Maps
/// `-` / `_` back to `+` / `/` before standard base64 decoding.
/// Returns `None` on any malformed character.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    // Pad to a multiple of 4 with '=' so the standard alphabet
    // decoder accepts it.
    let mut padded = String::with_capacity(s.len() + 3);
    for c in s.chars() {
        match c {
            '-' => padded.push('+'),
            '_' => padded.push('/'),
            c => padded.push(c),
        }
    }
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    b64_std_decode(&padded)
}

/// Self-contained standard-base64 decoder. We don't pull in the
/// `base64` crate just for this — a 40-line implementation keeps
/// dependencies tight.
fn b64_std_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        Some(match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut buf = 0u32;
        let mut pad = 0usize;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                if i < 2 {
                    return None;
                }
                pad += 1;
                continue;
            }
            buf = (buf << 6) | val(b)?;
        }
        // pad-shift compensates for missing trailing bytes.
        buf <<= 6 * pad;
        out.push((buf >> 16) as u8);
        if pad < 2 {
            out.push((buf >> 8) as u8);
        }
        if pad < 1 {
            out.push(buf as u8);
        }
    }
    Some(out)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// mantis_diff_responses
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiffResponsesArgs {
    /// "A" side response — the baseline (e.g. unauth or attacker
    /// profile).
    pub a: ResponseSnapshot,
    /// "B" side response — the comparison (e.g. authenticated or
    /// victim profile).
    pub b: ResponseSnapshot,
    /// Cap on the body-byte preview included in the result.
    /// Defaults to 256 to keep the LLM's view-window cheap.
    #[serde(default = "default_preview_cap")]
    pub preview_cap: usize,
}

fn default_preview_cap() -> usize {
    256
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ResponseSnapshot {
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DiffResult {
    /// One of: `identical`, `status_changed`, `length_changed`,
    /// `headers_changed`, `body_changed`, `mixed`. The classifier
    /// picks the most-impactful label.
    pub classification: String,
    pub status_a: u16,
    pub status_b: u16,
    pub status_delta: bool,
    pub body_len_a: usize,
    pub body_len_b: usize,
    pub body_len_delta: i64,
    pub body_identical: bool,
    /// Headers present in `a` but missing in `b`.
    pub headers_only_in_a: Vec<String>,
    /// Headers present in `b` but missing in `a`.
    pub headers_only_in_b: Vec<String>,
    /// Header names whose values differ between sides.
    pub headers_value_changed: Vec<String>,
    /// First N bytes of body A (capped).
    pub body_preview_a: String,
    /// First N bytes of body B (capped).
    pub body_preview_b: String,
    /// Heuristic "interesting markers" found in either body — token
    /// shapes, error strings, user/admin role hints. Useful priors
    /// for an LLM deciding whether the diff is exploitable.
    pub markers: Vec<String>,
}

pub fn diff_responses(args: &DiffResponsesArgs) -> DiffResult {
    let a = &args.a;
    let b = &args.b;
    let cap = args.preview_cap.min(4096);

    let body_identical = a.body == b.body;
    let body_len_a = a.body.len();
    let body_len_b = b.body.len();
    let body_len_delta = body_len_b as i64 - body_len_a as i64;
    let status_delta = a.status != b.status;

    // Header diffing.
    let mut only_a: Vec<String> = vec![];
    let mut only_b: Vec<String> = vec![];
    let mut changed: Vec<String> = vec![];
    for (k, va) in &a.headers {
        match b.headers.get(k) {
            None => only_a.push(k.clone()),
            Some(vb) if vb != va => changed.push(k.clone()),
            _ => {}
        }
    }
    for k in b.headers.keys() {
        if !a.headers.contains_key(k) {
            only_b.push(k.clone());
        }
    }
    only_a.sort();
    only_b.sort();
    changed.sort();
    let headers_changed = !only_a.is_empty() || !only_b.is_empty() || !changed.is_empty();

    let classification = if !status_delta && body_identical && !headers_changed {
        "identical"
    } else if status_delta && !body_identical {
        "mixed"
    } else if status_delta {
        "status_changed"
    } else if body_identical && headers_changed {
        "headers_changed"
    } else if !body_identical && a.body.len() != b.body.len() {
        "length_changed"
    } else if !body_identical {
        "body_changed"
    } else {
        "mixed"
    }
    .to_string();

    let markers = scan_markers(&a.body, &b.body);

    DiffResult {
        classification,
        status_a: a.status,
        status_b: b.status,
        status_delta,
        body_len_a,
        body_len_b,
        body_len_delta,
        body_identical,
        headers_only_in_a: only_a,
        headers_only_in_b: only_b,
        headers_value_changed: changed,
        body_preview_a: cap_str(&a.body, cap),
        body_preview_b: cap_str(&b.body, cap),
        markers,
    }
}

fn cap_str(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        s.to_string()
    } else {
        let mut out = s[..cap].to_string();
        out.push_str(" …(truncated)");
        out
    }
}

fn scan_markers(a: &str, b: &str) -> Vec<String> {
    const PATTERNS: &[(&str, &str)] = &[
        ("role:admin", "\"admin\""),
        ("role:superuser", "\"superuser\""),
        ("role:user", "\"user\""),
        ("token:jwt-shape", "eyJ"),
        ("error:unauthorized", "unauthorized"),
        ("error:forbidden", "forbidden"),
        ("error:not_found", "not found"),
        ("flag:debug_true", "\"debug\":true"),
        ("flag:is_admin_true", "\"is_admin\":true"),
        ("flag:owner_true", "\"owner\":true"),
        ("supabase:apikey", "apikey"),
        ("aws:access_key", "AKIA"),
        ("stripe:live_key", "sk_live_"),
        ("github:token", "ghp_"),
    ];
    let mut out: Vec<String> = vec![];
    for (label, needle) in PATTERNS {
        let in_a = a.contains(needle);
        let in_b = b.contains(needle);
        if in_a && !in_b {
            out.push(format!("{label} (only in A)"));
        } else if in_b && !in_a {
            out.push(format!("{label} (only in B)"));
        } else if in_a && in_b {
            out.push(format!("{label} (both)"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// mantis_summarize_url
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SummarizeUrlArgs {
    pub url: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct UrlSummary {
    pub raw: String,
    pub scheme: Option<String>,
    pub userinfo: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub effective_port: Option<u16>,
    pub path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
    pub query_params: Vec<(String, String)>,
    pub flags: UrlFlags,
}

#[derive(Debug, Serialize, JsonSchema, Default)]
pub struct UrlFlags {
    /// `true` if the host is a literal IPv4 / IPv6 address.
    pub host_is_ip_literal: bool,
    /// `true` if the host is a private (RFC 1918), loopback,
    /// link-local, or cloud-metadata candidate.
    pub host_is_internal: bool,
    /// `true` if the URL embeds `user:pass@host` (RFC 3986 userinfo).
    pub has_userinfo: bool,
    /// `true` if the URL uses a non-https scheme.
    pub is_plaintext_scheme: bool,
    /// `true` if the path looks like a server-side resource that
    /// could host secrets (matches `.env`, `.git/config`,
    /// `.aws/credentials`, `.npmrc`, …).
    pub path_is_secret_artifact: bool,
    /// `true` if the path looks like an admin / privileged endpoint
    /// (`/admin`, `/internal`, `/debug`, `/_health`, `/actuator`).
    pub path_is_admin_like: bool,
    /// Cloud-metadata candidates: `169.254.169.254`, `metadata.google.internal`,
    /// `metadata.azure.com`, `100.100.100.200` (Alibaba), `2852039166` (decimal).
    pub host_is_cloud_metadata: bool,
}

/// Lightweight URL parser. We don't pull in the `url` crate to keep
/// the dependency surface small; the grammar we need is RFC 3986's
/// happy path for absolute URLs, plus a few SSRF-relevant
/// classifications.
pub fn summarize_url(raw: &str) -> UrlSummary {
    let raw_trim = raw.trim().to_string();
    let mut out = UrlSummary {
        raw: raw_trim.clone(),
        scheme: None,
        userinfo: None,
        host: None,
        port: None,
        effective_port: None,
        path: String::new(),
        query: None,
        fragment: None,
        query_params: vec![],
        flags: UrlFlags::default(),
    };

    // scheme://
    let rest = if let Some(idx) = raw_trim.find("://") {
        let scheme = raw_trim[..idx].to_ascii_lowercase();
        out.scheme = Some(scheme.clone());
        out.flags.is_plaintext_scheme = !matches!(scheme.as_str(), "https" | "wss");
        &raw_trim[idx + 3..]
    } else {
        return out;
    };

    // fragment.
    let (rest, fragment) = split_once_at(rest, '#');
    out.fragment = fragment.map(str::to_owned);

    // query.
    let (rest, query) = split_once_at(rest, '?');
    out.query = query.map(str::to_owned);
    if let Some(q) = &out.query {
        out.query_params = parse_query(q);
    }

    // authority (userinfo@host:port) / path
    let (authority, path) = split_once_at(rest, '/');
    let path = path.map(|p| format!("/{p}")).unwrap_or_else(|| "/".to_string());
    out.path = path;
    out.flags.path_is_secret_artifact = is_secret_artifact(&out.path);
    out.flags.path_is_admin_like = is_admin_like(&out.path);

    let (userinfo, hostport) = if let Some(at) = authority.rfind('@') {
        (Some(&authority[..at]), &authority[at + 1..])
    } else {
        (None, authority)
    };
    if let Some(u) = userinfo {
        out.userinfo = Some(u.to_string());
        out.flags.has_userinfo = true;
    }

    // host[:port]. Brackets for IPv6.
    if let Some(stripped) = hostport.strip_prefix('[') {
        if let Some(close) = stripped.find(']') {
            out.host = Some(stripped[..close].to_string());
            let after = &stripped[close + 1..];
            if let Some(p) = after.strip_prefix(':') {
                out.port = p.parse().ok();
            }
        }
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        out.host = Some(h.to_string());
        out.port = p.parse().ok();
    } else if !hostport.is_empty() {
        out.host = Some(hostport.to_string());
    }

    out.effective_port = out
        .port
        .or_else(|| match out.scheme.as_deref() {
            Some("http") | Some("ws") => Some(80),
            Some("https") | Some("wss") => Some(443),
            Some("ftp") => Some(21),
            _ => None,
        });

    if let Some(h) = &out.host {
        out.flags.host_is_ip_literal = is_ip_literal(h);
        out.flags.host_is_internal = is_internal_host(h);
        out.flags.host_is_cloud_metadata = is_cloud_metadata_host(h);
    }
    out
}

fn split_once_at(s: &str, c: char) -> (&str, Option<&str>) {
    match s.find(c) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (percent_decode_lossy(k), percent_decode_lossy(v)),
            None => (percent_decode_lossy(kv), String::new()),
        })
        .collect()
}

fn percent_decode_lossy(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_ip_literal(host: &str) -> bool {
    // IPv6 bracket form is handled before we get here, so host is
    // either IPv4 dotted-decimal or IPv6 with no brackets.
    host.chars().all(|c| c.is_ascii_digit() || c == '.')
        && host.split('.').count() == 4
        && host.split('.').all(|o| o.parse::<u8>().is_ok())
        || host.contains(':') && host.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

fn is_internal_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    if matches!(h.as_str(), "localhost" | "ip6-localhost" | "ip6-loopback") {
        return true;
    }
    // RFC 1918 / loopback / link-local for IPv4 dotted-decimal.
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() == 4 {
        let p: Vec<Option<u8>> = parts.iter().map(|p| p.parse().ok()).collect();
        if p.iter().all(Option::is_some) {
            let o = (p[0].unwrap(), p[1].unwrap(), p[2].unwrap(), p[3].unwrap());
            if o.0 == 10 {
                return true;
            }
            if o.0 == 127 {
                return true;
            }
            if o.0 == 172 && (16..=31).contains(&o.1) {
                return true;
            }
            if o.0 == 192 && o.1 == 168 {
                return true;
            }
            if o.0 == 169 && o.1 == 254 {
                return true;
            }
            if o.0 == 100 && (64..=127).contains(&o.1) {
                return true;
            }
        }
    }
    // IPv6 loopback / unique-local.
    if h == "::1" || h.starts_with("fc") || h.starts_with("fd") || h.starts_with("fe80:") {
        return true;
    }
    h.ends_with(".internal") || h.ends_with(".local") || h.ends_with(".localhost")
}

fn is_cloud_metadata_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    matches!(
        h.as_str(),
        "169.254.169.254"
            | "metadata.google.internal"
            | "metadata.azure.com"
            | "metadata.azure.net"
            | "100.100.100.200"
            | "169.254.170.2"
    ) || h == "fd00:ec2::254"
}

fn is_secret_artifact(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "/.env",
        "/.git/config",
        "/.aws/credentials",
        "/.npmrc",
        "/.dockercfg",
        "/.docker/config.json",
        "/.ssh/id_rsa",
        "/wp-config.php",
        "/web.config",
        "/config.json",
        "/credentials.json",
        "/.htpasswd",
    ]
    .iter()
    .any(|needle| p.contains(needle))
}

fn is_admin_like(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "/admin",
        "/internal",
        "/debug",
        "/_health",
        "/actuator",
        "/server-status",
        "/server-info",
        "/private",
        "/.well-known/security.txt",
        "/management",
    ]
    .iter()
    .any(|needle| p.starts_with(needle) || p.contains(needle))
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn jwt(header: &str, payload: &str) -> String {
        format!(
            "{}.{}.sig",
            base64url_encode(header.as_bytes()),
            base64url_encode(payload.as_bytes()),
        )
    }

    fn base64url_encode(b: &[u8]) -> String {
        const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in b.chunks(3) {
            let mut v: u32 = 0;
            for (i, &c) in chunk.iter().enumerate() {
                v |= (c as u32) << (16 - 8 * i);
            }
            for i in 0..(chunk.len() + 1) {
                out.push(ALPH[((v >> (18 - 6 * i)) & 0x3f) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn decode_jwt_flags_alg_none() {
        let j = jwt(r#"{"alg":"none","typ":"JWT"}"#, r#"{"sub":"u1"}"#);
        let d = decode_jwt(&j);
        assert_eq!(d.alg.as_deref(), Some("none"));
        assert!(d.warnings.iter().any(|w| w.starts_with("alg:none")));
    }

    #[test]
    fn decode_jwt_extracts_standard_claims() {
        let j = jwt(
            r#"{"alg":"HS256"}"#,
            r#"{"sub":"alice","iss":"corp.example","exp":9999999999,"iat":1,"aud":"web"}"#,
        );
        let d = decode_jwt(&j);
        assert_eq!(d.sub.as_deref(), Some("alice"));
        assert_eq!(d.iss.as_deref(), Some("corp.example"));
        assert_eq!(d.exp_unix, Some(9999999999));
        assert_eq!(d.aud, Some(json!("web")));
        assert!(d.claims_present.contains(&"sub".to_string()));
        assert!(!d.warnings.iter().any(|w| w == "iss:missing"));
    }

    #[test]
    fn decode_jwt_flags_expired() {
        let j = jwt(r#"{"alg":"HS256"}"#, r#"{"exp":1}"#);
        let d = decode_jwt(&j);
        assert!(d.warnings.iter().any(|w| w == "exp:expired"));
    }

    #[test]
    fn decode_jwt_strips_bearer_prefix() {
        let j = format!(
            "Bearer {}",
            jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"u1"}"#)
        );
        let d = decode_jwt(&j);
        assert_eq!(d.sub.as_deref(), Some("u1"));
    }

    #[test]
    fn decode_jwt_handles_malformed() {
        let d = decode_jwt("not-a-jwt");
        assert!(d.warnings.iter().any(|w| w.starts_with("format:invalid")));
    }

    #[test]
    fn diff_responses_identical() {
        let a = ResponseSnapshot { status: 200, headers: BTreeMap::new(), body: "ok".into() };
        let b = a.clone();
        let r = diff_responses(&DiffResponsesArgs { a, b, preview_cap: 256 });
        assert_eq!(r.classification, "identical");
        assert!(r.body_identical);
    }

    #[test]
    fn diff_responses_status_changed_and_marker() {
        let mut a = ResponseSnapshot { status: 401, headers: BTreeMap::new(), body: r#"{"error":"unauthorized"}"#.into() };
        a.headers.insert("x-rate".into(), "1".into());
        let b = ResponseSnapshot {
            status: 200,
            headers: BTreeMap::new(),
            body: r#"{"role":"admin","ok":true}"#.into(),
        };
        let r = diff_responses(&DiffResponsesArgs { a, b, preview_cap: 256 });
        assert!(r.status_delta);
        assert!(r.markers.iter().any(|m| m.starts_with("role:admin (only in B)")));
        assert!(r
            .markers
            .iter()
            .any(|m| m.starts_with("error:unauthorized (only in A)")));
    }

    #[test]
    fn diff_responses_headers_only_changed() {
        let mut a = ResponseSnapshot { status: 200, headers: BTreeMap::new(), body: "x".into() };
        a.headers.insert("Set-Cookie".into(), "sid=1".into());
        let mut b = a.clone();
        b.headers.insert("Set-Cookie".into(), "sid=2".into());
        let r = diff_responses(&DiffResponsesArgs { a, b, preview_cap: 256 });
        assert_eq!(r.classification, "headers_changed");
        assert!(r.headers_value_changed.contains(&"Set-Cookie".into()));
    }

    #[test]
    fn summarize_url_basic() {
        let s = summarize_url("https://user:pw@app.example.com:8443/admin/users?id=42&q=a%20b#sec");
        assert_eq!(s.scheme.as_deref(), Some("https"));
        assert_eq!(s.host.as_deref(), Some("app.example.com"));
        assert_eq!(s.port, Some(8443));
        assert_eq!(s.path, "/admin/users");
        assert_eq!(s.query.as_deref(), Some("id=42&q=a%20b"));
        assert_eq!(s.fragment.as_deref(), Some("sec"));
        assert_eq!(s.query_params, vec![("id".into(), "42".into()), ("q".into(), "a b".into())]);
        assert!(s.flags.has_userinfo);
        assert!(s.flags.path_is_admin_like);
        assert!(!s.flags.host_is_internal);
        assert!(!s.flags.is_plaintext_scheme);
    }

    #[test]
    fn summarize_url_flags_imds() {
        let s = summarize_url("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
        assert!(s.flags.host_is_internal);
        assert!(s.flags.host_is_cloud_metadata);
        assert!(s.flags.host_is_ip_literal);
        assert!(s.flags.is_plaintext_scheme);
        assert_eq!(s.effective_port, Some(80));
    }

    #[test]
    fn summarize_url_flags_secret_artifact() {
        let s = summarize_url("https://app.example.com/.env");
        assert!(s.flags.path_is_secret_artifact);
    }

    #[test]
    fn summarize_url_invalid_returns_partial() {
        let s = summarize_url("not a url");
        assert!(s.scheme.is_none());
        assert!(s.host.is_none());
    }
}
