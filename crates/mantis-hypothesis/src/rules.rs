//! Phase 0 rule catalog.
//!
//! Each rule is a pure function from `&Surface` to `Option<HypothesisData>`.
//! Adding a rule is a matter of writing the function and appending it
//! to [`RULES`].
//!
//! Priors are basis-points-of-probability (parts per 10,000):
//! - 100 = 1%
//! - 500 = 5%
//! - 1500 = 15%
//! - 3000 = 30%
//!
//! These are *static* priors derived from "what's common in disclosed
//! reports" — they are not predictions. M0.5b's Bayesian update layer
//! will rewrite them per workspace.

use mantis_scanner_http::Surface;

use crate::HypothesisData;

type Rule = fn(&Surface) -> Option<HypothesisData>;

pub fn generate(surface: &Surface) -> Vec<HypothesisData> {
    RULES.iter().filter_map(|r| r(surface)).collect()
}

const RULES: &[Rule] = &[
    server_nginx_paths,
    server_apache_paths,
    server_iis_paths,
    path_admin_dashboard,
    path_api_versioned,
    status_unauthorized,
    status_forbidden,
    status_server_error,
    content_html_xss_candidate,
    content_json_idor_candidate,
    header_powered_by_disclosure,
    path_login_credential_stuffing,
];

fn server_nginx_paths(s: &Surface) -> Option<HypothesisData> {
    let server = s.server.as_deref()?.to_ascii_lowercase();
    if server.contains("nginx") {
        Some(HypothesisData {
            vuln_class: "nginx-recon".into(),
            summary: format!(
                "Probe nginx-specific paths on {}://{}:{}",
                s.target.scheme, s.target.host, s.target.port
            ),
            prior_pp10k: 1500,
        })
    } else {
        None
    }
}

fn server_apache_paths(s: &Surface) -> Option<HypothesisData> {
    let server = s.server.as_deref()?.to_ascii_lowercase();
    if server.contains("apache") {
        Some(HypothesisData {
            vuln_class: "apache-recon".into(),
            summary: format!(
                "Probe Apache-specific paths on {}://{}:{}",
                s.target.scheme, s.target.host, s.target.port
            ),
            prior_pp10k: 1200,
        })
    } else {
        None
    }
}

fn server_iis_paths(s: &Surface) -> Option<HypothesisData> {
    let server = s.server.as_deref()?.to_ascii_lowercase();
    if server.contains("iis") || server.contains("microsoft") {
        Some(HypothesisData {
            vuln_class: "iis-recon".into(),
            summary: format!("Probe IIS-specific paths on {}", s.target.url()),
            prior_pp10k: 1000,
        })
    } else {
        None
    }
}

fn path_admin_dashboard(s: &Surface) -> Option<HypothesisData> {
    let p = s.target.path.to_ascii_lowercase();
    if p.contains("/admin") || p.contains("/dashboard") || p.contains("/manage") {
        Some(HypothesisData {
            vuln_class: "broken-access-control".into(),
            summary: format!(
                "Test unauthenticated access to administrative path {}",
                s.target.path
            ),
            prior_pp10k: 3500,
        })
    } else {
        None
    }
}

fn path_api_versioned(s: &Surface) -> Option<HypothesisData> {
    let p = s.target.path.to_ascii_lowercase();
    if p.contains("/api/v") || p.starts_with("/v1") || p.starts_with("/v2") {
        Some(HypothesisData {
            vuln_class: "api-enumeration".into(),
            summary: format!(
                "Enumerate adjacent versioned API endpoints under {}",
                s.target.path
            ),
            prior_pp10k: 3000,
        })
    } else {
        None
    }
}

fn status_unauthorized(s: &Surface) -> Option<HypothesisData> {
    if s.status == 401 {
        Some(HypothesisData {
            vuln_class: "auth-bypass".into(),
            summary: format!(
                "Endpoint {} returns 401 — try common auth-bypass payloads",
                s.target.url()
            ),
            prior_pp10k: 2000,
        })
    } else {
        None
    }
}

fn status_forbidden(s: &Surface) -> Option<HypothesisData> {
    if s.status == 403 {
        Some(HypothesisData {
            vuln_class: "auth-bypass".into(),
            summary: format!(
                "Endpoint {} returns 403 — try path normalization and header overrides",
                s.target.url()
            ),
            prior_pp10k: 2500,
        })
    } else {
        None
    }
}

fn status_server_error(s: &Surface) -> Option<HypothesisData> {
    if s.status >= 500 {
        Some(HypothesisData {
            vuln_class: "info-disclosure".into(),
            summary: format!(
                "Endpoint {} returns {} — server-error responses often leak stack traces",
                s.target.url(),
                s.status
            ),
            prior_pp10k: 1500,
        })
    } else {
        None
    }
}

fn content_html_xss_candidate(s: &Surface) -> Option<HypothesisData> {
    if s.tech_hints.iter().any(|h| h == "content:html") && s.status == 200 {
        Some(HypothesisData {
            vuln_class: "xss-reflected".into(),
            summary: format!(
                "HTML response from {} — probe query parameters for reflected XSS",
                s.target.url()
            ),
            prior_pp10k: 1500,
        })
    } else {
        None
    }
}

fn content_json_idor_candidate(s: &Surface) -> Option<HypothesisData> {
    if s.tech_hints.iter().any(|h| h == "content:json") && s.status == 200 {
        Some(HypothesisData {
            vuln_class: "idor".into(),
            summary: format!(
                "JSON API response from {} — enumerate numeric/UUID identifiers",
                s.target.url()
            ),
            prior_pp10k: 2500,
        })
    } else {
        None
    }
}

fn header_powered_by_disclosure(s: &Surface) -> Option<HypothesisData> {
    if s.tech_hints.iter().any(|h| h == "header:x-powered-by") {
        Some(HypothesisData {
            vuln_class: "info-disclosure".into(),
            summary: format!(
                "X-Powered-By header on {} discloses backend stack — check version-specific CVEs",
                s.target.url()
            ),
            prior_pp10k: 800,
        })
    } else {
        None
    }
}

fn path_login_credential_stuffing(s: &Surface) -> Option<HypothesisData> {
    let p = s.target.path.to_ascii_lowercase();
    if p.contains("/login") || p.contains("/signin") || p.contains("/auth") {
        Some(HypothesisData {
            vuln_class: "weak-auth".into(),
            summary: format!(
                "Authentication endpoint {} — test for credential stuffing, rate limiting, and account enumeration",
                s.target.url()
            ),
            prior_pp10k: 2000,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_scanner_http::ProbeTarget;

    fn surface(status: u16, server: Option<&str>, path: &str, hints: &[&str]) -> Surface {
        Surface {
            target: ProbeTarget {
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: 443,
                path: path.into(),
            },
            status,
            server: server.map(|s| s.to_owned()),
            content_length: Some(1024),
            tech_hints: hints.iter().map(|h| (*h).to_owned()).collect(),
        }
    }

    #[test]
    fn nginx_rule_fires_on_server_header() {
        let s = surface(200, Some("nginx/1.25.0"), "/", &["server:nginx"]);
        let h = generate(&s);
        assert!(h.iter().any(|h| h.vuln_class == "nginx-recon"));
    }

    #[test]
    fn admin_path_high_prior() {
        let s = surface(200, None, "/admin/users", &[]);
        let h = generate(&s);
        let admin = h.iter().find(|h| h.vuln_class == "broken-access-control");
        assert!(admin.is_some());
        assert!(admin.unwrap().prior_pp10k >= 3000);
    }

    #[test]
    fn status_500_fires_info_disclosure() {
        let s = surface(500, None, "/", &[]);
        let h = generate(&s);
        assert!(h.iter().any(|h| h.vuln_class == "info-disclosure"));
    }

    #[test]
    fn json_response_fires_idor() {
        let s = surface(200, None, "/api/v1/users/42", &["content:json"]);
        let h = generate(&s);
        assert!(h.iter().any(|h| h.vuln_class == "idor"));
        // Also fires api-enumeration.
        assert!(h.iter().any(|h| h.vuln_class == "api-enumeration"));
    }

    #[test]
    fn login_path_fires_weak_auth() {
        let s = surface(200, None, "/auth/login", &[]);
        let h = generate(&s);
        assert!(h.iter().any(|h| h.vuln_class == "weak-auth"));
    }

    #[test]
    fn no_match_for_uninteresting_surface() {
        let s = surface(200, None, "/static/style.css", &[]);
        let h = generate(&s);
        // No high-signal rule should fire on a static asset.
        assert!(h.iter().all(|h| h.vuln_class != "broken-access-control"));
    }

    #[test]
    fn priors_are_in_descending_order_when_sorted() {
        let s = surface(403, Some("nginx/1.25.0"), "/admin/users", &["server:nginx"]);
        let h = crate::generate_for(&s);
        for w in h.windows(2) {
            assert!(w[0].prior_pp10k >= w[1].prior_pp10k);
        }
    }
}
