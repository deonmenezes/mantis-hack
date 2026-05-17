//! Primitive catalog. Phase 1 ships:
//!
//! - [`missing_security_headers::MissingSecurityHeaders`]
//! - [`open_redirect::OpenRedirect`]
//!
//! Future milestones expand the catalog to cover the rest of OWASP
//! Top 10 (XSS, SQLi, IDOR, SSRF, etc.).

pub mod cors_wildcard;
pub mod idor;
pub mod missing_security_headers;
pub mod open_redirect;
pub mod sqli_error;
pub mod xss_reflected;
