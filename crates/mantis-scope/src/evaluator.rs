//! Scope evaluator.
//!
//! Given a `(host, port, path?, protocol)` tuple, returns
//! [`ScopeDecision::InScope`] iff:
//!
//! 1. Every `include` axis matches (or is empty / wildcard-equivalent).
//! 2. No `exclude` axis matches.
//!
//! Empty `include.hosts` is treated as "match any host"; this lets
//! callers omit axes they don't care about. Same for the other three
//! axes. Empty `exclude` matches nothing.

use crate::manifest::{Protocol, ScopeManifest, ScopeRules};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeDecision {
    InScope,
    OutOfScope { reason: String },
}

#[derive(Debug, Clone)]
pub struct ScopeQuery<'a> {
    pub host: &'a str,
    pub port: u16,
    pub path: Option<&'a str>,
    pub protocol: Protocol,
}

#[derive(Debug, Clone)]
pub struct ScopeEvaluator {
    include: ScopeRules,
    exclude: ScopeRules,
}

impl ScopeEvaluator {
    pub fn new(manifest: &ScopeManifest) -> Self {
        Self {
            include: manifest.include.clone(),
            exclude: manifest.exclude.clone(),
        }
    }

    pub fn evaluate(&self, query: &ScopeQuery<'_>) -> ScopeDecision {
        // Include checks (each axis must match if non-empty).
        if !match_hosts(&self.include.hosts, query.host) {
            return out_of_scope(format!("host {} not in include.hosts", query.host));
        }
        if !match_ports(&self.include.ports, query.port) {
            return out_of_scope(format!("port {} not in include.ports", query.port));
        }
        if let Some(path) = query.path {
            if !match_paths(&self.include.paths, path) {
                return out_of_scope(format!("path {path} not in include.paths"));
            }
        }
        if !match_protocols(&self.include.protocols, query.protocol) {
            return out_of_scope(format!(
                "protocol {:?} not in include.protocols",
                query.protocol
            ));
        }
        // Exclude checks (any match rejects).
        if match_hosts_non_empty(&self.exclude.hosts, query.host) {
            return out_of_scope(format!("host {} in exclude.hosts", query.host));
        }
        if match_ports_non_empty(&self.exclude.ports, query.port) {
            return out_of_scope(format!("port {} in exclude.ports", query.port));
        }
        if let Some(path) = query.path {
            if match_paths_non_empty(&self.exclude.paths, path) {
                return out_of_scope(format!("path {path} in exclude.paths"));
            }
        }
        if match_protocols_non_empty(&self.exclude.protocols, query.protocol) {
            return out_of_scope(format!(
                "protocol {:?} in exclude.protocols",
                query.protocol
            ));
        }
        ScopeDecision::InScope
    }
}

fn out_of_scope(reason: String) -> ScopeDecision {
    ScopeDecision::OutOfScope { reason }
}

fn match_hosts(patterns: &[crate::host_pattern::HostPattern], host: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| p.matches(host))
}

fn match_hosts_non_empty(patterns: &[crate::host_pattern::HostPattern], host: &str) -> bool {
    !patterns.is_empty() && patterns.iter().any(|p| p.matches(host))
}

fn match_ports(patterns: &[crate::port_range::PortMatcher], port: u16) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| p.matches(port))
}

fn match_ports_non_empty(patterns: &[crate::port_range::PortMatcher], port: u16) -> bool {
    !patterns.is_empty() && patterns.iter().any(|p| p.matches(port))
}

fn match_paths(patterns: &[String], path: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| glob_match::glob_match(p, path))
}

fn match_paths_non_empty(patterns: &[String], path: &str) -> bool {
    !patterns.is_empty() && patterns.iter().any(|p| glob_match::glob_match(p, path))
}

fn match_protocols(allowed: &[Protocol], proto: Protocol) -> bool {
    allowed.is_empty() || allowed.contains(&proto)
}

fn match_protocols_non_empty(blocked: &[Protocol], proto: Protocol) -> bool {
    !blocked.is_empty() && blocked.contains(&proto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::BudgetEnvelope;
    use crate::host_pattern::HostPattern;
    use crate::manifest::{ScopeManifest, ScopeRules, MANIFEST_SCHEMA_VERSION};
    use crate::port_range::PortMatcher;
    use mantis_core::{EngagementId, OperatorId};
    use ulid::Ulid;

    fn manifest(include: ScopeRules, exclude: ScopeRules) -> ScopeManifest {
        ScopeManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            engagement_id: EngagementId(Ulid::new()),
            authorized_by: OperatorId(Ulid::new()),
            expires_at_unix: 1_900_000_000,
            budget: BudgetEnvelope {
                max_requests: 1000,
                max_egress_bytes: 100_000_000,
                max_wall_clock_seconds: 3600,
                max_requests_per_second: 50,
            },
            include,
            exclude,
        }
    }

    fn query<'a>(host: &'a str, port: u16, path: Option<&'a str>) -> ScopeQuery<'a> {
        ScopeQuery {
            host,
            port,
            path,
            protocol: Protocol::Https,
        }
    }

    #[test]
    fn host_match_in_scope() {
        let m = manifest(
            ScopeRules {
                hosts: vec![HostPattern::new("api.example.com")],
                ports: vec![PortMatcher::single(443)],
                paths: vec!["/**".into()],
                protocols: vec![Protocol::Https],
            },
            ScopeRules::default(),
        );
        let eval = ScopeEvaluator::new(&m);
        assert_eq!(
            eval.evaluate(&query("api.example.com", 443, Some("/x"))),
            ScopeDecision::InScope
        );
    }

    #[test]
    fn host_mismatch_out_of_scope() {
        let m = manifest(
            ScopeRules {
                hosts: vec![HostPattern::new("api.example.com")],
                ports: vec![PortMatcher::single(443)],
                paths: vec![],
                protocols: vec![],
            },
            ScopeRules::default(),
        );
        let eval = ScopeEvaluator::new(&m);
        let dec = eval.evaluate(&query("evil.attacker.com", 443, None));
        assert!(matches!(dec, ScopeDecision::OutOfScope { .. }));
    }

    #[test]
    fn port_outside_range_out_of_scope() {
        let m = manifest(
            ScopeRules {
                hosts: vec![HostPattern::new("*")],
                ports: vec![PortMatcher::range(80, 443).unwrap()],
                paths: vec![],
                protocols: vec![],
            },
            ScopeRules::default(),
        );
        let eval = ScopeEvaluator::new(&m);
        assert_eq!(
            eval.evaluate(&query("api.example.com", 443, None)),
            ScopeDecision::InScope
        );
        let dec = eval.evaluate(&query("api.example.com", 8443, None));
        assert!(matches!(dec, ScopeDecision::OutOfScope { .. }));
    }

    #[test]
    fn exclude_overrides_include() {
        let m = manifest(
            ScopeRules {
                hosts: vec![HostPattern::new("*.example.com")],
                ports: vec![PortMatcher::single(443)],
                paths: vec!["/**".into()],
                protocols: vec![Protocol::Https],
            },
            ScopeRules {
                paths: vec!["/admin/**".into()],
                ..Default::default()
            },
        );
        let eval = ScopeEvaluator::new(&m);
        assert_eq!(
            eval.evaluate(&query("api.example.com", 443, Some("/public/page"))),
            ScopeDecision::InScope
        );
        let dec = eval.evaluate(&query("api.example.com", 443, Some("/admin/users")));
        assert!(matches!(dec, ScopeDecision::OutOfScope { .. }));
    }

    #[test]
    fn empty_axis_means_match_any() {
        let m = manifest(
            ScopeRules {
                hosts: vec![HostPattern::new("api.example.com")],
                ports: vec![],
                paths: vec![],
                protocols: vec![],
            },
            ScopeRules::default(),
        );
        let eval = ScopeEvaluator::new(&m);
        assert_eq!(
            eval.evaluate(&query("api.example.com", 12345, Some("/x"))),
            ScopeDecision::InScope
        );
    }

    #[test]
    fn dns_rebinding_style_suffix_attack_rejected() {
        let m = manifest(
            ScopeRules {
                hosts: vec![HostPattern::new("*.example.com")],
                ports: vec![PortMatcher::single(443)],
                paths: vec![],
                protocols: vec![],
            },
            ScopeRules::default(),
        );
        let eval = ScopeEvaluator::new(&m);
        let dec = eval.evaluate(&query("api.example.com.attacker.tld", 443, None));
        assert!(matches!(dec, ScopeDecision::OutOfScope { .. }));
    }

    #[test]
    fn http_protocol_out_when_only_https_allowed() {
        let m = manifest(
            ScopeRules {
                hosts: vec![HostPattern::new("api.example.com")],
                ports: vec![PortMatcher::single(80), PortMatcher::single(443)],
                paths: vec![],
                protocols: vec![Protocol::Https],
            },
            ScopeRules::default(),
        );
        let eval = ScopeEvaluator::new(&m);
        let dec = eval.evaluate(&ScopeQuery {
            host: "api.example.com",
            port: 80,
            path: None,
            protocol: Protocol::Http,
        });
        assert!(matches!(dec, ScopeDecision::OutOfScope { .. }));
    }
}
