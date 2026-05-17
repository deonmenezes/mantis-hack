//! Host patterns with glob semantics.
//!
//! Patterns accept `*` and `?` wildcards. `*` does NOT match `.` so
//! `*.example.com` correctly excludes `evil.example.com.attacker.com`.
//! A bare `*` matches anything.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostPattern(String);

impl HostPattern {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Match `host` against the pattern. `*` and `?` wildcards do not
    /// span dots, so `*.example.com` matches `api.example.com` but not
    /// `a.b.example.com` and not `evil.example.com.attacker.tld`.
    pub fn matches(&self, host: &str) -> bool {
        // Use glob_match_with_captures to allow per-component matching.
        // glob-match's default matches across separators; we restrict
        // by performing a label-by-label check when the pattern
        // contains `*`.
        if self.0 == "*" {
            return true;
        }
        let pattern_labels: Vec<&str> = self.0.split('.').collect();
        let host_labels: Vec<&str> = host.split('.').collect();
        if pattern_labels.len() != host_labels.len() {
            return false;
        }
        pattern_labels
            .iter()
            .zip(host_labels.iter())
            .all(|(p, h)| glob_match::glob_match(p, h))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let p = HostPattern::new("api.example.com");
        assert!(p.matches("api.example.com"));
        assert!(!p.matches("api.example.org"));
    }

    #[test]
    fn star_at_left_matches_one_label() {
        let p = HostPattern::new("*.example.com");
        assert!(p.matches("api.example.com"));
        assert!(p.matches("foo.example.com"));
    }

    #[test]
    fn star_does_not_match_multiple_labels() {
        let p = HostPattern::new("*.example.com");
        assert!(!p.matches("a.b.example.com"));
    }

    #[test]
    fn star_does_not_match_suffix_attack() {
        let p = HostPattern::new("*.example.com");
        assert!(!p.matches("evil.example.com.attacker.tld"));
    }

    #[test]
    fn bare_star_matches_anything() {
        let p = HostPattern::new("*");
        assert!(p.matches("anything"));
        assert!(p.matches("api.example.com"));
        assert!(p.matches(""));
    }

    #[test]
    fn question_matches_single_char_within_label() {
        let p = HostPattern::new("api?.example.com");
        assert!(p.matches("api1.example.com"));
        assert!(p.matches("apiZ.example.com"));
        assert!(!p.matches("api12.example.com"));
    }

    #[test]
    fn empty_host_does_not_match_exact_pattern() {
        let p = HostPattern::new("example.com");
        assert!(!p.matches(""));
    }
}
