//! Severity inference for Phase 1 reports.
//!
//! Phase 1 uses a small hand-tuned table mapping vulnerability class
//! to severity. Phase 2 introduces proper CVSS v4 calculation per
//! PRD §5.9.2, but the inference table remains a reasonable default
//! for vuln classes that don't yet have CVSS vectors authored.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Higher rank = higher severity.
    pub fn rank(self) -> u32 {
        match self {
            Severity::Informational => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Informational => "Informational",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        })
    }
}

/// Map a vulnerability class string to severity. Unknown classes
/// default to `Informational`.
pub fn severity_for(vuln_class: &str) -> Severity {
    match vuln_class {
        "sqli" | "rce" | "deserialization" => Severity::Critical,
        "auth-bypass" | "broken-access-control" | "idor" | "ssrf" | "xxe" => Severity::High,
        "xss-reflected" | "xss-stored" | "open-redirect" | "csrf" | "weak-auth"
        | "cors-misconfig" => Severity::Medium,
        "info-disclosure" | "missing-security-headers" | "clickjacking" => Severity::Low,
        "api-enumeration" | "nginx-recon" | "apache-recon" | "iis-recon" => Severity::Informational,
        _ => Severity::Informational,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_outranks_others() {
        assert!(Severity::Critical.rank() > Severity::High.rank());
        assert!(Severity::High.rank() > Severity::Medium.rank());
        assert!(Severity::Medium.rank() > Severity::Low.rank());
        assert!(Severity::Low.rank() > Severity::Informational.rank());
    }

    #[test]
    fn known_classes_map() {
        assert_eq!(severity_for("sqli"), Severity::Critical);
        assert_eq!(severity_for("idor"), Severity::High);
        assert_eq!(severity_for("xss-reflected"), Severity::Medium);
        assert_eq!(severity_for("info-disclosure"), Severity::Low);
        assert_eq!(severity_for("api-enumeration"), Severity::Informational);
    }

    #[test]
    fn unknown_class_defaults_to_informational() {
        assert_eq!(severity_for("some-novel-class"), Severity::Informational);
    }

    #[test]
    fn display_renders() {
        assert_eq!(format!("{}", Severity::Critical), "Critical");
    }
}
