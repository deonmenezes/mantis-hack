//! Operator model (Phase 3 M3.3).
//!
//! PRD §5.12.1 calls for an explicit, inspectable profile of each
//! operator's preferences derived from observed behavior. Phase 3
//! M3.3 ships the data model + signal-recording API. The
//! daemon-side hooks that feed signals (auto-promotion gating,
//! notification timing, default report format selection) follow in
//! M3.3b.
//!
//! The model is intentionally simple counters keyed by tag. The
//! profile builder exposes derived summaries (e.g. "operator
//! consistently exports SARIF"). PRD §5.12.3 mandates every signal
//! be inspectable and the profile editable; both fall out of the
//! straightforward counter-based design.

use std::collections::HashMap;

use mantis_core::OperatorId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OperatorModelError {
    #[error("operator {0} has no profile")]
    NoProfile(String),
}

/// One observed behavior signal. The model records a count per
/// distinct (tag) instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    /// Operator viewed/acknowledged a claim of this severity label.
    SeverityAttended(String),
    /// Operator exported the engagement in this report format.
    FormatExported(String),
    /// Operator manually re-verified a claim of this vuln class.
    ClaimClassReviewed(String),
    /// Operator chose to retain a Rejected claim for follow-up.
    RetainedRejectedClaim(String),
    /// Operator updated scope, indicating a workflow preference.
    ScopeEdited,
    /// Operator approved a live-target verification.
    LiveVerificationApproved,
}

impl Signal {
    /// Counter key. Two signals share a key iff they should be
    /// counted as the same observation.
    pub fn counter_key(&self) -> String {
        match self {
            Signal::SeverityAttended(s) => format!("severity:{s}"),
            Signal::FormatExported(s) => format!("format:{s}"),
            Signal::ClaimClassReviewed(s) => format!("class:{s}"),
            Signal::RetainedRejectedClaim(s) => format!("retained:{s}"),
            Signal::ScopeEdited => "scope-edited".into(),
            Signal::LiveVerificationApproved => "live-verify".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperatorProfile {
    pub operator_id: Option<OperatorId>,
    /// counter_key → count
    pub signals: HashMap<String, u64>,
}

impl OperatorProfile {
    pub fn new(operator_id: OperatorId) -> Self {
        Self {
            operator_id: Some(operator_id),
            signals: HashMap::new(),
        }
    }

    pub fn record(&mut self, signal: &Signal) {
        *self.signals.entry(signal.counter_key()).or_insert(0) += 1;
    }

    pub fn count(&self, signal: &Signal) -> u64 {
        self.signals
            .get(&signal.counter_key())
            .copied()
            .unwrap_or(0)
    }

    /// Severity threshold the operator typically engages with.
    /// Returns the highest severity label they've attended to at
    /// least twice. Returns `None` if no severity signals yet.
    pub fn likely_severity_threshold(&self) -> Option<String> {
        const ORDER: &[&str] = &["Critical", "High", "Medium", "Low", "Informational"];
        let mut best: Option<&str> = None;
        for label in ORDER {
            let key = format!("severity:{label}");
            if self.signals.get(&key).copied().unwrap_or(0) >= 2 {
                best = Some(label);
                break;
            }
        }
        best.map(|s| s.to_owned())
    }

    /// Preferred report format = the format with the most exports
    /// (ties broken by alphabetical order).
    pub fn preferred_format(&self) -> Option<String> {
        let mut candidates: Vec<(&str, u64)> = self
            .signals
            .iter()
            .filter_map(|(k, v)| k.strip_prefix("format:").map(|f| (f, *v)))
            .collect();
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        candidates.first().map(|(f, _)| (*f).to_owned())
    }

    /// Vuln classes the operator regularly reviews (count >= 3).
    pub fn frequently_reviewed_classes(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .signals
            .iter()
            .filter_map(|(k, v)| {
                if *v >= 3 {
                    k.strip_prefix("class:").map(|c| c.to_owned())
                } else {
                    None
                }
            })
            .collect();
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_core::OperatorId;
    use std::str::FromStr;

    fn op_id() -> OperatorId {
        OperatorId(ulid::Ulid::from_str("01HXXXXXXXXXXXXXXXXXXXXXXX").unwrap_or(ulid::Ulid::new()))
    }

    #[test]
    fn fresh_profile_has_no_counts() {
        let p = OperatorProfile::new(op_id());
        assert_eq!(p.count(&Signal::SeverityAttended("High".into())), 0);
        assert_eq!(p.signals.len(), 0);
    }

    #[test]
    fn record_increments_counter() {
        let mut p = OperatorProfile::default();
        for _ in 0..3 {
            p.record(&Signal::SeverityAttended("High".into()));
        }
        assert_eq!(p.count(&Signal::SeverityAttended("High".into())), 3);
    }

    #[test]
    fn different_payloads_keyed_separately() {
        let mut p = OperatorProfile::default();
        p.record(&Signal::SeverityAttended("High".into()));
        p.record(&Signal::SeverityAttended("Low".into()));
        assert_eq!(p.count(&Signal::SeverityAttended("High".into())), 1);
        assert_eq!(p.count(&Signal::SeverityAttended("Low".into())), 1);
    }

    #[test]
    fn severity_threshold_picks_highest_with_at_least_2() {
        let mut p = OperatorProfile::default();
        p.record(&Signal::SeverityAttended("Critical".into()));
        // Critical only once → not the threshold yet.
        p.record(&Signal::SeverityAttended("High".into()));
        p.record(&Signal::SeverityAttended("High".into()));
        // High twice → threshold = High.
        assert_eq!(p.likely_severity_threshold(), Some("High".into()));

        p.record(&Signal::SeverityAttended("Critical".into()));
        // Critical now twice → threshold escalates.
        assert_eq!(p.likely_severity_threshold(), Some("Critical".into()));
    }

    #[test]
    fn severity_threshold_returns_none_when_no_data() {
        let p = OperatorProfile::default();
        assert!(p.likely_severity_threshold().is_none());
    }

    #[test]
    fn preferred_format_returns_top_exporter() {
        let mut p = OperatorProfile::default();
        p.record(&Signal::FormatExported("markdown".into()));
        p.record(&Signal::FormatExported("markdown".into()));
        p.record(&Signal::FormatExported("sarif".into()));
        assert_eq!(p.preferred_format(), Some("markdown".into()));
    }

    #[test]
    fn preferred_format_alphabetical_tie_break() {
        let mut p = OperatorProfile::default();
        p.record(&Signal::FormatExported("sarif".into()));
        p.record(&Signal::FormatExported("hackerone".into()));
        // Tied counts; alphabetical (lexical asc) wins.
        assert_eq!(p.preferred_format(), Some("hackerone".into()));
    }

    #[test]
    fn frequently_reviewed_classes_requires_threshold() {
        let mut p = OperatorProfile::default();
        for _ in 0..3 {
            p.record(&Signal::ClaimClassReviewed("sqli".into()));
        }
        for _ in 0..2 {
            p.record(&Signal::ClaimClassReviewed("xss-reflected".into()));
        }
        let classes = p.frequently_reviewed_classes();
        assert_eq!(classes, vec!["sqli"]);
    }

    #[test]
    fn scope_edited_and_live_verification_count() {
        let mut p = OperatorProfile::default();
        p.record(&Signal::ScopeEdited);
        p.record(&Signal::ScopeEdited);
        p.record(&Signal::LiveVerificationApproved);
        assert_eq!(p.count(&Signal::ScopeEdited), 2);
        assert_eq!(p.count(&Signal::LiveVerificationApproved), 1);
    }

    #[test]
    fn profile_round_trips_through_serde() {
        let mut p = OperatorProfile::default();
        p.record(&Signal::SeverityAttended("High".into()));
        p.record(&Signal::FormatExported("sarif".into()));
        let json = serde_json::to_string(&p).unwrap();
        let back: OperatorProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signals.len(), 2);
        assert_eq!(back.count(&Signal::SeverityAttended("High".into())), 1);
    }
}
