//! Rule-based hypothesis generator.
//!
//! Takes a [`Surface`] discovered by the scanner and runs it through a
//! catalog of pattern-matching rules. Each rule that matches emits a
//! [`HypothesisData`] with a Phase-0 static prior (parts per
//! ten-thousand). M0.5b will swap the static priors for
//! workspace-derived Bayesian posteriors.
//!
//! Priors are integers (parts per 10,000) rather than f64 to satisfy
//! ADR-0002's no-floats-in-events rule.

use mantis_scanner_http::Surface;
use serde::{Deserialize, Serialize};

pub mod error;
pub mod rules;

pub use crate::error::HypothesisError;
pub use crate::rules::generate;

/// A single hypothesis emitted by the rule catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HypothesisData {
    /// Vulnerability class identifier (e.g. `idor`, `xss-reflected`).
    pub vuln_class: String,
    /// Human-readable summary the rule wrote.
    pub summary: String,
    /// Prior probability in parts per 10,000 (basis-points-style).
    pub prior_pp10k: u32,
}

/// Run the full catalog over `surface` and return matching
/// hypotheses, ordered by descending prior.
pub fn generate_for(surface: &Surface) -> Vec<HypothesisData> {
    let mut out = generate(surface);
    out.sort_by_key(|h| std::cmp::Reverse(h.prior_pp10k));
    out
}
