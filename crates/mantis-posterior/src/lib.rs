//! Beta-posterior update layer.
//!
//! Phase 1 M1.4 introduces per-(stack, vuln_class) Beta posteriors
//! that replace the planner's static priors once enough real
//! outcomes accumulate.
//!
//! Model: each (stack_fingerprint, vuln_class) bucket holds a Beta(α, β)
//! distribution. α starts at 1 (one virtual success), β at 1 (one virtual
//! failure). Each Confirmed+Verified outcome adds 1 to α; each
//! Confirmed-but-Rejected or Denied outcome adds 1 to β.
//! Retained outcomes are excluded (per ADR-0012 they're not a clean
//! signal). Mean of the posterior is `α / (α + β)`.
//!
//! Blending with static priors: until we've seen
//! [`BLEND_THRESHOLD_OBSERVATIONS`] real outcomes in a bucket, we
//! interpolate between the static prior (from the hypothesis catalog)
//! and the empirical posterior so brand-new buckets aren't dominated
//! by their initial Beta(1, 1) = 0.5 mean.

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Number of observations after which the empirical posterior fully
/// replaces the static prior.
pub const BLEND_THRESHOLD_OBSERVATIONS: u32 = 10;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct BetaPosterior {
    pub alpha: f64,
    pub beta: f64,
}

impl Default for BetaPosterior {
    fn default() -> Self {
        Self::uniform()
    }
}

impl BetaPosterior {
    /// Beta(1, 1) — uniform on [0, 1].
    pub const fn uniform() -> Self {
        Self {
            alpha: 1.0,
            beta: 1.0,
        }
    }

    pub fn record_success(&mut self) {
        self.alpha += 1.0;
    }

    pub fn record_failure(&mut self) {
        self.beta += 1.0;
    }

    /// Empirical mean = α / (α + β).
    #[must_use]
    pub fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Number of real observations (excludes the uniform-prior +1/+1).
    #[must_use]
    pub fn observations(&self) -> u32 {
        // alpha + beta - 2 (the two virtual observations) gives the
        // real-observation count. Floor at 0.
        let n = (self.alpha + self.beta - 2.0).max(0.0);
        n as u32
    }

    /// 95% credible interval bounds. Uses the Wilson-style normal
    /// approximation; tight enough for operator display. Phase 2
    /// switches to a real Beta-quantile function.
    #[must_use]
    pub fn credible_interval_95(&self) -> (f64, f64) {
        let n = self.alpha + self.beta;
        let mean = self.mean();
        let variance = mean * (1.0 - mean) / (n + 1.0);
        let z = 1.96;
        let halfwidth = z * variance.sqrt();
        ((mean - halfwidth).max(0.0), (mean + halfwidth).min(1.0))
    }
}

/// Combine a [`BetaPosterior`] with a static prior so brand-new
/// buckets aren't anchored to Beta(1, 1) = 0.5. Returns the blended
/// rate in parts per 10,000 (basis points).
#[must_use]
pub fn blend_pp10k(posterior: BetaPosterior, static_pp10k: u32) -> u32 {
    let obs = posterior.observations();
    if obs >= BLEND_THRESHOLD_OBSERVATIONS {
        return (posterior.mean() * 10_000.0) as u32;
    }
    let posterior_weight = obs as f64 / BLEND_THRESHOLD_OBSERVATIONS as f64;
    let static_weight = 1.0 - posterior_weight;
    let blended =
        posterior.mean() * posterior_weight + (static_pp10k as f64 / 10_000.0) * static_weight;
    (blended * 10_000.0) as u32
}

/// Thread-safe store keyed by `(stack_fingerprint, vuln_class)`.
#[derive(Debug, Default)]
pub struct Posteriors {
    inner: RwLock<HashMap<(String, String), BetaPosterior>>,
}

impl Posteriors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn posterior_for(&self, stack: &str, vuln_class: &str) -> BetaPosterior {
        let key = (stack.to_owned(), vuln_class.to_owned());
        let guard = self.inner.read().expect("posteriors lock poisoned");
        *guard.get(&key).unwrap_or(&BetaPosterior::uniform())
    }

    pub fn record_outcome(&self, stack: &str, vuln_class: &str, success: bool) {
        let key = (stack.to_owned(), vuln_class.to_owned());
        let mut guard = self.inner.write().expect("posteriors lock poisoned");
        let entry = guard.entry(key).or_insert_with(BetaPosterior::uniform);
        if success {
            entry.record_success();
        } else {
            entry.record_failure();
        }
    }

    /// Convenience: feed the blended `pp10k` rate that the planner
    /// should use as the prior for an action against this
    /// `(stack, vuln_class)` bucket.
    pub fn blended_prior(&self, stack: &str, vuln_class: &str, static_pp10k: u32) -> u32 {
        let posterior = self.posterior_for(stack, vuln_class);
        blend_pp10k(posterior, static_pp10k)
    }

    /// Snapshot every bucket. Used for hibernation and reporting.
    pub fn snapshot(&self) -> Vec<((String, String), BetaPosterior)> {
        let guard = self.inner.read().expect("posteriors lock poisoned");
        guard.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    /// Restore a snapshot. Used when loading a hibernated workspace.
    pub fn restore(&self, items: Vec<((String, String), BetaPosterior)>) {
        let mut guard = self.inner.write().expect("posteriors lock poisoned");
        for (k, v) in items {
            guard.insert(k, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_mean_is_half() {
        assert!((BetaPosterior::uniform().mean() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn success_updates_alpha() {
        let mut p = BetaPosterior::uniform();
        p.record_success();
        assert!((p.alpha - 2.0).abs() < 1e-9);
        assert!((p.beta - 1.0).abs() < 1e-9);
        assert!(p.mean() > 0.5);
    }

    #[test]
    fn many_successes_approach_one() {
        let mut p = BetaPosterior::uniform();
        for _ in 0..100 {
            p.record_success();
        }
        assert!(p.mean() > 0.95);
    }

    #[test]
    fn balanced_outcomes_approach_half() {
        let mut p = BetaPosterior::uniform();
        for _ in 0..50 {
            p.record_success();
            p.record_failure();
        }
        assert!((p.mean() - 0.5).abs() < 0.05);
    }

    #[test]
    fn observations_count_excludes_uniform_prior() {
        let mut p = BetaPosterior::uniform();
        assert_eq!(p.observations(), 0);
        for _ in 0..7 {
            p.record_success();
        }
        for _ in 0..3 {
            p.record_failure();
        }
        assert_eq!(p.observations(), 10);
    }

    #[test]
    fn credible_interval_brackets_the_mean() {
        let mut p = BetaPosterior::uniform();
        for _ in 0..50 {
            p.record_success();
        }
        for _ in 0..50 {
            p.record_failure();
        }
        let (low, high) = p.credible_interval_95();
        assert!(low <= 0.5 && 0.5 <= high);
        assert!(high - low > 0.0);
    }

    #[test]
    fn blend_uses_static_prior_when_no_observations() {
        let p = BetaPosterior::uniform();
        // Static prior 3000 = 30%. Blended with empty posterior (mean 0.5):
        // weight 1.0 on static. Result = 3000.
        assert_eq!(blend_pp10k(p, 3000), 3000);
    }

    #[test]
    fn blend_uses_posterior_when_threshold_reached() {
        let mut p = BetaPosterior::uniform();
        for _ in 0..BLEND_THRESHOLD_OBSERVATIONS {
            p.record_success();
        }
        // Mean is 11/12 ≈ 0.917. blend_pp10k should ignore static
        // prior entirely.
        let blended = blend_pp10k(p, 50);
        assert!(blended > 8000, "got {blended}");
    }

    #[test]
    fn blend_interpolates_when_below_threshold() {
        let mut p = BetaPosterior::uniform();
        // 5 successes, 0 failures = 5 observations. Half-blended.
        for _ in 0..5 {
            p.record_success();
        }
        let blended = blend_pp10k(p, 100);
        // 50% weight on posterior (~0.857), 50% on static (0.01).
        let expected_mid = 0.5 * (6.0 / 7.0 + 0.01) * 10_000.0;
        assert!(
            (blended as f64 - expected_mid).abs() < 200.0,
            "got {blended}, expected near {expected_mid}"
        );
    }

    #[test]
    fn posteriors_store_round_trip() {
        let store = Posteriors::new();
        let initial = store.posterior_for("nginx", "info-disclosure");
        assert_eq!(initial, BetaPosterior::uniform());
        store.record_outcome("nginx", "info-disclosure", true);
        store.record_outcome("nginx", "info-disclosure", true);
        store.record_outcome("nginx", "info-disclosure", false);
        let updated = store.posterior_for("nginx", "info-disclosure");
        assert_eq!(updated.observations(), 3);
        assert!(updated.mean() > 0.5);
    }

    #[test]
    fn snapshot_restores_buckets() {
        let store = Posteriors::new();
        store.record_outcome("nginx", "xss-reflected", true);
        store.record_outcome("apache", "sqli", false);
        let snapshot = store.snapshot();
        assert_eq!(snapshot.len(), 2);

        let new_store = Posteriors::new();
        new_store.restore(snapshot);
        let nginx = new_store.posterior_for("nginx", "xss-reflected");
        let apache = new_store.posterior_for("apache", "sqli");
        assert_eq!(nginx.observations(), 1);
        assert_eq!(apache.observations(), 1);
        assert!(nginx.mean() > 0.5);
        assert!(apache.mean() < 0.5);
    }

    #[test]
    fn separate_keys_are_independent() {
        let store = Posteriors::new();
        store.record_outcome("nginx", "xss-reflected", true);
        store.record_outcome("nginx", "xss-reflected", true);
        // Different vuln_class: untouched.
        assert_eq!(
            store.posterior_for("nginx", "sqli"),
            BetaPosterior::uniform()
        );
        // Different stack: untouched.
        assert_eq!(
            store.posterior_for("apache", "xss-reflected"),
            BetaPosterior::uniform()
        );
    }
}
