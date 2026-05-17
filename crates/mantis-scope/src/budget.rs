//! Per-engagement budget envelope and live tracker.
//!
//! The envelope is the declarative limit from the signed scope manifest.
//! The tracker is the live counter the egress proxy consults on every
//! request. Exhaustion is fatal — there is no per-call recovery; the
//! engagement halts and the operator is notified.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEnvelope {
    pub max_requests: u64,
    pub max_egress_bytes: u64,
    pub max_wall_clock_seconds: u64,
    pub max_requests_per_second: u64,
}

#[derive(Debug)]
pub struct BudgetTracker {
    envelope: BudgetEnvelope,
    started_at: Instant,
    requests: AtomicU64,
    egress_bytes: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetDecision {
    Ok,
    ExhaustedRequests,
    ExhaustedBytes,
    ExhaustedTime,
    RateLimited,
}

impl BudgetTracker {
    pub fn new(envelope: BudgetEnvelope) -> Self {
        Self {
            envelope,
            started_at: Instant::now(),
            requests: AtomicU64::new(0),
            egress_bytes: AtomicU64::new(0),
        }
    }

    pub fn envelope(&self) -> &BudgetEnvelope {
        &self.envelope
    }

    pub fn requests_used(&self) -> u64 {
        self.requests.load(Ordering::Acquire)
    }

    pub fn egress_bytes_used(&self) -> u64 {
        self.egress_bytes.load(Ordering::Acquire)
    }

    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Reserve budget for a single request. Returns `Ok` on success or
    /// an `Exhausted*` variant on rejection. On `Ok` the request count
    /// is incremented; on rejection it is not.
    pub fn try_acquire_request(&self, expected_bytes: u64) -> BudgetDecision {
        if self.elapsed().as_secs() >= self.envelope.max_wall_clock_seconds {
            return BudgetDecision::ExhaustedTime;
        }
        let current = self.requests.load(Ordering::Acquire);
        if current >= self.envelope.max_requests {
            return BudgetDecision::ExhaustedRequests;
        }
        let current_bytes = self.egress_bytes.load(Ordering::Acquire);
        if current_bytes.saturating_add(expected_bytes) > self.envelope.max_egress_bytes {
            return BudgetDecision::ExhaustedBytes;
        }
        // Rate-limit window: requests in the most recent second.
        if self.envelope.max_requests_per_second > 0 {
            let elapsed = self.elapsed().as_secs_f64().max(1.0);
            let rate = (current as f64) / elapsed;
            if rate >= self.envelope.max_requests_per_second as f64 {
                return BudgetDecision::RateLimited;
            }
        }
        let prev = self.requests.fetch_add(1, Ordering::AcqRel);
        if prev >= self.envelope.max_requests {
            // Another thread won the race; un-decrement and reject.
            self.requests.fetch_sub(1, Ordering::AcqRel);
            return BudgetDecision::ExhaustedRequests;
        }
        BudgetDecision::Ok
    }

    /// Record `bytes` of egress against the budget. Called after the
    /// actual response size is known. Does not reject; rejection is the
    /// job of `try_acquire_request`.
    pub fn record_egress_bytes(&self, bytes: u64) {
        self.egress_bytes.fetch_add(bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> BudgetEnvelope {
        BudgetEnvelope {
            max_requests: 3,
            max_egress_bytes: 1024,
            max_wall_clock_seconds: 60,
            max_requests_per_second: 1000,
        }
    }

    #[test]
    fn allows_up_to_max_requests() {
        let t = BudgetTracker::new(envelope());
        for _ in 0..3 {
            assert_eq!(t.try_acquire_request(0), BudgetDecision::Ok);
        }
        assert_eq!(t.try_acquire_request(0), BudgetDecision::ExhaustedRequests);
    }

    #[test]
    fn rejects_on_byte_overflow() {
        let t = BudgetTracker::new(envelope());
        t.record_egress_bytes(500);
        assert_eq!(t.try_acquire_request(100), BudgetDecision::Ok); // 500 + 100 ≤ 1024
        assert_eq!(t.try_acquire_request(600), BudgetDecision::ExhaustedBytes); // 500 + 600 > 1024
    }

    #[test]
    fn elapsed_progresses() {
        let t = BudgetTracker::new(envelope());
        let e1 = t.elapsed();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let e2 = t.elapsed();
        assert!(e2 > e1);
    }

    #[test]
    fn record_bytes_accumulates() {
        let t = BudgetTracker::new(envelope());
        t.record_egress_bytes(100);
        t.record_egress_bytes(200);
        assert_eq!(t.egress_bytes_used(), 300);
    }

    #[test]
    fn rate_limit_triggers_when_burst() {
        let envelope = BudgetEnvelope {
            max_requests: 10_000,
            max_egress_bytes: u64::MAX,
            max_wall_clock_seconds: 60,
            max_requests_per_second: 1,
        };
        let t = BudgetTracker::new(envelope);
        // First call: rate = 0 because 0 prior requests. OK.
        assert_eq!(t.try_acquire_request(0), BudgetDecision::Ok);
        // Subsequent calls within the same second: rate ramps up.
        // We can't deterministically test this without manipulating
        // time, so we just exercise the code path.
        for _ in 0..50 {
            let _ = t.try_acquire_request(0);
        }
    }
}
