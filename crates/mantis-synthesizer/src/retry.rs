//! Shared retry policy for LLM adapters.
//!
//! Implements bounded exponential backoff with `Retry-After` header
//! respect. Retries are scheduled for transient HTTP statuses:
//! - `429 Too Many Requests` (rate limited)
//! - `502 Bad Gateway`, `503 Service Unavailable`, `504 Gateway Timeout`
//!
//! 4xx other than 429 and 408 surface immediately — those are
//! request-side errors and re-issuing won't help.

use std::time::Duration;

/// Retry decision returned from [`classify_response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Request succeeded. Do not retry.
    Done,
    /// Request failed with a non-retryable status. Surface to caller.
    Fatal,
    /// Request failed but is retryable. Sleep for the bundled
    /// duration, then retry. The duration honors `Retry-After`
    /// when present; otherwise falls back to exponential backoff.
    Retry(Duration),
}

/// Configuration for a retry loop. Defaults: 4 attempts, 250ms base
/// delay, 8s max delay. These keep total wall-clock latency
/// bounded even when the upstream returns 429 every call.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(8),
        }
    }
}

impl RetryPolicy {
    /// Compute the backoff for the n-th retry (n starts at 1).
    /// Honors `retry_after` when the server provided one.
    pub fn backoff_for(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        if let Some(ra) = retry_after {
            return ra.min(self.max_delay);
        }
        let exp = self
            .base_delay
            .saturating_mul(2u32.saturating_pow(attempt.saturating_sub(1)));
        exp.min(self.max_delay)
    }
}

/// Classify an HTTP status + optional `Retry-After` header into a
/// retry decision. Pure function so callers can unit-test their
/// retry behavior without spinning a network mock.
pub fn classify_status(
    status: u16,
    retry_after: Option<Duration>,
    policy: &RetryPolicy,
    attempt: u32,
) -> RetryDecision {
    if (200..300).contains(&status) {
        return RetryDecision::Done;
    }
    if attempt >= policy.max_attempts {
        return RetryDecision::Fatal;
    }
    let retryable = matches!(status, 408 | 429 | 502 | 503 | 504);
    if retryable {
        RetryDecision::Retry(policy.backoff_for(attempt, retry_after))
    } else {
        RetryDecision::Fatal
    }
}

/// Parse a `Retry-After` header value. Accepts both:
/// - integer seconds: `Retry-After: 30`
/// - HTTP-date: `Retry-After: Wed, 21 Oct 2026 07:28:00 GMT`
///   (returns `None` — we don't carry a date parser; callers fall
///   back to exponential backoff)
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    value.trim().parse::<u64>().ok().map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_status_yields_done() {
        let policy = RetryPolicy::default();
        assert_eq!(classify_status(200, None, &policy, 1), RetryDecision::Done);
        assert_eq!(classify_status(204, None, &policy, 3), RetryDecision::Done);
    }

    #[test]
    fn rate_limit_yields_retry_with_backoff() {
        let policy = RetryPolicy::default();
        match classify_status(429, None, &policy, 1) {
            RetryDecision::Retry(d) => assert_eq!(d, Duration::from_millis(250)),
            other => panic!("expected Retry, got {other:?}"),
        }
    }

    #[test]
    fn rate_limit_respects_retry_after_header() {
        let policy = RetryPolicy::default();
        let ra = parse_retry_after("3").unwrap();
        match classify_status(429, Some(ra), &policy, 1) {
            RetryDecision::Retry(d) => assert_eq!(d, Duration::from_secs(3)),
            other => panic!("expected Retry, got {other:?}"),
        }
    }

    #[test]
    fn retry_after_capped_at_max_delay() {
        let policy = RetryPolicy {
            max_attempts: 4,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(2),
        };
        let ra = parse_retry_after("3600").unwrap();
        match classify_status(429, Some(ra), &policy, 1) {
            RetryDecision::Retry(d) => assert_eq!(d, Duration::from_secs(2)),
            other => panic!("expected capped Retry, got {other:?}"),
        }
    }

    #[test]
    fn server_5xx_retryable_subset_yields_retry() {
        let policy = RetryPolicy::default();
        for status in [502, 503, 504] {
            assert!(matches!(
                classify_status(status, None, &policy, 1),
                RetryDecision::Retry(_)
            ));
        }
    }

    #[test]
    fn client_4xx_other_than_429_408_is_fatal() {
        let policy = RetryPolicy::default();
        for status in [400, 401, 403, 404, 422] {
            assert_eq!(
                classify_status(status, None, &policy, 1),
                RetryDecision::Fatal,
                "status {status} should be fatal"
            );
        }
    }

    #[test]
    fn retry_exhausted_after_max_attempts() {
        let policy = RetryPolicy {
            max_attempts: 3,
            ..Default::default()
        };
        // Attempt 3 hits the cap — even a retryable status should
        // surface as Fatal.
        assert_eq!(classify_status(429, None, &policy, 3), RetryDecision::Fatal);
    }

    #[test]
    fn backoff_grows_exponentially() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.backoff_for(1, None), Duration::from_millis(250));
        assert_eq!(policy.backoff_for(2, None), Duration::from_millis(500));
        assert_eq!(policy.backoff_for(3, None), Duration::from_secs(1));
        assert_eq!(policy.backoff_for(4, None), Duration::from_secs(2));
        assert_eq!(policy.backoff_for(5, None), Duration::from_secs(4));
        // Cap at max_delay (8s default).
        assert_eq!(policy.backoff_for(20, None), Duration::from_secs(8));
    }

    #[test]
    fn parse_retry_after_integer() {
        assert_eq!(parse_retry_after("5"), Some(Duration::from_secs(5)));
        assert_eq!(parse_retry_after("0"), Some(Duration::from_secs(0)));
    }

    #[test]
    fn parse_retry_after_handles_date_form_by_giving_up() {
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after(""), None);
    }
}
