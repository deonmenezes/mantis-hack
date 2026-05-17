//! Restricted cron-expression evaluator.
//!
//! Parses the Phase 4 M4.0 subset (see crate docs). The full
//! quartz-style grammar is M4.0b.

use serde::{Deserialize, Serialize};

use crate::error::SchedulerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CronExpr {
    /// Every minute.
    EveryMinute,
    /// Every N minutes, at second 0.
    EveryNMinutes(u8),
    /// Top of every hour.
    HourlyAtMinuteZero,
    /// Daily at the given hour (0..=23), minute 0.
    DailyAtHour(u8),
}

impl CronExpr {
    pub fn parse(s: &str) -> Result<Self, SchedulerError> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(SchedulerError::Cron {
                expr: s.to_owned(),
                reason: format!("expected 5 fields, got {}", parts.len()),
            });
        }
        let (minute, hour, dom, month, dow) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
        if dom != "*" || month != "*" || dow != "*" {
            return Err(SchedulerError::Cron {
                expr: s.to_owned(),
                reason: "Phase 4 M4.0 supports only `* * *` for day-of-month/month/day-of-week"
                    .into(),
            });
        }
        match (minute, hour) {
            ("*", "*") => Ok(CronExpr::EveryMinute),
            (m, "*") if m.starts_with("*/") => {
                let n: u8 = m[2..].parse().map_err(|_| SchedulerError::Cron {
                    expr: s.to_owned(),
                    reason: format!("malformed `*/N` minute: {m}"),
                })?;
                if n == 0 || n > 59 {
                    return Err(SchedulerError::Cron {
                        expr: s.to_owned(),
                        reason: format!("N in `*/N` must be 1..=59, got {n}"),
                    });
                }
                Ok(CronExpr::EveryNMinutes(n))
            }
            ("0", "*") => Ok(CronExpr::HourlyAtMinuteZero),
            ("0", h) => {
                let hour: u8 = h.parse().map_err(|_| SchedulerError::Cron {
                    expr: s.to_owned(),
                    reason: format!("malformed hour: {h}"),
                })?;
                if hour > 23 {
                    return Err(SchedulerError::Cron {
                        expr: s.to_owned(),
                        reason: format!("hour must be 0..=23, got {hour}"),
                    });
                }
                Ok(CronExpr::DailyAtHour(hour))
            }
            _ => Err(SchedulerError::Cron {
                expr: s.to_owned(),
                reason: format!("unsupported minute/hour pattern `{minute} {hour}`"),
            }),
        }
    }
}

/// Compute the next unix timestamp strictly greater than `now_unix`
/// at which the cron expression fires. UTC is assumed throughout
/// (operators wanting local-time schedules can offset before
/// calling).
#[must_use]
pub fn next_after(expr: CronExpr, now_unix: u64) -> u64 {
    match expr {
        CronExpr::EveryMinute => align_up(now_unix + 1, 60),
        CronExpr::EveryNMinutes(n) => {
            let stride = n as u64 * 60;
            align_up(now_unix + 1, stride)
        }
        CronExpr::HourlyAtMinuteZero => align_up(now_unix + 1, 3600),
        CronExpr::DailyAtHour(h) => {
            // Find the next time-of-day in UTC where hour=h and
            // minute=0. Unix time is seconds since 1970-01-01 UTC,
            // so "midnight UTC" is multiples of 86400.
            let day_start = (now_unix / 86_400) * 86_400;
            let target_today = day_start + (h as u64) * 3600;
            if target_today > now_unix {
                target_today
            } else {
                target_today + 86_400
            }
        }
    }
}

fn align_up(unix: u64, stride: u64) -> u64 {
    let r = unix % stride;
    if r == 0 {
        unix
    } else {
        unix + (stride - r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_minute() {
        assert_eq!(CronExpr::parse("* * * * *").unwrap(), CronExpr::EveryMinute);
    }

    #[test]
    fn parses_every_n_minutes() {
        assert_eq!(
            CronExpr::parse("*/5 * * * *").unwrap(),
            CronExpr::EveryNMinutes(5)
        );
    }

    #[test]
    fn parses_top_of_hour() {
        assert_eq!(
            CronExpr::parse("0 * * * *").unwrap(),
            CronExpr::HourlyAtMinuteZero
        );
    }

    #[test]
    fn parses_daily_at_hour() {
        assert_eq!(
            CronExpr::parse("0 14 * * *").unwrap(),
            CronExpr::DailyAtHour(14)
        );
    }

    #[test]
    fn rejects_unsupported_dom() {
        let e = CronExpr::parse("0 0 1 * *").unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("Phase 4 M4.0"), "got: {msg}");
    }

    #[test]
    fn rejects_zero_stride() {
        assert!(CronExpr::parse("*/0 * * * *").is_err());
    }

    #[test]
    fn rejects_too_many_fields() {
        assert!(CronExpr::parse("* * * * * *").is_err());
    }

    #[test]
    fn next_every_minute_aligns_to_minute_boundary() {
        // now = 100s (1m40s past epoch) → next = 120s (next minute).
        assert_eq!(next_after(CronExpr::EveryMinute, 100), 120);
        // Exact boundary now=60: strictly greater means next minute.
        assert_eq!(next_after(CronExpr::EveryMinute, 60), 120);
    }

    #[test]
    fn next_every_5_minutes_aligns_to_5min_boundary() {
        let stride = 5 * 60;
        // now = 12s past epoch → next at 300s.
        assert_eq!(next_after(CronExpr::EveryNMinutes(5), 12), stride);
        // At exact stride boundary, advance.
        assert_eq!(next_after(CronExpr::EveryNMinutes(5), stride), 2 * stride);
    }

    #[test]
    fn next_top_of_hour_aligns_to_hour_boundary() {
        // now = 30 min past midnight → next at 1h.
        assert_eq!(next_after(CronExpr::HourlyAtMinuteZero, 1800), 3600);
    }

    #[test]
    fn next_daily_at_hour_returns_today_or_tomorrow() {
        // now = 0 (midnight UTC). Schedule for 14:00 today.
        let next = next_after(CronExpr::DailyAtHour(14), 0);
        assert_eq!(next, 14 * 3600);
        // now = 15:00 UTC → next is 14:00 tomorrow.
        let now_15 = 15 * 3600;
        let next = next_after(CronExpr::DailyAtHour(14), now_15);
        assert_eq!(next, 14 * 3600 + 86_400);
    }
}
