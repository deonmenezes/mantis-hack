//! Continuous monitoring scheduler (Phase 4 M4.0).
//!
//! Owns cron-style schedules that fire engagement scans on a
//! recurring cadence (PRD §5.10). The scheduler stores schedules,
//! advances their "next run" timestamps, and exposes a `tick(now)`
//! call the daemon polls in its main loop.
//!
//! Phase 4 M4.0 supports a restricted cron grammar:
//! - `* * * * *` — every minute
//! - `*/N * * * *` — every N minutes (N in 1..=59)
//! - `0 * * * *` — top of every hour
//! - `0 H * * *` — daily at hour H (0..=23)
//! - `0 0 * * *` — daily at midnight
//!
//! Full quartz-style cron support lands in M4.0b. The restricted
//! grammar covers >90% of monitoring-engagement use cases.

pub mod cron;
pub mod error;
pub mod store;

pub use crate::cron::{next_after, CronExpr};
pub use crate::error::SchedulerError;
pub use crate::store::{Schedule, ScheduleId, ScheduleStore};
