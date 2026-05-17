//! Benchmark fixtures shared across the criterion `benches/` files.
//!
//! Targets these PRD §11 numbers:
//!
//! | Metric | Target |
//! |---|---|
//! | Daemon cold start | ≤200 ms |
//! | Engagement start to first packet | ≤1 s |
//! | First verified claim, typical web target | ≤90 s |
//! | Sustained HTTP throughput, 16-core host | ≥50,000 req/s |
//! | Median experiment latency, warm connection | ≤30 ms |
//! | Hibernation snapshot | ≤2 s |
//! | Hibernation restore | ≤3 s |
//! | Plugin warm-instance invocation overhead | ≤500 µs |
//! | Concurrent engagements per host | ≥100 |
//! | Event log query latency, 1B events | ≤1 s |
//!
//! Each criterion benchmark below records the median observed
//! latency. Comparing to the targets is the operator's job:
//! `cargo bench -p mantis-benches` produces criterion HTML reports
//! under `target/criterion/`, and CI can fail on regression via
//! `criterion::Throughput`.

pub const TARGET_COLD_START_MS: u32 = 200;
pub const TARGET_FIRST_PACKET_MS: u32 = 1000;
pub const TARGET_FIRST_CLAIM_MS: u32 = 90_000;
pub const TARGET_HTTP_THROUGHPUT_RPS: u32 = 50_000;
pub const TARGET_EXPERIMENT_LATENCY_MS: u32 = 30;
pub const TARGET_HIBERNATION_SNAPSHOT_MS: u32 = 2000;
pub const TARGET_HIBERNATION_RESTORE_MS: u32 = 3000;
pub const TARGET_PLUGIN_INVOCATION_US: u32 = 500;
pub const TARGET_CONCURRENT_ENGAGEMENTS: u32 = 100;
pub const TARGET_EVENT_LOG_QUERY_MS: u32 = 1000;
