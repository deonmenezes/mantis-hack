//! Reactor-per-core actor placement (PRD §7.2).
//!
//! PRD §7.2 calls for a Tokio-based reactor-per-core layout with
//! shared-nothing actor pinning and NUMA-aware placement on
//! multi-socket hosts. This crate provides the placement primitives:
//!
//! - [`available_cores`] — enumerate cores the process can pin to
//! - [`pin_current_to`] — pin the calling thread to a specific core
//! - [`ReactorPool::build`] — spawn one Tokio current-thread runtime
//!   per available core, each pinned, and run a task on each
//! - [`numa_groups`] — bucket cores by reported NUMA locality
//!
//! Platform support:
//! - Linux: real pinning via `sched_setaffinity` through
//!   `core_affinity`
//! - macOS / Windows: pinning is best-effort; the function still
//!   succeeds (the OS schedules where it pleases). Tests assert the
//!   API contract — they do not assert physical-core residence.
//!
//! NUMA bucketing currently treats every available core as a member
//! of a single group when topology data isn't accessible. On Linux
//! hosts with sysfs, a future revision can read
//! `/sys/devices/system/node/node*/cpulist` to refine groups; the
//! placement API does not change.

use std::sync::Arc;
use std::thread;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("no usable cores reported by the OS")]
    NoCores,

    #[error("failed to build per-core tokio runtime: {0}")]
    BuildRuntime(String),

    #[error("reactor task panicked: {0}")]
    Panicked(String),
}

/// Snapshot of the cores the calling process can affinity-pin to.
/// On macOS and Windows this falls back to `num_cpus::get`.
pub fn available_cores() -> Vec<CoreId> {
    core_affinity::get_core_ids()
        .map(|ids| ids.into_iter().map(|c| CoreId(c.id)).collect())
        .unwrap_or_else(|| (0..num_cpus::get()).map(CoreId).collect())
}

/// Physical core identifier as reported by the OS. Wraps the raw
/// `usize` so callers cannot mix it with arbitrary indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoreId(pub usize);

/// Pin the calling thread to `core`. Returns `true` if the OS
/// accepted the request, `false` otherwise (macOS / Windows always
/// returns `false` because affinity isn't exposed). The function
/// never panics.
pub fn pin_current_to(core: CoreId) -> bool {
    core_affinity::set_for_current(core_affinity::CoreId { id: core.0 })
}

/// Group cores by NUMA locality. Today this returns a single group
/// (all cores) on every platform. Future revisions add sysfs-based
/// bucketing on Linux; the API is stable so callers can rely on
/// `groups.len() >= 1` and `groups.iter().flatten()` covering every
/// available core.
pub fn numa_groups() -> Vec<Vec<CoreId>> {
    let cores = available_cores();
    if cores.is_empty() {
        return Vec::new();
    }
    vec![cores]
}

/// Spawn one OS thread per available core, each running a pinned
/// `tokio::runtime::current_thread` runtime that drives the
/// provided task closure. Returns when every per-core task has
/// finished.
pub struct ReactorPool;

impl ReactorPool {
    /// Build the pool and run `task_fn(core_id)` on every core.
    /// The task closure must be `Send + Sync` (called from one OS
    /// thread per core) and produce an `async` future that runs on
    /// the corresponding current-thread runtime.
    pub fn build<F, Fut>(task_fn: F) -> Result<(), RuntimeError>
    where
        F: Fn(CoreId) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + 'static,
    {
        let cores = available_cores();
        if cores.is_empty() {
            return Err(RuntimeError::NoCores);
        }
        let task_fn = Arc::new(task_fn);
        let mut handles: Vec<thread::JoinHandle<Result<(), RuntimeError>>> = Vec::new();
        for core in cores {
            let task_fn = task_fn.clone();
            let handle = thread::Builder::new()
                .name(format!("mantis-reactor-{}", core.0))
                .spawn(move || -> Result<(), RuntimeError> {
                    let _pinned = pin_current_to(core);
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| RuntimeError::BuildRuntime(e.to_string()))?;
                    rt.block_on(task_fn(core));
                    Ok(())
                })
                .map_err(|e| RuntimeError::BuildRuntime(e.to_string()))?;
            handles.push(handle);
        }
        for h in handles {
            match h.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(panic) => {
                    return Err(RuntimeError::Panicked(format!("{panic:?}")));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn available_cores_returns_at_least_one() {
        let cores = available_cores();
        assert!(!cores.is_empty());
    }

    #[test]
    fn numa_groups_cover_every_available_core() {
        let cores = available_cores();
        let groups = numa_groups();
        assert!(!groups.is_empty());
        let flat: Vec<CoreId> = groups.into_iter().flatten().collect();
        assert_eq!(flat.len(), cores.len());
    }

    #[test]
    fn pin_current_to_does_not_panic_on_any_platform() {
        let cores = available_cores();
        // Result may be false on macOS/Windows but the call must
        // never panic. Only the API contract is asserted.
        let _ = pin_current_to(cores[0]);
    }

    #[test]
    fn reactor_pool_runs_task_on_every_core() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();
        ReactorPool::build(move |_core| {
            let count = count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
            }
        })
        .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), available_cores().len());
    }

    #[test]
    fn reactor_pool_passes_distinct_core_ids() {
        use std::sync::Mutex;
        let seen: Arc<Mutex<Vec<CoreId>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = seen.clone();
        ReactorPool::build(move |core| {
            let seen = seen_clone.clone();
            async move {
                seen.lock().unwrap().push(core);
            }
        })
        .unwrap();
        let mut ids = seen.lock().unwrap().clone();
        ids.sort_by_key(|c| c.0);
        let mut expected: Vec<CoreId> = available_cores();
        expected.sort_by_key(|c| c.0);
        assert_eq!(ids, expected);
    }

    #[test]
    fn core_id_is_copy_and_hashable() {
        use std::collections::HashSet;
        let a = CoreId(0);
        let b = a; // Copy
        let mut set: HashSet<CoreId> = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }
}
