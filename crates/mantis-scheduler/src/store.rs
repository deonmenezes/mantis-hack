//! Schedule store. Thread-safe HashMap of schedule_id → Schedule.

use std::collections::HashMap;
use std::sync::RwLock;

use mantis_core::EngagementId;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::cron::{next_after, CronExpr};
use crate::error::SchedulerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScheduleId(pub Ulid);

impl ScheduleId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }
}

impl Default for ScheduleId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub id: ScheduleId,
    pub engagement_id: EngagementId,
    pub cron: CronExpr,
    pub created_at_unix: u64,
    pub next_run_unix: u64,
    pub last_run_unix: Option<u64>,
}

#[derive(Debug, Default)]
pub struct ScheduleStore {
    inner: RwLock<HashMap<ScheduleId, Schedule>>,
}

impl ScheduleStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(
        &self,
        engagement_id: EngagementId,
        cron: CronExpr,
        now_unix: u64,
    ) -> Result<ScheduleId, SchedulerError> {
        let id = ScheduleId::new();
        let schedule = Schedule {
            id,
            engagement_id,
            cron,
            created_at_unix: now_unix,
            next_run_unix: next_after(cron, now_unix),
            last_run_unix: None,
        };
        self.inner
            .write()
            .map_err(|_| SchedulerError::Poisoned)?
            .insert(id, schedule);
        Ok(id)
    }

    pub fn remove(&self, id: ScheduleId) -> Result<(), SchedulerError> {
        self.inner
            .write()
            .map_err(|_| SchedulerError::Poisoned)?
            .remove(&id)
            .ok_or_else(|| SchedulerError::NotFound {
                id: id.0.to_string(),
            })
            .map(|_| ())
    }

    pub fn list(&self) -> Result<Vec<Schedule>, SchedulerError> {
        let guard = self.inner.read().map_err(|_| SchedulerError::Poisoned)?;
        Ok(guard.values().cloned().collect())
    }

    pub fn get(&self, id: ScheduleId) -> Result<Option<Schedule>, SchedulerError> {
        let guard = self.inner.read().map_err(|_| SchedulerError::Poisoned)?;
        Ok(guard.get(&id).cloned())
    }

    /// Return the schedules whose `next_run_unix <= now_unix`, then
    /// advance them. Each schedule fires at most once per tick
    /// regardless of how far behind it is — catch-up is intentional
    /// (we don't want a daemon that was offline for hours to thunder
    /// every cron at once).
    pub fn tick(&self, now_unix: u64) -> Result<Vec<Schedule>, SchedulerError> {
        let mut guard = self.inner.write().map_err(|_| SchedulerError::Poisoned)?;
        let mut due: Vec<Schedule> = vec![];
        for schedule in guard.values_mut() {
            if schedule.next_run_unix <= now_unix {
                due.push(schedule.clone());
                schedule.last_run_unix = Some(now_unix);
                schedule.next_run_unix = next_after(schedule.cron, now_unix);
            }
        }
        Ok(due)
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn eng_id() -> EngagementId {
        EngagementId(Ulid::new())
    }

    #[test]
    fn add_then_list() {
        let store = ScheduleStore::new();
        let id1 = store.add(eng_id(), CronExpr::EveryMinute, 0).unwrap();
        let id2 = store
            .add(eng_id(), CronExpr::HourlyAtMinuteZero, 0)
            .unwrap();
        assert_eq!(store.len(), 2);
        let list = store.list().unwrap();
        assert!(list.iter().any(|s| s.id == id1));
        assert!(list.iter().any(|s| s.id == id2));
    }

    #[test]
    fn remove_unloads() {
        let store = ScheduleStore::new();
        let id = store.add(eng_id(), CronExpr::EveryMinute, 0).unwrap();
        store.remove(id).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn remove_missing_errors() {
        let store = ScheduleStore::new();
        assert!(store.remove(ScheduleId::new()).is_err());
    }

    #[test]
    fn tick_returns_due_schedules_and_advances() {
        let store = ScheduleStore::new();
        let now = 0;
        let id = store.add(eng_id(), CronExpr::EveryMinute, now).unwrap();
        // At t=0 the schedule was just added; next_run is at the
        // first minute boundary > 0, which is 60.
        let due_at_30 = store.tick(30).unwrap();
        assert!(due_at_30.is_empty(), "nothing due before 60");
        let due_at_60 = store.tick(60).unwrap();
        assert_eq!(due_at_60.len(), 1);
        assert_eq!(due_at_60[0].id, id);
        // Next run advanced to 120 (catch-up: at most one fire per tick).
        let schedule = store.get(id).unwrap().unwrap();
        assert_eq!(schedule.next_run_unix, 120);
        assert_eq!(schedule.last_run_unix, Some(60));
    }

    #[test]
    fn tick_does_not_thunder_when_behind() {
        // Add a schedule, simulate a long gap, ensure only one fire.
        let store = ScheduleStore::new();
        let id = store.add(eng_id(), CronExpr::EveryMinute, 0).unwrap();
        // Advance 3 hours = 180 minutes. EveryMinute would have fired
        // 180 times naively; tick should fire only once per call.
        let due = store.tick(3 * 3600).unwrap();
        assert_eq!(due.len(), 1);
        let schedule = store.get(id).unwrap().unwrap();
        // next_run is at the next minute after the current tick.
        assert_eq!(schedule.next_run_unix, 3 * 3600 + 60);
    }

    #[test]
    fn multiple_schedules_fire_independently() {
        let store = ScheduleStore::new();
        let _ = store.add(eng_id(), CronExpr::EveryMinute, 0).unwrap();
        let hourly = store
            .add(eng_id(), CronExpr::HourlyAtMinuteZero, 0)
            .unwrap();
        let _ = hourly;
        // At t = 60s, only the every-minute should fire.
        let due = store.tick(60).unwrap();
        assert_eq!(due.len(), 1);
        // At t = 3600s, the hourly should fire (the every-minute did
        // already at 60, so its next_run is 120, not 3600 — but it
        // is now due too).
        let due = store.tick(3600).unwrap();
        // Both fire (every-minute is way overdue and the hourly is
        // exactly due).
        assert_eq!(due.len(), 2);
    }
}
