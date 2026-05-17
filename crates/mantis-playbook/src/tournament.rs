//! Tournament selector (PRD §5.8.4).
//!
//! Each playbook tracks `(successes, failures)` over its lifetime.
//! The tournament prunes the playbook set: keep the top N by mean
//! success rate, plus all playbooks with too few observations to
//! judge (so brand-new playbooks don't get killed before they get
//! a fair shot).

use serde::{Deserialize, Serialize};

use crate::Playbook;

/// Minimum observations a playbook must have before its success
/// rate is comparable to peers. Newer playbooks are kept regardless
/// of where they would rank.
pub const MIN_OBSERVATIONS_FOR_TOURNAMENT: u32 = 5;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlaybookStats {
    pub successes: u32,
    pub failures: u32,
}

impl PlaybookStats {
    pub fn record_success(&mut self) {
        self.successes += 1;
    }

    pub fn record_failure(&mut self) {
        self.failures += 1;
    }

    pub fn observations(&self) -> u32 {
        self.successes + self.failures
    }

    pub fn success_rate(&self) -> f64 {
        let n = self.observations();
        if n == 0 {
            return 0.0;
        }
        self.successes as f64 / n as f64
    }
}

/// Sort `playbooks` so the top-N (by success rate) come first, then
/// truncate to `max_keep`. New playbooks (< MIN_OBSERVATIONS) are
/// always retained — they aggregate at the front of the list to
/// guarantee they're tried before the pruner runs again.
pub fn tournament_prune(playbooks: &mut Vec<Playbook>, max_keep: usize) {
    // Partition into "new enough" and "mature".
    let mut new_books = vec![];
    let mut mature_books = vec![];
    for book in playbooks.drain(..) {
        if book.stats.observations() < MIN_OBSERVATIONS_FOR_TOURNAMENT {
            new_books.push(book);
        } else {
            mature_books.push(book);
        }
    }
    mature_books.sort_by(|a, b| {
        b.stats
            .success_rate()
            .partial_cmp(&a.stats.success_rate())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let keep_mature = max_keep.saturating_sub(new_books.len());
    mature_books.truncate(keep_mature);

    *playbooks = new_books;
    playbooks.append(&mut mature_books);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Playbook, PlaybookStep, Preconditions};

    fn book(name: &str, succ: u32, fail: u32) -> Playbook {
        Playbook {
            id: crate::PlaybookId::new(),
            name: name.into(),
            preconditions: Preconditions::default(),
            steps: vec![PlaybookStep {
                primitive_id: "p".into(),
                vuln_class: "vc".into(),
                verifier_id: None,
            }],
            stats: PlaybookStats {
                successes: succ,
                failures: fail,
            },
        }
    }

    #[test]
    fn success_rate_handles_zero() {
        let s = PlaybookStats::default();
        assert_eq!(s.success_rate(), 0.0);
    }

    #[test]
    fn tournament_keeps_top_by_rate() {
        let mut books = vec![
            book("low", 1, 9),  // mature, 10%
            book("high", 9, 1), // mature, 90%
            book("mid", 5, 5),  // mature, 50%
        ];
        tournament_prune(&mut books, 2);
        assert_eq!(books.len(), 2);
        assert_eq!(books[0].name, "high");
        assert_eq!(books[1].name, "mid");
    }

    #[test]
    fn tournament_preserves_new_playbooks() {
        let mut books = vec![
            book("mature-high", 9, 1),
            book("mature-low", 1, 9),
            book("new", 1, 0), // < MIN_OBSERVATIONS_FOR_TOURNAMENT
        ];
        tournament_prune(&mut books, 1);
        // New playbook retained + the mature high — but max_keep=1
        // means the mature high is dropped because the new one fills
        // the slot.
        assert!(books.iter().any(|b| b.name == "new"));
    }

    #[test]
    fn tournament_keeps_all_when_max_exceeds_count() {
        let mut books = vec![book("a", 10, 0), book("b", 5, 5)];
        tournament_prune(&mut books, 10);
        assert_eq!(books.len(), 2);
    }

    #[test]
    fn record_success_and_failure_update_counters() {
        let mut s = PlaybookStats::default();
        s.record_success();
        s.record_success();
        s.record_failure();
        assert_eq!(s.successes, 2);
        assert_eq!(s.failures, 1);
        assert!((s.success_rate() - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(s.observations(), 3);
    }
}
