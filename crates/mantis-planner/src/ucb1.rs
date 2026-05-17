//! UCB1 selection.

/// Default exploration constant. `sqrt(2)` is the textbook value
/// for rewards in [0, 1].
pub const DEFAULT_EXPLORATION: f64 = std::f64::consts::SQRT_2;

/// UCB1 score for a child of a parent with `parent_visits` visits.
/// Returns `f64::INFINITY` for unvisited children so they are
/// selected before anything else.
#[must_use]
pub fn ucb1(
    child_visits: u64,
    child_total_reward: f64,
    parent_visits: u64,
    exploration_constant: f64,
) -> f64 {
    if child_visits == 0 {
        return f64::INFINITY;
    }
    let exploit = child_total_reward / child_visits as f64;
    let parent = parent_visits.max(1) as f64;
    let explore = exploration_constant * (parent.ln() / child_visits as f64).sqrt();
    exploit + explore
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unvisited_arm_is_infinite() {
        assert_eq!(ucb1(0, 0.0, 100, DEFAULT_EXPLORATION), f64::INFINITY);
    }

    #[test]
    fn exploit_dominates_when_exploration_is_zero() {
        let score = ucb1(10, 7.0, 100, 0.0);
        assert!((score - 0.7).abs() < 1e-9);
    }

    #[test]
    fn higher_reward_means_higher_score_at_equal_visits() {
        let a = ucb1(10, 7.0, 100, DEFAULT_EXPLORATION);
        let b = ucb1(10, 3.0, 100, DEFAULT_EXPLORATION);
        assert!(a > b);
    }

    #[test]
    fn fewer_visits_means_higher_explore_term() {
        // Same reward rate, but `a` has been visited less.
        let a = ucb1(2, 1.0, 100, DEFAULT_EXPLORATION);
        let b = ucb1(50, 25.0, 100, DEFAULT_EXPLORATION);
        assert!(a > b, "a should explore more: {a} <= {b}");
    }
}
