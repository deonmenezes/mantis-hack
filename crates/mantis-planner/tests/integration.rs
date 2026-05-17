//! Integration tests for the MCTS planner.
//!
//! The headline property: given a set of (surface, primitive) arms
//! with different true reward rates, the planner concentrates
//! visits on the highest-reward arms after enough simulations.

#![allow(clippy::unwrap_used)]

use mantis_planner::{Action, ActionId, Planner, SurfaceKey};

#[test]
fn planner_with_no_actions_returns_none() {
    let p = Planner::new();
    assert!(p.next_action().is_none());
}

#[test]
fn register_returns_stable_id() {
    let mut p = Planner::new();
    let a = p.register_action(SurfaceKey("s1".into()), "prim-a".into(), 100);
    let b = p.register_action(SurfaceKey("s1".into()), "prim-a".into(), 100);
    assert_eq!(a, b, "registering same pair twice should yield same id");
    let c = p.register_action(SurfaceKey("s1".into()), "prim-b".into(), 100);
    assert_ne!(a, c, "different primitive should yield different id");
    assert_eq!(p.action_count(), 2);
}

#[test]
fn ucb1_explores_other_arms_after_one_does_poorly() {
    // Arm `a` gets visited first (tie-broken deterministically by
    // iteration order). If `a` returns reward 0, UCB1's exploit
    // term drops and the explore term pulls toward `b`.
    let mut p = Planner::new();
    let a = p.register_action(SurfaceKey("s".into()), "prim-a".into(), 100);
    let b = p.register_action(SurfaceKey("s".into()), "prim-b".into(), 100);

    let mut seen_a = false;
    let mut seen_b = false;
    for _ in 0..30 {
        let action = p.next_action().unwrap();
        let reward = if action.id == a { 0.0 } else { 1.0 };
        if action.id == a {
            seen_a = true;
        }
        if action.id == b {
            seen_b = true;
        }
        p.record_outcome(action.id, reward);
        if seen_a && seen_b {
            break;
        }
    }
    assert!(seen_a && seen_b, "both arms must be explored");
}

#[test]
fn planner_concentrates_on_high_reward_arm() {
    let mut p = Planner::new();
    let good = p.register_action(SurfaceKey("s".into()), "good".into(), 100);
    let bad = p.register_action(SurfaceKey("s".into()), "bad".into(), 100);
    let neutral = p.register_action(SurfaceKey("s".into()), "neutral".into(), 100);

    // True reward rates: good=0.8, bad=0.1, neutral=0.4
    let true_rates: std::collections::HashMap<ActionId, f64> =
        [(good, 0.8), (bad, 0.1), (neutral, 0.4)]
            .into_iter()
            .collect();

    let mut rng_state: u64 = 0xc0ffee;
    let mut prng = || {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        (rng_state as f64) / (u64::MAX as f64)
    };

    for _ in 0..400 {
        let action = p.next_action().unwrap();
        let rate = *true_rates.get(&action.id).unwrap();
        let reward = if prng() < rate { 1.0 } else { 0.0 };
        p.record_outcome(action.id, reward);
    }

    // The good arm should have visibly more visits than the bad one.
    let good_v = p.visits(good);
    let bad_v = p.visits(bad);
    assert!(
        good_v > bad_v,
        "good arm should outpace bad arm; got good={good_v} bad={bad_v}"
    );
    // And the mean reward on good should be close to its true rate.
    let good_mean = p.mean_reward(good);
    assert!(
        (good_mean - 0.8).abs() < 0.15,
        "good arm mean {good_mean} should approach 0.8"
    );
}

#[test]
fn planner_spreads_across_surfaces() {
    let mut p = Planner::new();
    let s1 = p.register_action(SurfaceKey("/a".into()), "prim".into(), 100);
    let s2 = p.register_action(SurfaceKey("/b".into()), "prim".into(), 100);
    let s3 = p.register_action(SurfaceKey("/c".into()), "prim".into(), 100);

    for _ in 0..30 {
        let action = p.next_action().unwrap();
        p.record_outcome(action.id, 0.5);
    }
    // Every surface should have been visited at least once.
    assert!(p.visits(s1) > 0);
    assert!(p.visits(s2) > 0);
    assert!(p.visits(s3) > 0);
}

#[test]
fn action_struct_carries_surface_and_primitive_refs() {
    let mut p = Planner::new();
    p.register_action(SurfaceKey("/foo".into()), "open-redirect".into(), 200);
    let Action {
        surface_key,
        primitive_id,
        ..
    } = p.next_action().unwrap();
    assert_eq!(surface_key.0, "/foo");
    assert_eq!(primitive_id, "open-redirect");
}

#[test]
fn higher_prior_arm_explored_first() {
    let mut p = Planner::new();
    let low_prior = p.register_action(SurfaceKey("s".into()), "low".into(), 50);
    let high_prior = p.register_action(SurfaceKey("s".into()), "high".into(), 3000);

    // First action should be the high-prior arm.
    let first = p.next_action().unwrap();
    assert_eq!(first.id, high_prior);
    p.record_outcome(first.id, 0.0);

    // We don't make claims about subsequent picks — UCB1 may
    // re-balance immediately. We just check the prior actually
    // moved the needle on the first pick.
    let _ = low_prior;
}
