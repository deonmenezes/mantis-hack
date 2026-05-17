//! Monte Carlo Tree Search planner.
//!
//! Phase 1 ships a two-level tree:
//!
//! - Root
//! - Surface nodes (one per discovered surface)
//! - Primitive leaves (one per primitive applicable to that surface)
//!
//! Selection uses UCB1 with a configurable exploration constant.
//! Reward is in [0, 1] — typically 1.0 when the verifier confirms a
//! claim and 0.0 otherwise. The planner is pure data — it does not
//! run primitives itself; the caller drives the loop:
//!
//! ```text
//! loop {
//!     let Some(action) = planner.next_action() else { break };
//!     let reward = run_primitive_and_verify(action).await;
//!     planner.record_outcome(action, reward);
//! }
//! ```
//!
//! Later milestones add: Bayesian posteriors over the static priors
//! (M1.4), RAVE for cross-arm credit assignment, progressive widening
//! when the action space is huge (Phase 2+), and chain-exploit
//! planning when primitives compose (Phase 2+).
//!
//! Priors enter the planner as initial virtual-visit weight: a
//! primitive with prior 0.30 starts with 3 virtual wins out of 10
//! virtual visits, so UCB1 prefers it before any real outcomes
//! arrive.

pub mod tree;
pub mod ucb1;

pub use crate::tree::{Action, ActionId, NodeId, Planner, SurfaceKey};
pub use crate::ucb1::DEFAULT_EXPLORATION;
