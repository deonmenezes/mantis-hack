//! Two-level MCTS tree.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ucb1::{ucb1, DEFAULT_EXPLORATION};

/// Stable identifier for a node in the [`Planner`]'s tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u32);

/// Stable identifier for an `(surface, primitive)` action pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionId(pub u32);

/// Stable per-engagement identifier for a surface. The planner does
/// not interpret these; callers compute them however they like
/// (URL hash, sequential index, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SurfaceKey(pub String);

/// Action emitted by [`Planner::next_action`]: which surface to
/// probe with which primitive.
#[derive(Debug, Clone)]
pub struct Action<'a> {
    pub id: ActionId,
    pub surface_key: &'a SurfaceKey,
    pub primitive_id: &'a str,
}

#[derive(Debug)]
struct Node {
    /// Visits this node has seen.
    visits: u64,
    /// Sum of rewards observed on visits to this node.
    total_reward: f64,
    /// Children's NodeIds. Leaves (primitive nodes) have no children.
    children: Vec<NodeId>,
    /// For leaf nodes only: the action this leaf represents.
    action: Option<ActionId>,
}

impl Node {
    fn root() -> Self {
        Self {
            visits: 0,
            total_reward: 0.0,
            children: vec![],
            action: None,
        }
    }
    fn leaf(action: ActionId, prior_pp10k: u32) -> Self {
        // Prior-as-virtual-visits: one virtual observation with
        // reward equal to the prior rate. A single virtual visit
        // breaks the f64::INFINITY tie among unvisited arms while
        // letting UCB1's exploration term grow quickly enough to
        // ensure low-mean arms still get tried.
        let prior_rate = prior_pp10k as f64 / 10_000.0;
        Self {
            visits: 1,
            total_reward: prior_rate,
            children: vec![],
            action: Some(action),
        }
    }
}

#[derive(Debug)]
pub struct Planner {
    nodes: Vec<Node>,
    root: NodeId,
    /// surface_key -> NodeId for the surface-level node.
    surfaces: HashMap<SurfaceKey, NodeId>,
    /// All registered actions, indexed by ActionId.
    actions: Vec<RegisteredAction>,
    exploration_constant: f64,
}

#[derive(Debug, Clone)]
struct RegisteredAction {
    surface_key: SurfaceKey,
    primitive_id: String,
    leaf_node: NodeId,
}

impl Planner {
    pub fn new() -> Self {
        let mut nodes = vec![Node::root()];
        let root = NodeId(0);
        let _ = &mut nodes[root.0 as usize];
        Self {
            nodes,
            root,
            surfaces: HashMap::new(),
            actions: vec![],
            exploration_constant: DEFAULT_EXPLORATION,
        }
    }

    pub fn with_exploration(mut self, constant: f64) -> Self {
        self.exploration_constant = constant;
        self
    }

    /// Register an (surface, primitive) action with a prior in basis
    /// points (parts per 10,000). Idempotent on
    /// `(surface_key, primitive_id)`.
    pub fn register_action(
        &mut self,
        surface_key: SurfaceKey,
        primitive_id: String,
        prior_pp10k: u32,
    ) -> ActionId {
        // Find or create surface node.
        let surface_node = match self.surfaces.get(&surface_key).copied() {
            Some(id) => id,
            None => {
                let id = NodeId(self.nodes.len() as u32);
                self.nodes.push(Node {
                    visits: 0,
                    total_reward: 0.0,
                    children: vec![],
                    action: None,
                });
                self.nodes[self.root.0 as usize].children.push(id);
                self.surfaces.insert(surface_key.clone(), id);
                id
            }
        };

        // Check if action already exists.
        if let Some(existing) = self
            .actions
            .iter()
            .find(|a| a.surface_key == surface_key && a.primitive_id == primitive_id)
        {
            return ActionId(
                self.actions
                    .iter()
                    .position(|a| {
                        a.surface_key == existing.surface_key
                            && a.primitive_id == existing.primitive_id
                    })
                    .expect("just found") as u32,
            );
        }

        // Add leaf.
        let action_id = ActionId(self.actions.len() as u32);
        let leaf_id = NodeId(self.nodes.len() as u32);
        self.nodes.push(Node::leaf(action_id, prior_pp10k));
        self.nodes[surface_node.0 as usize].children.push(leaf_id);
        self.actions.push(RegisteredAction {
            surface_key,
            primitive_id,
            leaf_node: leaf_id,
        });
        action_id
    }

    /// Returns the action to run next, or `None` if there are no
    /// registered actions.
    #[must_use]
    pub fn next_action(&self) -> Option<Action<'_>> {
        if self.actions.is_empty() {
            return None;
        }
        // Selection: walk from root via UCB1 at each level.
        let surface_node = self.select_child(self.root)?;
        let leaf_node = self.select_child(surface_node)?;
        let action_id = self.nodes[leaf_node.0 as usize].action?;
        let registered = &self.actions[action_id.0 as usize];
        Some(Action {
            id: action_id,
            surface_key: &registered.surface_key,
            primitive_id: &registered.primitive_id,
        })
    }

    fn select_child(&self, parent_id: NodeId) -> Option<NodeId> {
        let parent = &self.nodes[parent_id.0 as usize];
        if parent.children.is_empty() {
            return None;
        }
        // Parent visits for UCB1 is the sum of child visits, which
        // includes virtual visits from priors. Using parent.visits
        // directly would ignore the virtual visits and give an
        // artificially-zero exploration term on the first pick.
        let parent_visits: u64 = parent
            .children
            .iter()
            .map(|c| self.nodes[c.0 as usize].visits)
            .sum();
        parent.children.iter().copied().max_by(|a, b| {
            let sa = ucb1(
                self.nodes[a.0 as usize].visits,
                self.nodes[a.0 as usize].total_reward,
                parent_visits,
                self.exploration_constant,
            );
            let sb = ucb1(
                self.nodes[b.0 as usize].visits,
                self.nodes[b.0 as usize].total_reward,
                parent_visits,
                self.exploration_constant,
            );
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Record the outcome of running an action. `reward` should be
    /// in `[0, 1]` — by convention, 1.0 if the verifier confirmed
    /// the resulting claim, 0.0 otherwise.
    pub fn record_outcome(&mut self, action_id: ActionId, reward: f64) {
        let registered = &self.actions[action_id.0 as usize];
        let leaf_id = registered.leaf_node;
        let surface_key = registered.surface_key.clone();
        let surface_node = self
            .surfaces
            .get(&surface_key)
            .copied()
            .expect("surface registered with action");

        // Backpropagate: leaf, surface, root.
        for node_id in [leaf_id, surface_node, self.root] {
            let n = &mut self.nodes[node_id.0 as usize];
            n.visits += 1;
            n.total_reward += reward;
        }
    }

    /// Visit count for an action.
    #[must_use]
    pub fn visits(&self, action_id: ActionId) -> u64 {
        let leaf = self.actions[action_id.0 as usize].leaf_node;
        self.nodes[leaf.0 as usize].visits
    }

    /// Mean reward observed for an action.
    #[must_use]
    pub fn mean_reward(&self, action_id: ActionId) -> f64 {
        let leaf = self.actions[action_id.0 as usize].leaf_node;
        let n = &self.nodes[leaf.0 as usize];
        if n.visits == 0 {
            0.0
        } else {
            n.total_reward / n.visits as f64
        }
    }

    /// Total registered actions.
    #[must_use]
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }
}

impl Default for Planner {
    fn default() -> Self {
        Self::new()
    }
}
