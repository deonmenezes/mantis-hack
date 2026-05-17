//! Trajectory compression (Phase 3 M3.4).
//!
//! PRD §5.13 calls for compressed engagement trajectories suitable
//! for model training: tuples of (state, action, observation,
//! reward) per scan iteration. Phase 3 M3.4 ships the
//! lossy-compression pipeline that takes a full event log and
//! produces an anonymizable trajectory record. Operators opt in
//! explicitly to contributing trajectories to a shared training
//! pool (PRD §5.13.3).

use mantis_core::EngagementId;
use mantis_event_store::{Event, EventKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trajectory {
    pub engagement_id: Option<EngagementId>,
    pub steps: Vec<Step>,
    pub anonymized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub action: Action,
    pub observation: Observation,
    pub reward: Reward,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub primitive_id: String,
    pub surface_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Observation {
    Confirmed,
    Denied,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reward {
    /// Confirmed + Verified (full reward).
    Full,
    /// Confirmed but Rejected by verifier (negative signal).
    Negative,
    /// Denied or Inconclusive.
    Zero,
}

/// Compress an event log into a trajectory. Lossy: only step-shaped
/// information survives. Surface URLs become labels (e.g. host +
/// first path component) so the trajectory can be anonymized later
/// without losing the structural signal.
pub fn compress(engagement_id: EngagementId, events: &[Event]) -> Trajectory {
    use std::collections::HashMap;
    let mut latest_verdict_by_pair: HashMap<(String, String), String> = HashMap::new();
    let mut steps = vec![];

    // First pass: index claim verdicts so we can attach them to
    // earlier PrimitiveExecuted events.
    for event in events {
        match &event.kind {
            EventKind::ClaimVerified {
                surface_id,
                primitive_id,
                ..
            } => {
                latest_verdict_by_pair.insert(
                    (surface_id.clone(), primitive_id.clone()),
                    "verified".into(),
                );
            }
            EventKind::ClaimRejected {
                surface_id,
                primitive_id,
                ..
            } => {
                latest_verdict_by_pair.insert(
                    (surface_id.clone(), primitive_id.clone()),
                    "rejected".into(),
                );
            }
            EventKind::ClaimRetained {
                surface_id,
                primitive_id,
                ..
            } => {
                latest_verdict_by_pair.insert(
                    (surface_id.clone(), primitive_id.clone()),
                    "retained".into(),
                );
            }
            _ => {}
        }
    }

    for event in events {
        if let EventKind::PrimitiveExecuted {
            surface_id,
            primitive_id,
            verdict,
            ..
        } = &event.kind
        {
            let action = Action {
                primitive_id: primitive_id.clone(),
                surface_label: surface_label_for(surface_id),
            };
            let observation = match verdict.as_str() {
                "confirmed" => Observation::Confirmed,
                "denied" => Observation::Denied,
                _ => Observation::Inconclusive,
            };
            let reward = if observation == Observation::Confirmed {
                match latest_verdict_by_pair
                    .get(&(surface_id.clone(), primitive_id.clone()))
                    .map(String::as_str)
                {
                    Some("verified") => Reward::Full,
                    Some("rejected") => Reward::Negative,
                    _ => Reward::Zero,
                }
            } else {
                Reward::Zero
            };
            steps.push(Step {
                action,
                observation,
                reward,
            });
        }
    }
    Trajectory {
        engagement_id: Some(engagement_id),
        steps,
        anonymized: false,
    }
}

/// Strip engagement id and surface-label specifics so the
/// trajectory is safe to contribute to a shared training pool.
pub fn anonymize(trajectory: &mut Trajectory) {
    trajectory.engagement_id = None;
    for step in &mut trajectory.steps {
        step.action.surface_label = "anon".into();
    }
    trajectory.anonymized = true;
}

fn surface_label_for(url: &str) -> String {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let (hostport, rest) = after_scheme.split_once('/').unwrap_or((after_scheme, ""));
    let host = hostport.split(':').next().unwrap_or(hostport);
    let first_seg = rest.split('/').next().unwrap_or("");
    if first_seg.is_empty() {
        host.to_owned()
    } else {
        format!("{host}/{first_seg}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn eng_id() -> EngagementId {
        EngagementId(Ulid::new())
    }

    fn ev(seq: u64, kind: EventKind) -> Event {
        Event::new(seq, 0, kind)
    }

    #[test]
    fn empty_log_yields_empty_trajectory() {
        let t = compress(eng_id(), &[]);
        assert!(t.steps.is_empty());
        assert!(!t.anonymized);
    }

    #[test]
    fn confirmed_plus_verified_is_full_reward() {
        let url = "https://api.example.com:443/v1/users";
        let events = vec![
            ev(
                0,
                EventKind::PrimitiveExecuted {
                    surface_id: url.into(),
                    primitive_id: "idor".into(),
                    vuln_class: "idor".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                1,
                EventKind::ClaimVerified {
                    surface_id: url.into(),
                    primitive_id: "idor".into(),
                    verifier_id: "v".into(),
                },
            ),
        ];
        let t = compress(eng_id(), &events);
        assert_eq!(t.steps.len(), 1);
        assert_eq!(t.steps[0].observation, Observation::Confirmed);
        assert_eq!(t.steps[0].reward, Reward::Full);
    }

    #[test]
    fn confirmed_plus_rejected_is_negative() {
        let url = "https://x.example.com:443/y";
        let events = vec![
            ev(
                0,
                EventKind::PrimitiveExecuted {
                    surface_id: url.into(),
                    primitive_id: "p".into(),
                    vuln_class: "vc".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                1,
                EventKind::ClaimRejected {
                    surface_id: url.into(),
                    primitive_id: "p".into(),
                    reason: "verifier said no".into(),
                },
            ),
        ];
        let t = compress(eng_id(), &events);
        assert_eq!(t.steps[0].reward, Reward::Negative);
    }

    #[test]
    fn denied_observation_yields_zero_reward() {
        let events = vec![ev(
            0,
            EventKind::PrimitiveExecuted {
                surface_id: "https://x.example.com:443/".into(),
                primitive_id: "p".into(),
                vuln_class: "vc".into(),
                verdict: "denied".into(),
            },
        )];
        let t = compress(eng_id(), &events);
        assert_eq!(t.steps[0].observation, Observation::Denied);
        assert_eq!(t.steps[0].reward, Reward::Zero);
    }

    #[test]
    fn surface_label_drops_query_and_deep_path() {
        let events = vec![ev(
            0,
            EventKind::PrimitiveExecuted {
                surface_id: "https://api.example.com:443/v1/users/42".into(),
                primitive_id: "p".into(),
                vuln_class: "vc".into(),
                verdict: "denied".into(),
            },
        )];
        let t = compress(eng_id(), &events);
        assert_eq!(t.steps[0].action.surface_label, "api.example.com/v1");
    }

    #[test]
    fn anonymize_strips_identifying_info() {
        let mut t = Trajectory {
            engagement_id: Some(eng_id()),
            steps: vec![Step {
                action: Action {
                    primitive_id: "p".into(),
                    surface_label: "api.example.com/v1".into(),
                },
                observation: Observation::Confirmed,
                reward: Reward::Full,
            }],
            anonymized: false,
        };
        anonymize(&mut t);
        assert!(t.engagement_id.is_none());
        assert_eq!(t.steps[0].action.surface_label, "anon");
        assert!(t.anonymized);
    }
}
