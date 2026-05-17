//! Cross-engagement memory (Phase 3 M3.2).
//!
//! PRD §5.11 mandates that every engagement's event log be
//! indexed for full-text and semantic search across the workspace,
//! and that a synthesized brief surface relevant historical
//! observations at new-engagement start.
//!
//! Phase 3 M3.2 ships the index + brief generator using exact-match
//! on (stack, vuln_class). Semantic embedding lookup lands in M3.2b
//! (uses the same `Brief` shape — only the matching changes).

use std::collections::HashMap;
use std::sync::RwLock;

use mantis_core::EngagementId;
use mantis_event_store::{Event, EventKind};
use serde::{Deserialize, Serialize};

/// One indexed datapoint: which engagement, stack fingerprint, and
/// vuln_class produced what outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationIndex {
    pub engagement_id: EngagementId,
    pub stack: String,
    pub vuln_class: String,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Verified,
    Rejected,
    Retained,
    HypothesisOnly,
}

#[derive(Debug, Default)]
pub struct Memory {
    inner: RwLock<Vec<ObservationIndex>>,
}

impl Memory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Index an engagement's event log. Each
    /// `SurfaceDiscovered + ClaimVerified` pair becomes a Verified
    /// observation; `ClaimRejected` and `ClaimRetained` become their
    /// respective outcomes; remaining hypotheses become
    /// `HypothesisOnly`.
    pub fn ingest(&self, engagement_id: EngagementId, events: &[Event]) {
        let mut stack_by_url: HashMap<String, String> = HashMap::new();
        for event in events {
            if let EventKind::SurfaceDiscovered {
                host,
                port,
                scheme,
                path,
                tech_hints,
                ..
            } = &event.kind
            {
                let url = format!("{scheme}://{host}:{port}{path}");
                let stack = tech_hints
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_owned());
                stack_by_url.insert(url, stack);
            }
        }
        let mut additions = vec![];
        for event in events {
            match &event.kind {
                EventKind::HypothesisGenerated {
                    surface_id,
                    vuln_class,
                    ..
                } => {
                    let stack = stack_by_url
                        .get(surface_id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_owned());
                    additions.push(ObservationIndex {
                        engagement_id,
                        stack,
                        vuln_class: vuln_class.clone(),
                        outcome: Outcome::HypothesisOnly,
                    });
                }
                EventKind::ClaimVerified {
                    surface_id,
                    primitive_id: _,
                    verifier_id: _,
                } => {
                    let stack = stack_by_url
                        .get(surface_id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_owned());
                    additions.push(ObservationIndex {
                        engagement_id,
                        stack,
                        vuln_class: vuln_class_from_primitive_event(events, surface_id, true),
                        outcome: Outcome::Verified,
                    });
                }
                EventKind::ClaimRejected {
                    surface_id,
                    primitive_id: _,
                    reason: _,
                } => {
                    let stack = stack_by_url
                        .get(surface_id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_owned());
                    additions.push(ObservationIndex {
                        engagement_id,
                        stack,
                        vuln_class: vuln_class_from_primitive_event(events, surface_id, false),
                        outcome: Outcome::Rejected,
                    });
                }
                EventKind::ClaimRetained {
                    surface_id,
                    primitive_id: _,
                    reason: _,
                } => {
                    let stack = stack_by_url
                        .get(surface_id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_owned());
                    additions.push(ObservationIndex {
                        engagement_id,
                        stack,
                        vuln_class: vuln_class_from_primitive_event(events, surface_id, false),
                        outcome: Outcome::Retained,
                    });
                }
                _ => {}
            }
        }
        if let Ok(mut inner) = self.inner.write() {
            inner.extend(additions);
        }
    }

    /// Synthesized brief for a new engagement starting against
    /// `stacks`. Returns historical hit rates per vuln_class for
    /// each stack the new engagement contains.
    pub fn brief(&self, stacks: &[String]) -> Brief {
        let inner = self.inner.read().map(|g| g.clone()).unwrap_or_default();
        let mut per_class: HashMap<(String, String), Stats> = HashMap::new();
        for obs in inner {
            if stacks.is_empty() || stacks.contains(&obs.stack) {
                let entry = per_class
                    .entry((obs.stack.clone(), obs.vuln_class.clone()))
                    .or_default();
                match obs.outcome {
                    Outcome::Verified => entry.verified += 1,
                    Outcome::Rejected => entry.rejected += 1,
                    Outcome::Retained => entry.retained += 1,
                    Outcome::HypothesisOnly => entry.hypothesis_only += 1,
                }
            }
        }
        let mut entries: Vec<BriefEntry> = per_class
            .into_iter()
            .map(|((stack, vuln_class), stats)| BriefEntry {
                stack,
                vuln_class,
                stats,
            })
            .collect();
        entries.sort_by(|a, b| {
            b.stats
                .verified
                .cmp(&a.stats.verified)
                .then_with(|| a.vuln_class.cmp(&b.vuln_class))
        });
        Brief { entries }
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub verified: u32,
    pub rejected: u32,
    pub retained: u32,
    pub hypothesis_only: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BriefEntry {
    pub stack: String,
    pub vuln_class: String,
    pub stats: Stats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Brief {
    pub entries: Vec<BriefEntry>,
}

fn vuln_class_from_primitive_event(
    events: &[Event],
    surface_id: &str,
    expect_confirmed: bool,
) -> String {
    // Look back for the most recent PrimitiveExecuted on this surface
    // and use its vuln_class.
    for event in events.iter().rev() {
        if let EventKind::PrimitiveExecuted {
            surface_id: s,
            vuln_class,
            verdict,
            ..
        } = &event.kind
        {
            if s == surface_id {
                let matches = if expect_confirmed {
                    verdict == "confirmed"
                } else {
                    true
                };
                if matches {
                    return vuln_class.clone();
                }
            }
        }
    }
    "unknown".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_event_store::Event;
    use ulid::Ulid;

    fn eng_id() -> EngagementId {
        EngagementId(Ulid::new())
    }

    fn ev(seq: u64, kind: EventKind) -> Event {
        Event::new(seq, 0, kind)
    }

    fn surface_event(seq: u64, url: &str, status: u16, hints: &[&str]) -> Event {
        let after_scheme = url.split("://").nth(1).unwrap_or(url);
        let (hostport, rest) = after_scheme.split_once('/').unwrap_or((after_scheme, ""));
        let (host, port_str) = hostport.split_once(':').unwrap_or((hostport, "443"));
        let port: u16 = port_str.parse().unwrap_or(443);
        ev(
            seq,
            EventKind::SurfaceDiscovered {
                host: host.into(),
                port,
                scheme: url.split("://").next().unwrap_or("https").into(),
                path: format!("/{rest}"),
                status,
                server: None,
                content_length: None,
                tech_hints: hints.iter().map(|s| (*s).into()).collect(),
            },
        )
    }

    #[test]
    fn empty_memory_brief_is_empty() {
        let m = Memory::new();
        let brief = m.brief(&[]);
        assert!(brief.entries.is_empty());
    }

    #[test]
    fn ingest_records_verified() {
        let m = Memory::new();
        let url = "https://api.example.com:443/v1/users";
        let events = vec![
            surface_event(0, url, 200, &["server:nginx"]),
            ev(
                1,
                EventKind::HypothesisGenerated {
                    surface_id: url.into(),
                    vuln_class: "idor".into(),
                    summary: "x".into(),
                    prior: 100,
                },
            ),
            ev(
                2,
                EventKind::PrimitiveExecuted {
                    surface_id: url.into(),
                    primitive_id: "idor.numeric-id-enumeration".into(),
                    vuln_class: "idor".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                3,
                EventKind::ClaimVerified {
                    surface_id: url.into(),
                    primitive_id: "idor.numeric-id-enumeration".into(),
                    verifier_id: "v".into(),
                },
            ),
        ];
        m.ingest(eng_id(), &events);
        assert_eq!(m.len(), 2); // HypothesisOnly + Verified
    }

    #[test]
    fn brief_aggregates_by_stack_and_class() {
        let m = Memory::new();
        let url_a = "https://a.example.com:443/x";
        let url_b = "https://b.example.com:443/y";
        let events_a = vec![
            surface_event(0, url_a, 200, &["server:nginx"]),
            ev(
                1,
                EventKind::PrimitiveExecuted {
                    surface_id: url_a.into(),
                    primitive_id: "p".into(),
                    vuln_class: "idor".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                2,
                EventKind::ClaimVerified {
                    surface_id: url_a.into(),
                    primitive_id: "p".into(),
                    verifier_id: "v".into(),
                },
            ),
        ];
        let events_b = vec![
            surface_event(0, url_b, 200, &["server:nginx"]),
            ev(
                1,
                EventKind::PrimitiveExecuted {
                    surface_id: url_b.into(),
                    primitive_id: "p".into(),
                    vuln_class: "idor".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                2,
                EventKind::ClaimRejected {
                    surface_id: url_b.into(),
                    primitive_id: "p".into(),
                    reason: "false positive".into(),
                },
            ),
        ];
        m.ingest(eng_id(), &events_a);
        m.ingest(eng_id(), &events_b);
        let brief = m.brief(&["server:nginx".into()]);
        assert!(!brief.entries.is_empty());
        let nginx_idor = brief
            .entries
            .iter()
            .find(|e| e.stack == "server:nginx" && e.vuln_class == "idor")
            .unwrap();
        assert_eq!(nginx_idor.stats.verified, 1);
        assert_eq!(nginx_idor.stats.rejected, 1);
    }

    #[test]
    fn brief_filters_by_requested_stacks() {
        let m = Memory::new();
        let url = "https://x.example.com:443/y";
        let events = vec![
            surface_event(0, url, 200, &["server:apache"]),
            ev(
                1,
                EventKind::PrimitiveExecuted {
                    surface_id: url.into(),
                    primitive_id: "p".into(),
                    vuln_class: "info-disclosure".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                2,
                EventKind::ClaimVerified {
                    surface_id: url.into(),
                    primitive_id: "p".into(),
                    verifier_id: "v".into(),
                },
            ),
        ];
        m.ingest(eng_id(), &events);
        let brief = m.brief(&["server:nginx".into()]);
        assert!(brief.entries.is_empty(), "non-matching stack excluded");

        let brief = m.brief(&["server:apache".into()]);
        assert!(!brief.entries.is_empty());
    }
}
