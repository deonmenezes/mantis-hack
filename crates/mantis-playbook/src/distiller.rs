//! Event-log → playbook miner.
//!
//! For each engagement, find `SurfaceDiscovered →
//! ClaimVerified` event pairs and emit a one-step playbook per
//! pair. Multi-step chains are detected when several
//! `ClaimVerified` events share the same surface_id; they're
//! grouped into a single ordered playbook.
//!
//! Phase 3 M3.1 is intentionally simple. M3.2 adds:
//! - parameter generalization across engagements
//! - precondition expansion via tech_hint clustering
//! - deduplication via canonical-form hashing

use std::collections::HashMap;

use mantis_event_store::{Event, EventKind};

use crate::{Playbook, PlaybookStep, Preconditions};

/// Distill playbooks from a single engagement's event log.
pub fn distill(events: &[Event]) -> Vec<Playbook> {
    // Index of surface_id → recorded SurfaceDiscovered details.
    let mut surfaces: HashMap<String, SurfaceMeta> = HashMap::new();
    // surface_id → ordered list of (primitive_id, vuln_class, verifier_id)
    let mut chains: HashMap<String, Vec<PlaybookStep>> = HashMap::new();
    // (surface_id, primitive_id) → expected verifier id from ClaimVerified.
    let mut verifier_by_pair: HashMap<(String, String), String> = HashMap::new();

    // First pass: collect surfaces and verifier ids.
    for event in events {
        match &event.kind {
            EventKind::SurfaceDiscovered {
                host,
                port,
                scheme,
                path,
                status,
                tech_hints,
                ..
            } => {
                let key = format!("{scheme}://{host}:{port}{path}");
                surfaces.insert(
                    key,
                    SurfaceMeta {
                        status: *status,
                        tech_hint: tech_hints.first().cloned(),
                    },
                );
            }
            EventKind::ClaimVerified {
                surface_id,
                primitive_id,
                verifier_id,
            } => {
                verifier_by_pair.insert(
                    (surface_id.clone(), primitive_id.clone()),
                    verifier_id.clone(),
                );
            }
            _ => {}
        }
    }

    // Second pass: build ordered chains of confirmed primitives.
    for event in events {
        if let EventKind::PrimitiveExecuted {
            surface_id,
            primitive_id,
            vuln_class,
            verdict,
        } = &event.kind
        {
            if verdict != "confirmed" {
                continue;
            }
            // Only count this step if the verifier confirmed it too.
            let verifier_id = verifier_by_pair
                .get(&(surface_id.clone(), primitive_id.clone()))
                .cloned();
            if verifier_id.is_none() {
                continue;
            }
            chains
                .entry(surface_id.clone())
                .or_default()
                .push(PlaybookStep {
                    primitive_id: primitive_id.clone(),
                    vuln_class: vuln_class.clone(),
                    verifier_id,
                });
        }
    }

    let mut out = vec![];
    for (surface_id, steps) in chains {
        if steps.is_empty() {
            continue;
        }
        let meta = surfaces.get(&surface_id);
        let name = format!(
            "{}-on-{}",
            steps
                .iter()
                .map(|s| s.vuln_class.as_str())
                .collect::<Vec<_>>()
                .join("+"),
            url_to_short_label(&surface_id)
        );
        let preconditions = Preconditions {
            url_prefix: Some(url_prefix_for(&surface_id)),
            tech_hint: meta.and_then(|m| m.tech_hint.clone()),
            status_min: 200,
            status_max: 399,
        };
        out.push(Playbook::new(name, preconditions, steps));
    }
    // Stable order for callers: by name.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

struct SurfaceMeta {
    #[allow(dead_code)] // Reserved for M3.2 precondition refinement.
    status: u16,
    tech_hint: Option<String>,
}

fn url_to_short_label(url: &str) -> String {
    // Best-effort: take the host + first path segment.
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let (hostport, path) = after_scheme.split_once('/').unwrap_or((after_scheme, ""));
    let host = hostport.split(':').next().unwrap_or(hostport);
    let first_seg = path.split('/').next().unwrap_or("");
    if first_seg.is_empty() {
        host.to_owned()
    } else {
        format!("{host}-{first_seg}")
    }
}

fn url_prefix_for(url: &str) -> String {
    // Strip trailing `/foo/bar` to give a host+root prefix.
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let (hostport, _) = after_scheme.split_once('/').unwrap_or((after_scheme, ""));
    let scheme = url.split("://").next().unwrap_or("https");
    format!("{scheme}://{hostport}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_event_store::Event;

    fn ev(seq: u64, kind: EventKind) -> Event {
        Event::new(seq, 0, kind)
    }

    fn surface_event(seq: u64, url: &str, status: u16, tech: &[&str]) -> Event {
        let after_scheme = url.split("://").nth(1).unwrap_or(url);
        let (hostport, rest) = after_scheme.split_once('/').unwrap_or((after_scheme, ""));
        let (host, port_str) = hostport.split_once(':').unwrap_or((hostport, "443"));
        let port: u16 = port_str.parse().unwrap_or(443);
        let scheme = url.split("://").next().unwrap_or("https").into();
        ev(
            seq,
            EventKind::SurfaceDiscovered {
                host: host.into(),
                port,
                scheme,
                path: format!("/{rest}"),
                status,
                server: None,
                content_length: None,
                tech_hints: tech.iter().map(|s| (*s).to_owned()).collect(),
            },
        )
    }

    #[test]
    fn distills_single_step_playbook() {
        let url = "https://api.example.com:443/v1/users";
        let events = vec![
            surface_event(0, url, 200, &["content:json"]),
            ev(
                1,
                EventKind::PrimitiveExecuted {
                    surface_id: url.into(),
                    primitive_id: "idor.numeric-id-enumeration".into(),
                    vuln_class: "idor".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                2,
                EventKind::ClaimVerified {
                    surface_id: url.into(),
                    primitive_id: "idor.numeric-id-enumeration".into(),
                    verifier_id: "verifier.idor".into(),
                },
            ),
        ];
        let books = distill(&events);
        assert_eq!(books.len(), 1);
        assert_eq!(books[0].steps.len(), 1);
        assert_eq!(books[0].steps[0].vuln_class, "idor");
        assert_eq!(
            books[0].steps[0].verifier_id.as_deref(),
            Some("verifier.idor")
        );
        assert_eq!(
            books[0].preconditions.tech_hint.as_deref(),
            Some("content:json")
        );
    }

    #[test]
    fn ignores_denied_primitives() {
        let url = "https://api.example.com:443/v1/users";
        let events = vec![
            surface_event(0, url, 200, &[]),
            ev(
                1,
                EventKind::PrimitiveExecuted {
                    surface_id: url.into(),
                    primitive_id: "open-redirect.query-param".into(),
                    vuln_class: "open-redirect".into(),
                    verdict: "denied".into(),
                },
            ),
        ];
        let books = distill(&events);
        assert!(books.is_empty());
    }

    #[test]
    fn requires_verifier_confirmation() {
        // PrimitiveExecuted = Confirmed, but no ClaimVerified follows.
        let url = "https://api.example.com:443/x";
        let events = vec![
            surface_event(0, url, 200, &[]),
            ev(
                1,
                EventKind::PrimitiveExecuted {
                    surface_id: url.into(),
                    primitive_id: "p".into(),
                    vuln_class: "info-disclosure".into(),
                    verdict: "confirmed".into(),
                },
            ),
            // No ClaimVerified — only ClaimRejected.
            ev(
                2,
                EventKind::ClaimRejected {
                    surface_id: url.into(),
                    primitive_id: "p".into(),
                    reason: "x".into(),
                },
            ),
        ];
        let books = distill(&events);
        assert!(books.is_empty(), "rejected claims must not seed playbooks");
    }

    #[test]
    fn multi_step_chain_on_same_surface() {
        let url = "https://api.example.com:443/v1/users/42";
        let events = vec![
            surface_event(0, url, 200, &["content:json"]),
            ev(
                1,
                EventKind::PrimitiveExecuted {
                    surface_id: url.into(),
                    primitive_id: "idor.numeric-id-enumeration".into(),
                    vuln_class: "idor".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                2,
                EventKind::ClaimVerified {
                    surface_id: url.into(),
                    primitive_id: "idor.numeric-id-enumeration".into(),
                    verifier_id: "verifier.idor".into(),
                },
            ),
            ev(
                3,
                EventKind::PrimitiveExecuted {
                    surface_id: url.into(),
                    primitive_id: "cors.reflect-with-credentials".into(),
                    vuln_class: "cors-misconfig".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                4,
                EventKind::ClaimVerified {
                    surface_id: url.into(),
                    primitive_id: "cors.reflect-with-credentials".into(),
                    verifier_id: "verifier.cors".into(),
                },
            ),
        ];
        let books = distill(&events);
        assert_eq!(books.len(), 1);
        assert_eq!(books[0].steps.len(), 2);
        // Order is preserved.
        assert_eq!(books[0].steps[0].vuln_class, "idor");
        assert_eq!(books[0].steps[1].vuln_class, "cors-misconfig");
    }

    #[test]
    fn separate_surfaces_yield_separate_playbooks() {
        let a = "https://a.example.com:443/x";
        let b = "https://b.example.com:443/y";
        let events = vec![
            surface_event(0, a, 200, &[]),
            surface_event(1, b, 200, &[]),
            ev(
                2,
                EventKind::PrimitiveExecuted {
                    surface_id: a.into(),
                    primitive_id: "p".into(),
                    vuln_class: "vc".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                3,
                EventKind::ClaimVerified {
                    surface_id: a.into(),
                    primitive_id: "p".into(),
                    verifier_id: "v".into(),
                },
            ),
            ev(
                4,
                EventKind::PrimitiveExecuted {
                    surface_id: b.into(),
                    primitive_id: "p".into(),
                    vuln_class: "vc".into(),
                    verdict: "confirmed".into(),
                },
            ),
            ev(
                5,
                EventKind::ClaimVerified {
                    surface_id: b.into(),
                    primitive_id: "p".into(),
                    verifier_id: "v".into(),
                },
            ),
        ];
        let books = distill(&events);
        assert_eq!(books.len(), 2);
    }

    #[test]
    fn url_label_helpers_extract_host_and_root() {
        assert_eq!(
            url_to_short_label("https://api.example.com:443/v1/users"),
            "api.example.com-v1"
        );
        assert_eq!(
            url_prefix_for("https://api.example.com:443/v1/users"),
            "https://api.example.com:443"
        );
    }
}
