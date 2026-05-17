//! TUI model-view (Phase 2 M2.4).
//!
//! Renders the daemon's live state into a structured `ScreenModel`
//! that a ratatui binding renders to the terminal. Phase 2 M2.4
//! ships the model + plain-ASCII renderer (suitable for tests and
//! `mantis status --watch` in dumb terminals). The ratatui binding
//! lands in M2.4b as `mantis-tui-ratatui`.
//!
//! Keeping the model separate from the terminal backend matches the
//! same split used in the gRPC API: the UI is just another
//! rendering of `EngagementInfo` + claim/event streams.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScreenModel {
    pub engagements: Vec<EngagementRow>,
    pub claims: Vec<ClaimRow>,
    pub log_lines: Vec<String>,
    pub selected_engagement: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementRow {
    pub id: String,
    pub name: String,
    pub state: String,
    pub events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRow {
    pub vuln_class: String,
    pub severity: String,
    pub status: String,
    pub url: String,
}

/// Events the model accepts from the daemon's event stream.
#[derive(Debug, Clone)]
pub enum Update {
    EngagementUpserted(EngagementRow),
    ClaimAdded(ClaimRow),
    LogLine(String),
    SelectEngagement(usize),
    PreviousEngagement,
    NextEngagement,
    Clear,
}

impl ScreenModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, update: Update) {
        match update {
            Update::EngagementUpserted(row) => {
                if let Some(existing) = self.engagements.iter_mut().find(|e| e.id == row.id) {
                    *existing = row;
                } else {
                    self.engagements.push(row);
                }
            }
            Update::ClaimAdded(claim) => {
                self.claims.push(claim);
                if self.claims.len() > 1000 {
                    let drop = self.claims.len() - 1000;
                    self.claims.drain(..drop);
                }
            }
            Update::LogLine(line) => {
                self.log_lines.push(line);
                if self.log_lines.len() > 2000 {
                    let drop = self.log_lines.len() - 2000;
                    self.log_lines.drain(..drop);
                }
            }
            Update::SelectEngagement(i) => {
                if i < self.engagements.len() {
                    self.selected_engagement = Some(i);
                }
            }
            Update::PreviousEngagement => {
                if self.engagements.is_empty() {
                    return;
                }
                let cur = self.selected_engagement.unwrap_or(0);
                self.selected_engagement = Some(if cur == 0 {
                    self.engagements.len() - 1
                } else {
                    cur - 1
                });
            }
            Update::NextEngagement => {
                if self.engagements.is_empty() {
                    return;
                }
                let cur = self.selected_engagement.unwrap_or(0);
                self.selected_engagement = Some((cur + 1) % self.engagements.len());
            }
            Update::Clear => {
                self.claims.clear();
                self.log_lines.clear();
            }
        }
    }

    /// Render the model as plain ASCII suitable for `cat`-style
    /// output or dumb terminals. ratatui-side rendering reuses the
    /// model directly (the renderer is in `mantis-tui-ratatui`).
    pub fn render_ascii(&self, width: usize) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str(&"=".repeat(width));
        out.push('\n');
        out.push_str(" Mantis TUI\n");
        out.push_str(&"=".repeat(width));
        out.push('\n');
        out.push_str(" Engagements:\n");
        if self.engagements.is_empty() {
            out.push_str("   (none)\n");
        } else {
            for (idx, eng) in self.engagements.iter().enumerate() {
                let marker = if Some(idx) == self.selected_engagement {
                    " > "
                } else {
                    "   "
                };
                out.push_str(&format!(
                    "{marker}{}  {:<20} {:<10} events={}\n",
                    eng.id, eng.name, eng.state, eng.events
                ));
            }
        }
        out.push_str(&"-".repeat(width));
        out.push('\n');
        out.push_str(" Recent claims:\n");
        if self.claims.is_empty() {
            out.push_str("   (none)\n");
        } else {
            for c in self.claims.iter().rev().take(10) {
                out.push_str(&format!(
                    "   [{}] {:<24} {} on {}\n",
                    c.severity, c.vuln_class, c.status, c.url
                ));
            }
        }
        out.push_str(&"-".repeat(width));
        out.push('\n');
        out.push_str(" Log tail:\n");
        for line in self.log_lines.iter().rev().take(10) {
            out.push_str(&format!("   {line}\n"));
        }
        out.push_str(&"=".repeat(width));
        out.push('\n');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eng(id: &str, name: &str, state: &str) -> EngagementRow {
        EngagementRow {
            id: id.into(),
            name: name.into(),
            state: state.into(),
            events: 0,
        }
    }

    #[test]
    fn upsert_replaces_existing_engagement() {
        let mut m = ScreenModel::new();
        m.apply(Update::EngagementUpserted(eng("a", "first", "active")));
        m.apply(Update::EngagementUpserted(eng(
            "a",
            "first-renamed",
            "paused",
        )));
        assert_eq!(m.engagements.len(), 1);
        assert_eq!(m.engagements[0].name, "first-renamed");
        assert_eq!(m.engagements[0].state, "paused");
    }

    #[test]
    fn claims_bounded_to_1000() {
        let mut m = ScreenModel::new();
        for i in 0..1500 {
            m.apply(Update::ClaimAdded(ClaimRow {
                vuln_class: "xss".into(),
                severity: "Medium".into(),
                status: "Verified".into(),
                url: format!("https://x/{i}"),
            }));
        }
        assert_eq!(m.claims.len(), 1000);
    }

    #[test]
    fn log_lines_bounded_to_2000() {
        let mut m = ScreenModel::new();
        for i in 0..3000 {
            m.apply(Update::LogLine(format!("line {i}")));
        }
        assert_eq!(m.log_lines.len(), 2000);
    }

    #[test]
    fn select_and_navigate_engagements() {
        let mut m = ScreenModel::new();
        m.apply(Update::EngagementUpserted(eng("a", "A", "active")));
        m.apply(Update::EngagementUpserted(eng("b", "B", "active")));
        m.apply(Update::EngagementUpserted(eng("c", "C", "active")));
        m.apply(Update::SelectEngagement(1));
        assert_eq!(m.selected_engagement, Some(1));
        m.apply(Update::NextEngagement);
        assert_eq!(m.selected_engagement, Some(2));
        m.apply(Update::NextEngagement);
        assert_eq!(m.selected_engagement, Some(0)); // wraps
        m.apply(Update::PreviousEngagement);
        assert_eq!(m.selected_engagement, Some(2)); // wraps
    }

    #[test]
    fn select_out_of_range_is_ignored() {
        let mut m = ScreenModel::new();
        m.apply(Update::EngagementUpserted(eng("a", "A", "active")));
        m.apply(Update::SelectEngagement(99));
        assert_eq!(m.selected_engagement, None);
    }

    #[test]
    fn render_ascii_shows_sections() {
        let mut m = ScreenModel::new();
        m.apply(Update::EngagementUpserted(eng("01HXX", "demo", "active")));
        m.apply(Update::ClaimAdded(ClaimRow {
            vuln_class: "idor".into(),
            severity: "High".into(),
            status: "Verified".into(),
            url: "https://api/v1".into(),
        }));
        m.apply(Update::LogLine("scan complete".into()));
        let out = m.render_ascii(72);
        assert!(out.contains("Mantis TUI"));
        assert!(out.contains("01HXX"));
        assert!(out.contains("idor"));
        assert!(out.contains("scan complete"));
    }

    #[test]
    fn clear_drops_claims_and_logs() {
        let mut m = ScreenModel::new();
        m.apply(Update::ClaimAdded(ClaimRow {
            vuln_class: "x".into(),
            severity: "Low".into(),
            status: "Verified".into(),
            url: "u".into(),
        }));
        m.apply(Update::LogLine("a".into()));
        m.apply(Update::Clear);
        assert!(m.claims.is_empty());
        assert!(m.log_lines.is_empty());
    }
}
