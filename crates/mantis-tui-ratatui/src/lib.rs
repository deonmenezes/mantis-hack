//! ratatui binding for [`mantis_tui::ScreenModel`] (PRD §9.2, M2.4b).
//!
//! Renders the model into a three-pane layout:
//! - top: engagement list (highlighted selection)
//! - middle: recent claims table
//! - bottom: log tail
//!
//! Keeps the renderer pure: given a model and a frame, it draws.
//! Input handling and the event-loop driver belong to the binary,
//! not to this library — keeping it test-driven against
//! `ratatui::backend::TestBackend` without spinning a real terminal.

use mantis_tui::{ClaimRow, EngagementRow, ScreenModel};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

/// Top-level renderer. Splits the frame into three panes and renders
/// the model's three list views.
pub fn render(model: &ScreenModel, frame: &mut Frame<'_>) {
    let area = frame.area();
    render_area(model, area, frame.buffer_mut());
}

/// Direct rendering against a `Buffer`. Used by tests and by callers
/// that already manage their own frame lifecycle.
pub fn render_area(model: &ScreenModel, area: Rect, buf: &mut Buffer) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Min(5),
            Constraint::Length(8),
        ])
        .split(area);

    render_engagements(model, chunks[0], buf);
    render_claims(model, chunks[1], buf);
    render_log(model, chunks[2], buf);
}

fn render_engagements(model: &ScreenModel, area: Rect, buf: &mut Buffer) {
    let title = Line::from(vec![
        Span::styled(
            " Mantis ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("/ engagements "),
    ]);
    let block = Block::default().title(title).borders(Borders::ALL);

    if model.engagements.is_empty() {
        let p = Paragraph::new("  (no engagements)")
            .block(block)
            .wrap(Wrap { trim: false });
        ratatui::widgets::Widget::render(p, area, buf);
        return;
    }

    let rows: Vec<Row> = model
        .engagements
        .iter()
        .enumerate()
        .map(|(idx, e)| build_engagement_row(idx, e, model.selected_engagement))
        .collect();

    let widths = [
        Constraint::Length(16), // id
        Constraint::Min(12),    // name
        Constraint::Length(12), // state
        Constraint::Length(10), // events
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                Cell::from(" id"),
                Cell::from(" name"),
                Cell::from(" state"),
                Cell::from(" events"),
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(block)
        .column_spacing(1);
    ratatui::widgets::Widget::render(table, area, buf);
}

fn build_engagement_row<'a>(
    idx: usize,
    row: &'a EngagementRow,
    selected: Option<usize>,
) -> Row<'a> {
    let is_sel = Some(idx) == selected;
    let marker = if is_sel { ">" } else { " " };
    let style = if is_sel {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Row::new(vec![
        Cell::from(format!("{marker}{}", row.id)),
        Cell::from(row.name.as_str()),
        Cell::from(row.state.as_str()),
        Cell::from(row.events.to_string()),
    ])
    .style(style)
}

fn render_claims(model: &ScreenModel, area: Rect, buf: &mut Buffer) {
    let title = Line::from(" claims ");
    let block = Block::default().title(title).borders(Borders::ALL);

    if model.claims.is_empty() {
        let p = Paragraph::new("  (no claims yet)").block(block);
        ratatui::widgets::Widget::render(p, area, buf);
        return;
    }

    let rows: Vec<Row> = model
        .claims
        .iter()
        .rev()
        .take((area.height.saturating_sub(3)) as usize)
        .map(build_claim_row)
        .collect();

    let widths = [
        Constraint::Length(12), // severity
        Constraint::Length(20), // vuln class
        Constraint::Length(12), // status
        Constraint::Min(20),    // url
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                Cell::from(" severity"),
                Cell::from(" vuln class"),
                Cell::from(" status"),
                Cell::from(" url"),
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(block)
        .column_spacing(1);
    ratatui::widgets::Widget::render(table, area, buf);
}

fn build_claim_row(row: &ClaimRow) -> Row<'_> {
    let sev_style = match row.severity.as_str() {
        "Critical" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        "High" => Style::default().fg(Color::LightRed),
        "Medium" => Style::default().fg(Color::Yellow),
        "Low" => Style::default().fg(Color::Green),
        _ => Style::default(),
    };
    Row::new(vec![
        Cell::from(row.severity.as_str()).style(sev_style),
        Cell::from(row.vuln_class.as_str()),
        Cell::from(row.status.as_str()),
        Cell::from(row.url.as_str()),
    ])
}

fn render_log(model: &ScreenModel, area: Rect, buf: &mut Buffer) {
    let block = Block::default().title(" log ").borders(Borders::ALL);
    let max_lines = area.height.saturating_sub(2) as usize;
    let text = if model.log_lines.is_empty() {
        "  (no log lines)".to_owned()
    } else {
        model
            .log_lines
            .iter()
            .rev()
            .take(max_lines)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    };
    let p = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
    ratatui::widgets::Widget::render(p, area, buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_tui::{ClaimRow, EngagementRow, ScreenModel, Update};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn buffer_text(buf: &Buffer) -> String {
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn render_to_string(model: &ScreenModel, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(model, f)).unwrap();
        buffer_text(terminal.backend().buffer())
    }

    #[test]
    fn empty_model_renders_three_panes() {
        let model = ScreenModel::new();
        let s = render_to_string(&model, 80, 24);
        assert!(s.contains("Mantis"));
        assert!(s.contains("engagements"));
        assert!(s.contains("(no engagements)"));
        assert!(s.contains("claims"));
        assert!(s.contains("(no claims yet)"));
        assert!(s.contains("log"));
        assert!(s.contains("(no log lines)"));
    }

    #[test]
    fn engagement_rows_appear_in_engagement_pane() {
        let mut model = ScreenModel::new();
        model.apply(Update::EngagementUpserted(EngagementRow {
            id: "01HA".into(),
            name: "demo-target".into(),
            state: "active".into(),
            events: 42,
        }));
        let s = render_to_string(&model, 100, 24);
        assert!(s.contains("01HA"));
        assert!(s.contains("demo-target"));
        assert!(s.contains("active"));
        assert!(s.contains("42"));
    }

    #[test]
    fn selected_engagement_is_marked_with_caret() {
        let mut model = ScreenModel::new();
        model.apply(Update::EngagementUpserted(EngagementRow {
            id: "01HA".into(),
            name: "a".into(),
            state: "active".into(),
            events: 1,
        }));
        model.apply(Update::EngagementUpserted(EngagementRow {
            id: "01HB".into(),
            name: "b".into(),
            state: "active".into(),
            events: 2,
        }));
        model.apply(Update::SelectEngagement(1));
        let s = render_to_string(&model, 100, 24);
        // The marker > prefixes the id of the selected engagement.
        let lines: Vec<&str> = s.lines().collect();
        let marked = lines
            .iter()
            .find(|l| l.contains(">01HB"))
            .expect("selected row should have > marker");
        assert!(marked.contains("01HB"));
    }

    #[test]
    fn claims_appear_in_claims_pane() {
        let mut model = ScreenModel::new();
        model.apply(Update::ClaimAdded(ClaimRow {
            vuln_class: "sqli".into(),
            severity: "High".into(),
            status: "verified".into(),
            url: "https://x.example/v1/q".into(),
        }));
        let s = render_to_string(&model, 100, 24);
        assert!(s.contains("sqli"));
        assert!(s.contains("High"));
        assert!(s.contains("verified"));
        assert!(s.contains("x.example"));
    }

    #[test]
    fn log_lines_appear_in_log_pane_newest_first() {
        let mut model = ScreenModel::new();
        model.apply(Update::LogLine("first line".into()));
        model.apply(Update::LogLine("second line".into()));
        let s = render_to_string(&model, 100, 24);
        let first_idx = s.find("first line").unwrap();
        let second_idx = s.find("second line").unwrap();
        // Reverse order: second (newest) should appear before first.
        assert!(second_idx < first_idx);
    }

    #[test]
    fn render_area_does_not_panic_on_tiny_areas() {
        let model = ScreenModel::new();
        let backend = TestBackend::new(20, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(&model, f)).unwrap();
    }

    #[test]
    fn claims_pane_caps_visible_rows_to_pane_height() {
        let mut model = ScreenModel::new();
        for i in 0..50 {
            model.apply(Update::ClaimAdded(ClaimRow {
                vuln_class: format!("class-{i}"),
                severity: "Low".into(),
                status: "verified".into(),
                url: format!("https://x.example/{i}"),
            }));
        }
        // 80x24 frame: claims pane is the middle constraint (Min 5).
        // With 8 + 8 + remaining(=8) = 24 rows total. We should NOT
        // see all 50 entries — only what fits in the middle pane.
        let s = render_to_string(&model, 80, 24);
        let count = (0..50)
            .filter(|i| s.contains(&format!("class-{i}")))
            .count();
        assert!(count < 50);
        // But the most recent one (class-49) must always be visible.
        assert!(s.contains("class-49"));
    }
}
