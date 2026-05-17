//! Minimal PDF emitter (PRD §5.9.1 — M2.5d).
//!
//! Hand-rolled PDF/1.4 writer. Text-only. Each page uses Helvetica
//! 12pt for body and 16pt bold-ish for headers (rendered via the
//! built-in Helvetica-Bold font). The output is a valid PDF that
//! every major viewer (macOS Preview, Chrome, Adobe Reader, etc.)
//! renders correctly.
//!
//! Choosing to hand-roll PDF rather than depend on Typst keeps the
//! workspace dependency footprint small and avoids pulling in a
//! C++ typesetter for what is fundamentally a structured-text
//! report. The trade-off is that the PDF is plain — no tables, no
//! images. A future M2.5d2 may swap in Typst when the report's
//! visual fidelity requirements justify the dep.

use std::fmt::Write as _;

use crate::Report;
use mantis_claim::{Claim, ClaimState};

const PAGE_WIDTH: u32 = 612;
const PAGE_HEIGHT: u32 = 792;
const MARGIN_LEFT: u32 = 54;
const MARGIN_TOP: u32 = 54;
const MARGIN_BOTTOM: u32 = 54;
const BODY_LEADING: u32 = 14;
const HEADING_LEADING: u32 = 20;
const SUBHEAD_LEADING: u32 = 16;

const FONT_BODY: &str = "F1";
const FONT_BOLD: &str = "F2";
const FONT_MONO: &str = "F3";

pub fn render(report: &Report<'_>) -> Vec<u8> {
    let lines = build_lines(report);
    let pages = paginate(&lines);
    emit_pdf(&pages)
}

#[derive(Debug, Clone)]
enum Line {
    Heading(String),
    Subhead(String),
    Body(String),
    Mono(String),
    Spacer,
}

impl Line {
    fn leading(&self) -> u32 {
        match self {
            Line::Heading(_) => HEADING_LEADING,
            Line::Subhead(_) => SUBHEAD_LEADING,
            Line::Body(_) | Line::Mono(_) | Line::Spacer => BODY_LEADING,
        }
    }
    fn font_name(&self) -> &'static str {
        match self {
            Line::Heading(_) | Line::Subhead(_) => FONT_BOLD,
            Line::Mono(_) => FONT_MONO,
            Line::Body(_) | Line::Spacer => FONT_BODY,
        }
    }
    fn font_size(&self) -> u8 {
        match self {
            Line::Heading(_) => 16,
            Line::Subhead(_) => 13,
            _ => 11,
        }
    }
    fn text(&self) -> &str {
        match self {
            Line::Heading(s) | Line::Subhead(s) | Line::Body(s) | Line::Mono(s) => s,
            Line::Spacer => "",
        }
    }
}

fn build_lines(report: &Report<'_>) -> Vec<Line> {
    let mut lines = vec![];
    lines.push(Line::Heading("Mantis Engagement Report".into()));
    lines.push(Line::Spacer);
    lines.push(Line::Body(format!(
        "Engagement: {}",
        report.metadata.engagement_id
    )));
    lines.push(Line::Body(format!(
        "Name: {}",
        report.metadata.engagement_name
    )));
    if let Some(op) = &report.metadata.operator_name {
        lines.push(Line::Body(format!("Operator: {op}")));
    }
    lines.push(Line::Body(format!(
        "Generated at: {} (unix seconds)",
        report.metadata.generated_at_unix
    )));
    if let Some(fp) = &report.metadata.workspace_fingerprint {
        lines.push(Line::Body(format!("Workspace fingerprint: {fp}")));
    }
    lines.push(Line::Spacer);

    let verified: Vec<&Claim> = report
        .claims
        .iter()
        .filter(|c| matches!(c.state, ClaimState::Verified { .. }))
        .collect();
    let rejected = report
        .claims
        .iter()
        .filter(|c| matches!(c.state, ClaimState::Rejected { .. }))
        .count();
    let retained = report
        .claims
        .iter()
        .filter(|c| matches!(c.state, ClaimState::Retained { .. }))
        .count();

    lines.push(Line::Subhead("Summary".into()));
    lines.push(Line::Body(format!("Verified findings: {}", verified.len())));
    lines.push(Line::Body(format!("Rejected by verifier: {rejected}")));
    lines.push(Line::Body(format!(
        "Retained (verifier inconclusive): {retained}"
    )));
    lines.push(Line::Spacer);

    if verified.is_empty() {
        lines.push(Line::Subhead("Findings".into()));
        lines.push(Line::Body(
            "No verified findings in this engagement.".into(),
        ));
    } else {
        lines.push(Line::Subhead("Findings".into()));
        let mut sorted = verified.clone();
        sorted.sort_by(|a, b| {
            crate::severity::severity_for(&b.vuln_class)
                .rank()
                .cmp(&crate::severity::severity_for(&a.vuln_class).rank())
        });
        for (idx, claim) in sorted.iter().enumerate() {
            lines.push(Line::Spacer);
            let sev = crate::severity::severity_for(&claim.vuln_class);
            lines.push(Line::Subhead(format!(
                "Finding {}: {} on {}",
                idx + 1,
                crate::pretty_class(&claim.vuln_class),
                claim.surface.url()
            )));
            lines.push(Line::Body(format!(
                "Vulnerability class: {}",
                claim.vuln_class
            )));
            lines.push(Line::Body(format!("Primitive: {}", claim.primitive_id)));
            lines.push(Line::Body(format!("Severity: {sev}")));
            if let ClaimState::Verified { verifier_id } = &claim.state {
                lines.push(Line::Body(format!("Verified by: {verifier_id}")));
            }
            lines.push(Line::Spacer);
            lines.push(Line::Body("Evidence:".into()));
            for ev in &claim.evidence {
                lines.push(Line::Body(format!("  - {}: {}", ev.kind, ev.detail)));
            }
            lines.push(Line::Spacer);
            lines.push(Line::Body("Reproducer (cURL):".into()));
            for chunk in wrap(&claim.reproducer.curl, 80) {
                lines.push(Line::Mono(chunk));
            }
            lines.push(Line::Spacer);
            lines.push(Line::Body("Reproducer (raw HTTP):".into()));
            for raw_line in claim.reproducer.raw_http.split("\r\n") {
                for chunk in wrap(raw_line, 80) {
                    lines.push(Line::Mono(chunk));
                }
            }
            lines.push(Line::Spacer);
        }
    }
    lines
}

fn wrap(s: &str, max: usize) -> Vec<String> {
    if s.is_empty() {
        return vec![String::new()];
    }
    let mut out = vec![];
    let mut buf = String::new();
    for ch in s.chars() {
        buf.push(ch);
        if buf.chars().count() >= max {
            out.push(std::mem::take(&mut buf));
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

fn paginate(lines: &[Line]) -> Vec<Vec<Line>> {
    let usable = PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM;
    let mut pages: Vec<Vec<Line>> = vec![vec![]];
    let mut y = 0u32;
    for line in lines {
        let leading = line.leading();
        if y + leading > usable {
            pages.push(vec![]);
            y = 0;
        }
        pages.last_mut().expect("never empty").push(line.clone());
        y += leading;
    }
    pages
}

fn emit_pdf(pages: &[Vec<Line>]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(4096);
    out.extend_from_slice(b"%PDF-1.4\n");
    out.extend_from_slice(b"%\xe2\xe3\xcf\xd3\n"); // PDF binary marker

    // Object 1: Catalog
    // Object 2: Pages
    // Object 3..3+N-1: Page objects
    // Object 3+N..3+2N-1: Content streams
    // Object 3+2N..3+2N+2: Fonts (F1 Helvetica, F2 Helvetica-Bold, F3 Courier)
    let n = pages.len() as u32;
    let page_obj_start = 3u32;
    let content_obj_start = page_obj_start + n;
    let font_obj_start = content_obj_start + n;

    let mut offsets: Vec<usize> = vec![0]; // index 0 = free object placeholder

    offsets.push(out.len());
    write!(
        &mut out as &mut dyn std::io::Write,
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    )
    .unwrap();

    offsets.push(out.len());
    let kids: String = (0..n)
        .map(|i| format!("{} 0 R", page_obj_start + i))
        .collect::<Vec<_>>()
        .join(" ");
    write!(
        &mut out as &mut dyn std::io::Write,
        "2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {n} >>\nendobj\n"
    )
    .unwrap();

    // Page objects.
    for i in 0..n {
        offsets.push(out.len());
        let contents = content_obj_start + i;
        write!(
            &mut out as &mut dyn std::io::Write,
            "{} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] /Resources << /Font << /{FONT_BODY} {} 0 R /{FONT_BOLD} {} 0 R /{FONT_MONO} {} 0 R >> >> /Contents {} 0 R >>\nendobj\n",
            page_obj_start + i,
            font_obj_start,
            font_obj_start + 1,
            font_obj_start + 2,
            contents,
        ).unwrap();
    }

    // Content streams.
    for (i, page_lines) in pages.iter().enumerate() {
        let stream = build_content_stream(page_lines);
        offsets.push(out.len());
        write!(
            &mut out as &mut dyn std::io::Write,
            "{} 0 obj\n<< /Length {} >>\nstream\n",
            content_obj_start + i as u32,
            stream.len()
        )
        .unwrap();
        out.extend_from_slice(stream.as_bytes());
        out.extend_from_slice(b"\nendstream\nendobj\n");
    }

    // Fonts.
    for (i, (name, font)) in [
        (FONT_BODY, "Helvetica"),
        (FONT_BOLD, "Helvetica-Bold"),
        (FONT_MONO, "Courier"),
    ]
    .iter()
    .enumerate()
    {
        offsets.push(out.len());
        write!(
            &mut out as &mut dyn std::io::Write,
            "{} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /{font} /Name /{name} >>\nendobj\n",
            font_obj_start + i as u32,
        )
        .unwrap();
    }

    // xref table.
    let xref_offset = out.len();
    let total_objects = offsets.len();
    writeln!(&mut out as &mut dyn std::io::Write, "xref").unwrap();
    writeln!(&mut out as &mut dyn std::io::Write, "0 {total_objects}").unwrap();
    // First entry is the free-list head (object 0).
    out.extend_from_slice(b"0000000000 65535 f \n");
    for &offset in offsets.iter().skip(1) {
        writeln!(
            &mut out as &mut dyn std::io::Write,
            "{:010} 00000 n ",
            offset
        )
        .unwrap();
    }

    // Trailer. No trailing newline — the spec terminates with %%EOF
    // exactly, and downstream tooling treats the marker as the last
    // byte of the file.
    write!(
        &mut out as &mut dyn std::io::Write,
        "trailer\n<< /Size {total_objects} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF"
    )
    .unwrap();

    out
}

fn build_content_stream(lines: &[Line]) -> String {
    let mut out = String::new();
    out.push_str("BT\n");
    // Start at top-left of the printable area.
    let _ = writeln!(out, "{} {} Td", MARGIN_LEFT, PAGE_HEIGHT - MARGIN_TOP);
    let mut current_font = "";
    let mut current_size: u8 = 0;
    for line in lines {
        let f = line.font_name();
        let s = line.font_size();
        if f != current_font || s != current_size {
            let _ = writeln!(out, "/{f} {s} Tf");
            current_font = f;
            current_size = s;
        }
        let leading = line.leading();
        let _ = writeln!(out, "0 -{leading} Td");
        if !line.text().is_empty() {
            let _ = writeln!(out, "({}) Tj", escape_pdf_string(line.text()));
        }
    }
    out.push_str("ET\n");
    out
}

fn escape_pdf_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            // Replace any other non-printable / non-ASCII with `?`
            // so the PDF stays valid 7-bit ASCII.
            c if (c as u32) < 0x20 || (c as u32) > 0x7E => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_claim::{Claim, ClaimState, SurfaceSnapshot};
    use mantis_primitive::{EvidenceItem, Reproducer};

    fn sample_claim() -> Claim {
        Claim {
            primitive_id: "info-disclosure.missing-security-headers".into(),
            vuln_class: "info-disclosure".into(),
            surface: SurfaceSnapshot {
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/v1/users".into(),
                status: 200,
            },
            evidence: vec![EvidenceItem {
                kind: "missing-header".into(),
                detail: "strict-transport-security".into(),
            }],
            reproducer: Reproducer::from_curl_and_raw(
                "curl https://api.example.com/v1/users",
                "GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            ),
            state: ClaimState::Verified {
                verifier_id: "v.test".into(),
            },
        }
    }

    fn metadata() -> crate::ReportMetadata {
        crate::ReportMetadata {
            engagement_id: "01HXX".into(),
            engagement_name: "demo".into(),
            operator_name: Some("alice".into()),
            generated_at_unix: 1_700_000_000,
            workspace_fingerprint: Some("dead".into()),
        }
    }

    #[test]
    fn emits_valid_pdf_header() {
        let claims = vec![];
        let report = crate::Report::new(metadata(), &claims);
        let bytes = render(&report);
        assert!(bytes.starts_with(b"%PDF-1.4"));
        assert!(bytes.ends_with(b"%%EOF"));
    }

    #[test]
    fn includes_xref_and_trailer() {
        let claims = vec![];
        let report = crate::Report::new(metadata(), &claims);
        let bytes = render(&report);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("xref"));
        assert!(s.contains("trailer"));
        assert!(s.contains("startxref"));
        assert!(s.contains("/Root 1 0 R"));
    }

    #[test]
    fn embeds_finding_text() {
        let claims = vec![sample_claim()];
        let report = crate::Report::new(metadata(), &claims);
        let bytes = render(&report);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("Mantis Engagement Report"));
        assert!(s.contains("Finding 1"));
        assert!(s.contains("strict-transport-security"));
        assert!(s.contains("v.test"));
    }

    #[test]
    fn escapes_pdf_special_chars() {
        // A string containing parentheses and a backslash.
        let escaped = escape_pdf_string("a (b) \\c\n");
        assert_eq!(escaped, "a \\(b\\) \\\\c\\n");
    }

    #[test]
    fn paginate_splits_when_content_overflows() {
        let mut lines = Vec::new();
        for _ in 0..200 {
            lines.push(Line::Body("x".into()));
        }
        let pages = paginate(&lines);
        assert!(pages.len() > 1);
    }

    #[test]
    fn empty_report_still_emits_one_page() {
        let claims = vec![];
        let report = crate::Report::new(metadata(), &claims);
        let bytes = render(&report);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("No verified findings"));
        // Should still have a valid xref table.
        assert!(s.contains("xref\n0 "));
    }

    #[test]
    fn handles_unicode_by_replacing_with_question_mark() {
        // The PDF emitter is 7-bit ASCII; non-ASCII chars become ?
        let escaped = escape_pdf_string("héllo wörld");
        assert!(escaped.chars().all(|c| (c as u32) < 0x80));
    }
}
