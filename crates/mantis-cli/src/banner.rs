//! ASCII banner.
//!
//! Printed at the start of every offensive Mantis invocation —
//! `mantis hack`, `mantis pentest`, `mantis find-auth-bugs`,
//! `mantis goal`, `mantis auth-diff` — so the terminal-user always
//! sees the brand mark before any traffic leaves the host.
//!
//! Honors:
//! - `--no-banner` flag (set via Command-level handlers)
//! - `NO_COLOR` env var (W3C suggested) — strips ANSI escapes
//! - `MANTIS_NO_BANNER=1` env var — suppresses output entirely
//! - non-TTY stderr — strips ANSI escapes (so logs / pipes stay clean)

use std::io::IsTerminal;

const MINT: &str = "\x1b[38;2;130;240;180m";
const DIM: &str = "\x1b[38;2;160;160;180m";
const RESET: &str = "\x1b[0m";

/// Block-letter "MANTIS" rendered in ANSI Shadow style.
const BANNER_LINES: &[&str] = &[
    "███╗   ███╗ █████╗ ███╗   ██╗████████╗██╗███████╗",
    "████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝",
    "██╔████╔██║███████║██╔██╗ ██║   ██║   ██║███████╗",
    "██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██║╚════██║",
    "██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║███████║",
    "╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝",
];

const TAGLINE_VERBS: &str = "stalk · wait · strike · hold";
const TAGLINE_BODY: &str = "ethically hack any website with the power of AI";

/// Print the banner to stderr. Stderr because mantis subcommands
/// emit JSON / structured data on stdout, and we don't want to
/// pollute pipeable output.
pub fn print() {
    if std::env::var_os("MANTIS_NO_BANNER").is_some() {
        return;
    }
    let use_color = should_color();
    let mint = if use_color { MINT } else { "" };
    let dim = if use_color { DIM } else { "" };
    let reset = if use_color { RESET } else { "" };

    eprintln!();
    for line in BANNER_LINES {
        eprintln!("{mint}{line}{reset}");
    }
    eprintln!();
    eprintln!("    {dim}{TAGLINE_VERBS}{reset}");
    eprintln!("    {TAGLINE_BODY}");
    eprintln!();
}

/// Print only if the caller hasn't already suppressed it via flag.
pub fn maybe_print(suppress: bool) {
    if !suppress {
        print();
    }
}

/// Plain (no-ANSI) version — used by the markdown slash-command
/// renderer, log files, CI artifacts, etc. Returns the full string
/// with a trailing newline.
pub fn plain_text() -> String {
    let mut s = String::new();
    s.push('\n');
    for line in BANNER_LINES {
        s.push_str(line);
        s.push('\n');
    }
    s.push('\n');
    s.push_str("    ");
    s.push_str(TAGLINE_VERBS);
    s.push('\n');
    s.push_str("    ");
    s.push_str(TAGLINE_BODY);
    s.push('\n');
    s
}

fn should_color() -> bool {
    // W3C / informal cross-tool convention: NO_COLOR=any value → no
    // color. Also disable when stderr isn't a terminal.
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if !std::io::stderr().is_terminal() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_has_six_lines_of_letters() {
        assert_eq!(BANNER_LINES.len(), 6);
    }

    #[test]
    fn plain_text_contains_letters_and_tagline() {
        let t = plain_text();
        assert!(t.contains("MANTIS") || t.contains("█"));
        assert!(t.contains("stalk"));
        assert!(t.contains("ethically hack any website"));
    }

    #[test]
    fn plain_text_has_no_ansi_escapes() {
        let t = plain_text();
        assert!(!t.contains("\x1b["));
    }

    #[test]
    fn every_line_is_same_visual_width() {
        // Width invariant — block letters must align. Char count
        // (not byte count) is the right measure for multi-byte
        // glyphs like █, ╗, ╝.
        let widths: Vec<usize> = BANNER_LINES.iter().map(|s| s.chars().count()).collect();
        let first = widths[0];
        for (i, w) in widths.iter().enumerate() {
            assert_eq!(
                *w, first,
                "line {i} width {w} != line 0 width {first}: {}",
                BANNER_LINES[i]
            );
        }
    }
}
