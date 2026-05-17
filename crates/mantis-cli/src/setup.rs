//! First-run setup screen.
//!
//! Triggered by `mantis` with no subcommand, or `mantis setup`. Prints
//! the green ASCII banner, scans the environment for known LLM
//! providers, and tells the user exactly what to do next.
//!
//! Supported providers (must match the matrix in `handle_llm`):
//! - `anthropic`   — direct Anthropic API, key in `ANTHROPIC_API_KEY`
//! - `openai`      — direct OpenAI API,    key in `OPENAI_API_KEY`
//! - `claude-cli`  — shells out to the local `claude` binary; no key

use std::io::IsTerminal;
use std::path::PathBuf;

use crate::banner;

const GREEN: &str = "\x1b[32m";
const DIM: &str = "\x1b[2;37m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

struct LlmStatus {
    /// Internal id passed to `mantis llm probe --provider <id>`.
    id: &'static str,
    /// Human-friendly name shown in the table.
    display: &'static str,
    /// True when the provider is fully ready to use.
    ready: bool,
    /// One-line detail (key fingerprint, binary path, or why not ready).
    detail: String,
    /// Copy-pasteable command to make this provider ready.
    setup_hint: &'static str,
}

pub(crate) fn run() {
    banner::print();

    let use_color = should_color();
    let g = if use_color { GREEN } else { "" };
    let d = if use_color { DIM } else { "" };
    let b = if use_color { BOLD } else { "" };
    let r = if use_color { RESET } else { "" };

    let statuses = detect();
    let ready_count = statuses.iter().filter(|s| s.ready).count();

    eprintln!("    {b}LLM providers detected{r}");
    eprintln!("    {d}─────────────────────{r}");
    for s in &statuses {
        let marker = if s.ready {
            format!("{g}✓{r}")
        } else {
            format!("{d}·{r}")
        };
        eprintln!(
            "    {marker} {name:<20} {detail}",
            name = s.display,
            detail = s.detail,
        );
    }
    eprintln!();

    if ready_count == 0 {
        eprintln!(
            "    {b}No LLM is configured yet.{r} Configure at least one to run a scan:"
        );
        eprintln!();
        for s in &statuses {
            eprintln!("      {d}# {name}{r}", name = s.display);
            eprintln!("      {hint}", hint = s.setup_hint);
            eprintln!();
        }
        eprintln!(
            "    Then run {b}mantis{r} again — this screen will show {g}✓{r} next to the one you set up."
        );
    } else {
        eprintln!(
            "    {g}{ready_count} provider(s) ready.{r} Try a scan:"
        );
        eprintln!();
        eprintln!("      {b}mantis pentest https://example.com{r}");
        eprintln!("      {b}mantis hack    https://example.com{r}");
        eprintln!();
        eprintln!(
            "    Or verify the provider end-to-end with {d}1 token{r}:"
        );
        eprintln!();
        for s in statuses.iter().filter(|s| s.ready) {
            eprintln!("      mantis llm probe --provider {id}", id = s.id);
        }
    }
    eprintln!();
    eprintln!(
        "    {d}docs: https://mantishack.com/docs{r}   {d}help: mantis --help{r}"
    );
    eprintln!();
}

fn detect() -> Vec<LlmStatus> {
    vec![
        detect_anthropic(),
        detect_openai(),
        detect_claude_cli(),
    ]
}

fn detect_anthropic() -> LlmStatus {
    match std::env::var("ANTHROPIC_API_KEY") {
        Ok(k) if !k.trim().is_empty() => LlmStatus {
            id: "anthropic",
            display: "Anthropic API",
            ready: true,
            detail: format!("ANTHROPIC_API_KEY set ({})", fingerprint(&k)),
            setup_hint: "export ANTHROPIC_API_KEY=sk-ant-...   # from https://console.anthropic.com/",
        },
        _ => LlmStatus {
            id: "anthropic",
            display: "Anthropic API",
            ready: false,
            detail: "ANTHROPIC_API_KEY not set".to_string(),
            setup_hint: "export ANTHROPIC_API_KEY=sk-ant-...   # from https://console.anthropic.com/",
        },
    }
}

fn detect_openai() -> LlmStatus {
    match std::env::var("OPENAI_API_KEY") {
        Ok(k) if !k.trim().is_empty() => LlmStatus {
            id: "openai",
            display: "OpenAI API",
            ready: true,
            detail: format!("OPENAI_API_KEY set ({})", fingerprint(&k)),
            setup_hint: "export OPENAI_API_KEY=sk-...          # from https://platform.openai.com/api-keys",
        },
        _ => LlmStatus {
            id: "openai",
            display: "OpenAI API",
            ready: false,
            detail: "OPENAI_API_KEY not set".to_string(),
            setup_hint: "export OPENAI_API_KEY=sk-...          # from https://platform.openai.com/api-keys",
        },
    }
}

fn detect_claude_cli() -> LlmStatus {
    match which("claude") {
        Some(path) => LlmStatus {
            id: "claude-cli",
            display: "Claude Code CLI",
            ready: true,
            detail: format!("claude on PATH ({})", path.display()),
            setup_hint: "npm install -g @anthropic-ai/claude-code   # then run `claude` once to log in",
        },
        None => LlmStatus {
            id: "claude-cli",
            display: "Claude Code CLI",
            ready: false,
            detail: "`claude` binary not on PATH".to_string(),
            setup_hint: "npm install -g @anthropic-ai/claude-code   # then run `claude` once to log in",
        },
    }
}

/// Minimal `which` — walks `$PATH` looking for an executable named `name`.
/// No external dep.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &std::path::Path) -> bool {
    p.is_file()
}

/// Show only the first 4 + last 4 chars of a secret, e.g. `sk-a…wxyz`.
/// Never log the full key.
fn fingerprint(key: &str) -> String {
    let trimmed = key.trim();
    let n = trimmed.chars().count();
    if n <= 10 {
        return "***".to_string();
    }
    let head: String = trimmed.chars().take(4).collect();
    let tail: String = trimmed.chars().skip(n - 4).collect();
    format!("{head}…{tail}")
}

fn should_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_short_keys_redacted() {
        assert_eq!(fingerprint("short"), "***");
        assert_eq!(fingerprint(""), "***");
    }

    #[test]
    fn fingerprint_long_keys_show_head_and_tail() {
        let fp = fingerprint("sk-ant-api03-AAAAAAAAAAAAAAAAwxyz");
        assert!(fp.starts_with("sk-a"));
        assert!(fp.ends_with("wxyz"));
        assert!(fp.contains('…'));
        // Must never contain the middle of the key.
        assert!(!fp.contains("AAAAAAAA"));
    }

    #[test]
    fn detect_returns_all_three_providers() {
        let s = detect();
        assert_eq!(s.len(), 3);
        let ids: Vec<_> = s.iter().map(|x| x.id).collect();
        assert!(ids.contains(&"anthropic"));
        assert!(ids.contains(&"openai"));
        assert!(ids.contains(&"claude-cli"));
    }
}
