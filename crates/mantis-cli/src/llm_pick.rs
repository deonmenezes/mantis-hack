//! First-available LLM adapter picker.
//!
//! Used by the offensive pipeline (`mantis hack`, `mantis pentest`,
//! `mantis goal`) to opportunistically call an LLM without forcing
//! the user to configure one. Picker order:
//!
//!   1. `ANTHROPIC_API_KEY`   → [`AnthropicAdapter`]
//!   2. `OPENAI_API_KEY`      → [`OpenAIAdapter`]
//!   3. `claude` binary on PATH → [`ClaudeCliAdapter`]
//!   4. None
//!
//! The picker is deliberately ordered: direct-API keys are preferred
//! over the CLI subprocess (lower latency, no shell-out, no spawn
//! overhead). The CLI adapter is the fallback because it doesn't
//! require the user to manage keys — Claude Code's own auth handles
//! that.
//!
//! Honors:
//! - `MANTIS_NO_LLM=1`  → always returns `None`
//! - `MANTIS_LLM_PROVIDER=<id>` → force a specific provider
//!   (`anthropic`, `openai`, `claude-cli`); errors if unavailable.

use mantis_synthesizer::{
    anthropic::AnthropicAdapter, claude_cli::ClaudeCliAdapter, openai::OpenAIAdapter, LlmAdapter,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// What kind of provider was picked. Lets callers log what they used
/// without re-running the picker.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PickedProvider {
    Anthropic,
    OpenAI,
    ClaudeCli,
}

impl PickedProvider {
    pub(crate) fn label(self) -> &'static str {
        match self {
            PickedProvider::Anthropic => "anthropic",
            PickedProvider::OpenAI => "openai",
            PickedProvider::ClaudeCli => "claude-cli",
        }
    }
}

/// Pick the first ready provider. Returns `None` when LLM is disabled
/// or no provider is available. The caller should treat `None` as
/// "skip the LLM-augmented step" — never as a fatal error.
pub(crate) fn pick() -> Option<(Arc<dyn LlmAdapter>, PickedProvider)> {
    if std::env::var_os("MANTIS_NO_LLM").is_some() {
        return None;
    }

    // Forced provider — useful for tests and for users who have
    // multiple keys but want to lock in one.
    if let Ok(forced) = std::env::var("MANTIS_LLM_PROVIDER") {
        return force(&forced);
    }

    // Auto-pick.
    if let Some(key) = nonempty_env("ANTHROPIC_API_KEY") {
        let adapter = AnthropicAdapter::new(key).with_max_tokens(1024);
        return Some((Arc::new(adapter), PickedProvider::Anthropic));
    }
    if let Some(key) = nonempty_env("OPENAI_API_KEY") {
        let adapter = OpenAIAdapter::new(key).with_max_tokens(1024);
        return Some((Arc::new(adapter), PickedProvider::OpenAI));
    }
    if which("claude").is_some() {
        let adapter = ClaudeCliAdapter::new();
        return Some((Arc::new(adapter), PickedProvider::ClaudeCli));
    }
    None
}

fn force(id: &str) -> Option<(Arc<dyn LlmAdapter>, PickedProvider)> {
    match id {
        "anthropic" => nonempty_env("ANTHROPIC_API_KEY").map(|k| {
            let a: Arc<dyn LlmAdapter> =
                Arc::new(AnthropicAdapter::new(k).with_max_tokens(1024));
            (a, PickedProvider::Anthropic)
        }),
        "openai" => nonempty_env("OPENAI_API_KEY").map(|k| {
            let a: Arc<dyn LlmAdapter> = Arc::new(OpenAIAdapter::new(k).with_max_tokens(1024));
            (a, PickedProvider::OpenAI)
        }),
        "claude-cli" => which("claude").map(|_| {
            let a: Arc<dyn LlmAdapter> = Arc::new(ClaudeCliAdapter::new());
            (a, PickedProvider::ClaudeCli)
        }),
        other => {
            eprintln!(
                "[mantis] warning: MANTIS_LLM_PROVIDER={other} is not a known provider \
                 (anthropic, openai, claude-cli) — skipping LLM"
            );
            None
        }
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

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

// ---------------------------------------------------------------------------
// LLM-augmented pipeline helpers.
//
// Both functions are best-effort: any failure (network, malformed
// reply, auth, sandbox) is logged to stderr and yields a no-op
// result. The deterministic pipeline must never depend on these
// succeeding.
// ---------------------------------------------------------------------------

/// Cap LLM-suggested paths so a hallucinating model can't blow up
/// the wordlist. 50 is generous — typical reply yields 10–25.
const MAX_LLM_PATHS: usize = 50;

/// Ask the LLM for high-signal API endpoint paths to add to the
/// wordlist, based on the recon notes from Phase 1.
pub(crate) async fn suggest_paths(
    adapter: &dyn LlmAdapter,
    target_url: &str,
    discovery_notes: &[String],
    supabase_detected: bool,
) -> Vec<String> {
    let notes_block = if discovery_notes.is_empty() {
        "(no discovery notes)".to_string()
    } else {
        discovery_notes
            .iter()
            .take(40)
            .map(|n| format!("- {n}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let backend = if supabase_detected { "Supabase" } else { "unknown / none detected" };
    let prompt = format!(
        "You are an offensive-security recon assistant. Based on this target's \
         discovered surface, list up to 25 high-signal API endpoint paths to probe \
         for broken authorization (IDOR, tenant isolation, role escalation, \
         unauthenticated reads).\n\n\
         OUTPUT FORMAT (strict): one path per line. Each path starts with '/'. \
         No commentary, no markdown, no numbering. If you have no good guesses, \
         output nothing.\n\n\
         Target:        {target_url}\n\
         Auth backend:  {backend}\n\
         Discovery notes:\n{notes_block}"
    );
    match adapter.complete(&prompt).await {
        Ok(text) => parse_paths(&text),
        Err(e) => {
            eprintln!(
                "[mantis] LLM hypothesis call failed ({e}); continuing without LLM-suggested paths"
            );
            Vec::new()
        }
    }
}

fn parse_paths(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        // Strip leading bullets, numbering, whitespace, code fences.
        let stripped = raw
            .trim()
            .trim_start_matches("```")
            .trim_start_matches(|c: char| {
                c.is_whitespace() || matches!(c, '-' | '*' | '•' | '.' | ')' | '(') || c.is_ascii_digit()
            })
            .trim();
        // Some models wrap paths in backticks.
        let stripped = stripped.trim_matches('`');
        if !stripped.starts_with('/') {
            continue;
        }
        // Reject pathological lines.
        if stripped.len() > 200 || stripped.contains(char::is_whitespace) {
            continue;
        }
        out.push(stripped.to_string());
        if out.len() >= MAX_LLM_PATHS {
            break;
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Append an LLM-drafted Executive Summary section to the
/// vulnerability-report markdown. `findings_summary` should be a
/// short factual blob (counts, top classes, top endpoints) — keep
/// the prompt under a few KB so it works for free-tier models too.
pub(crate) async fn append_exec_summary(
    adapter: &dyn LlmAdapter,
    report_path: &Path,
    findings_summary: &str,
) {
    let prompt = format!(
        "You are writing the Executive Summary section of a penetration-test report. \
         Below is the deterministic pipeline's findings summary — treat it as the \
         single source of truth. DO NOT invent findings, severities, endpoints, or \
         attack chains that aren't already in the summary.\n\n\
         Produce 3-6 sentences of plain markdown (no top-level heading; the section \
         heading is added by the caller). Cover, in order:\n\
         1. testing scope and method, in one line;\n\
         2. the result in one line;\n\
         3. the top 3 most important risks if any (else: explicit statement that \
            none were found);\n\
         4. the single most impactful next step.\n\n\
         Findings summary:\n{findings_summary}"
    );
    match adapter.complete(&prompt).await {
        Ok(text) => {
            let body = text.trim();
            if body.is_empty() {
                eprintln!("[mantis] LLM exec-summary returned empty; skipping append");
                return;
            }
            let block = format!(
                "\n\n## Executive Summary (LLM-augmented)\n\n_Generated by an LLM from the deterministic findings above. The findings themselves are authoritative._\n\n{body}\n"
            );
            match std::fs::OpenOptions::new().append(true).open(report_path) {
                Ok(mut f) => {
                    use std::io::Write;
                    if let Err(e) = f.write_all(block.as_bytes()) {
                        eprintln!("[mantis] LLM exec-summary write failed ({e})");
                    }
                }
                Err(e) => eprintln!(
                    "[mantis] LLM exec-summary cannot open report {} ({e})",
                    report_path.display()
                ),
            }
        }
        Err(e) => eprintln!("[mantis] LLM exec-summary call failed ({e}); continuing"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_paths_extracts_clean_paths() {
        let text = "/api/users\n/api/orders\n  /admin/keys  \nblah\n- /api/foo\n  2. /api/bar\n";
        let paths = parse_paths(text);
        assert!(paths.contains(&"/api/users".to_string()));
        assert!(paths.contains(&"/api/orders".to_string()));
        assert!(paths.contains(&"/admin/keys".to_string()));
        assert!(paths.contains(&"/api/foo".to_string()));
        assert!(paths.contains(&"/api/bar".to_string()));
        assert!(!paths.contains(&"blah".to_string()));
    }

    #[test]
    fn parse_paths_dedupes_and_caps() {
        let mut text = String::new();
        for i in 0..200 {
            text.push_str(&format!("/api/x{i}\n"));
        }
        let paths = parse_paths(&text);
        assert!(paths.len() <= MAX_LLM_PATHS);
    }

    #[test]
    fn parse_paths_rejects_paths_with_spaces() {
        let text = "/api/has space\n/clean\n";
        let paths = parse_paths(text);
        assert_eq!(paths, vec!["/clean".to_string()]);
    }
}
