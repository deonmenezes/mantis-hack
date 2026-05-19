//! Pretty markdown logger for `claude --print` stream events.
//!
//! Captures every tool call, sub-agent spawn, MCP call, Bash, file
//! read/write, and assistant text block into `logs.md` so the
//! operator can audit (or share) exactly what the orchestrator did
//! without having to re-parse the raw stream-json.
//!
//! Markdown is chosen over JSON-lines because:
//!   - The output is human-meant — a hunter reviewing post-engagement.
//!   - GitHub renders it directly in the engagement dir.
//!   - The structured event stream is already persisted in the
//!     daemon's Merkle log; this file is the human mirror.
//!
//! Each run writes a single header + monotonic timestamped sections;
//! re-running `mantis hack` / `mantis prompt` appends a new "Run"
//! header so multiple sessions accumulate in the same file.

use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Markdown log writer. One per `claude --print` invocation; calls
/// to [`Self::record`] are cheap (no fsync) and best-effort —
/// failures are logged to stderr but never propagated to the caller
/// (we don't want a log-disk-full to crash the orchestrator).
pub(crate) struct RunLog {
    path: PathBuf,
    started_at: Instant,
}

impl RunLog {
    /// Open `logs.md` at `path` (creating it if absent), append a
    /// new "Run started" header block, and return a handle.
    /// `kind` is the subcommand label — e.g. `mantis hack`,
    /// `mantis prompt`. `target` is whatever identifier the caller
    /// wants in the header (a URL for `hack`, the prompt text head
    /// for `prompt`).
    pub(crate) fn open(path: PathBuf, kind: &str, target: &str) -> Result<Self> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open log file {}", path.display()))?;

        let exists_already = file
            .metadata()
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        if !exists_already {
            writeln!(file, "# Mantis run log")?;
            writeln!(file)?;
            writeln!(
                file,
                "Every command Claude executes — tool calls, sub-agent spawns, MCP calls, Bash, \
                 file I/O, assistant turns. Each `mantis hack` / `mantis prompt` invocation \
                 appends a new section. Newest at the bottom."
            )?;
            writeln!(file)?;
        }
        writeln!(file, "---")?;
        writeln!(file)?;
        writeln!(file, "## {kind} — {target}")?;
        writeln!(file)?;
        writeln!(file, "- **started**: `{}`", iso_now())?;
        writeln!(file)?;
        Ok(Self {
            path,
            started_at: Instant::now(),
        })
    }

    /// Record one stream event. Always best-effort; never errors out.
    pub(crate) fn record(&self, event: &serde_json::Value) {
        if let Some(entry) = render_event(event, self.started_at.elapsed().as_secs_f64()) {
            if let Err(e) = self.append(&entry) {
                eprintln!("[mantishack] log-write failed ({}): {e}", self.path.display());
            }
        }
    }

    /// Read-only access to the log file path. Auto-resume reads this
    /// to seed the next session with the prior log tail.
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Append a "Run finished" footer line + a blank gap.
    pub(crate) fn finalize(&self, exit_status: &str) {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        let footer = format!(
            "\n- **finished**: `{}`  ·  elapsed: `{elapsed:.1}s`  ·  status: `{exit_status}`\n\n",
            iso_now()
        );
        let _ = self.append(&footer);
    }

    fn append(&self, s: &str) -> Result<()> {
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        file.write_all(s.as_bytes())?;
        Ok(())
    }
}

/// Convert one `claude --print` stream-json event into a markdown
/// block. Returns `None` for events we deliberately drop (per-token
/// deltas, system pings, etc).
fn render_event(event: &serde_json::Value, t_secs: f64) -> Option<String> {
    let ty = event.get("type")?.as_str()?;
    match ty {
        "system" => {
            let subtype = event
                .get("subtype")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            Some(format!(
                "- `t={t_secs:6.1}s` · _system_ · `{subtype}`\n"
            ))
        }
        "assistant" => render_assistant(event, t_secs),
        "user" => render_user(event, t_secs),
        "result" => {
            let subtype = event.get("subtype").and_then(|s| s.as_str()).unwrap_or("");
            let cost = event
                .get("total_cost_usd")
                .and_then(|s| s.as_f64())
                .unwrap_or(0.0);
            let turns = event
                .get("num_turns")
                .and_then(|s| s.as_u64())
                .unwrap_or(0);
            Some(format!(
                "\n### Final result — `{subtype}`\n\n- turns: **{turns}**\n- cost: **${cost:.4}**\n"
            ))
        }
        _ => None,
    }
}

fn render_assistant(event: &serde_json::Value, t_secs: f64) -> Option<String> {
    let content = event.pointer("/message/content")?.as_array()?;
    let mut out = String::new();
    for block in content {
        let bty = block.get("type").and_then(|s| s.as_str()).unwrap_or("");
        match bty {
            "tool_use" => {
                let name = block.get("name").and_then(|s| s.as_str()).unwrap_or("?");
                let input = block.get("input");
                out.push_str(&format_tool_call(name, input, t_secs));
            }
            "text" => {
                let txt = block.get("text").and_then(|s| s.as_str()).unwrap_or("").trim();
                if !txt.is_empty() {
                    out.push_str(&format!("- `t={t_secs:6.1}s` · _assistant_:\n\n"));
                    for line in txt.lines() {
                        out.push_str("  > ");
                        out.push_str(line);
                        out.push('\n');
                    }
                    out.push('\n');
                }
            }
            _ => {}
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn render_user(event: &serde_json::Value, t_secs: f64) -> Option<String> {
    let content = event.pointer("/message/content")?.as_array()?;
    for block in content {
        if block.get("type").and_then(|s| s.as_str()) != Some("tool_result") {
            continue;
        }
        let is_error = block
            .get("is_error")
            .and_then(|s| s.as_bool())
            .unwrap_or(false);
        let marker = if is_error { "❌ error" } else { "✅ ok" };
        // Pull a short preview of the result text (first tool_result
        // content block, capped).
        let preview = block
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|first| first.get("text").and_then(|t| t.as_str()))
            .map(|t| {
                let trimmed = t.trim();
                if trimmed.len() <= 240 {
                    trimmed.to_string()
                } else {
                    format!("{}…", &trimmed[..240])
                }
            })
            .unwrap_or_default();
        let mut out = format!("  - `t={t_secs:6.1}s` · {marker}");
        if !preview.is_empty() {
            out.push_str(" — ");
            out.push_str(&preview.replace('\n', " "));
        }
        out.push('\n');
        return Some(out);
    }
    None
}

/// Format one `tool_use` block as a markdown bullet. The body shows
/// the tool name in code, the most informative argument inline, and
/// (for argument-heavy tools) a fenced JSON block with the full
/// input.
fn format_tool_call(name: &str, input: Option<&serde_json::Value>, t_secs: f64) -> String {
    let head_args = head_args_inline(name, input);
    let mut out = format!("- `t={t_secs:6.1}s` · 🛠 `{name}`");
    if !head_args.is_empty() {
        out.push_str(" — ");
        out.push_str(&head_args);
    }
    out.push('\n');
    if let Some(input) = input {
        if let Ok(pretty) = serde_json::to_string_pretty(input) {
            if pretty.len() > 80 && pretty.lines().count() > 1 {
                out.push_str("\n  <details><summary>full input</summary>\n\n  ```json\n");
                for line in pretty.lines() {
                    out.push_str("  ");
                    out.push_str(line);
                    out.push('\n');
                }
                out.push_str("  ```\n\n  </details>\n");
            }
        }
    }
    out
}

/// Single-line summary of the most informative argument for the given
/// tool — same as the terminal-stream version, just trimmed.
fn head_args_inline(name: &str, input: Option<&serde_json::Value>) -> String {
    let Some(input) = input else {
        return String::new();
    };
    match name {
        "Task" => {
            let subtype = input.get("subagent_type").and_then(|s| s.as_str()).unwrap_or("?");
            let bg = input.get("run_in_background").and_then(|s| s.as_bool()).unwrap_or(false);
            format!(
                "spawn **{subtype}**{}",
                if bg { " (background)" } else { "" }
            )
        }
        "Bash" => input
            .get("command")
            .and_then(|s| s.as_str())
            .map(|c| {
                let preview: String = c.chars().take(120).collect();
                format!("`{}`", preview.replace('`', "\\`"))
            })
            .unwrap_or_default(),
        "Read" | "Edit" | "Write" | "Glob" | "Grep" => input
            .get("file_path")
            .or_else(|| input.get("path"))
            .or_else(|| input.get("pattern"))
            .and_then(|s| s.as_str())
            .map(|s| format!("`{s}`"))
            .unwrap_or_default(),
        n if n.starts_with("mcp__mantis__") => {
            let mut parts = Vec::new();
            for key in [
                "target_domain",
                "wave",
                "agent",
                "to_phase",
                "round",
                "auth_status",
                "profile_name",
                "engagement_id",
            ] {
                if let Some(v) = input.get(key).and_then(|s| s.as_str()) {
                    let label = match key {
                        "to_phase" => format!("→ **{v}**"),
                        _ => format!("`{key}={v}`"),
                    };
                    parts.push(label);
                }
            }
            parts.join(", ")
        }
        _ => String::new(),
    }
}

/// Compact ISO-8601-ish "YYYY-MM-DD HH:MM:SS" timestamp in UTC.
/// std-only so we don't pull in `chrono` or `time` just for this.
fn iso_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Convert unix seconds to YYYY-MM-DD HH:MM:SS UTC via a tiny
    // calendar walk.
    let (y, mo, d, h, m, s) = unix_to_ymdhms(secs as i64);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

fn unix_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let mut t = secs.max(0);
    let s = (t % 60) as u32;
    t /= 60;
    let m = (t % 60) as u32;
    t /= 60;
    let h = (t % 24) as u32;
    let mut days = (t / 24) as i64;

    // Days since 1970-01-01.
    let mut y = 1970i32;
    loop {
        let leap = is_leap(y);
        let year_days = if leap { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        y += 1;
    }
    let months = [31, if is_leap(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 0usize;
    while mo < 12 && days >= months[mo] {
        days -= months[mo];
        mo += 1;
    }
    (y, (mo as u32) + 1, (days as u32) + 1, h, m, s)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Inspect a stream-json `result` event for the kinds of failures
/// that warrant an auto-resume. Returns `Some(reason)` describing
/// the failure when one is detected (and the caller should resume),
/// `None` otherwise.
///
/// The `result` event's `subtype` distinguishes:
///   - `success`           → no resume needed
///   - `error_max_turns`   → resume with the seed unchanged
///   - `error_during_execution` → resume (API error, network, …)
///   - any other non-success → resume
///
/// `is_error: true` at top level is also treated as a resume signal.
pub(crate) fn detect_api_error(event: &serde_json::Value) -> Option<String> {
    if event.get("type").and_then(|t| t.as_str()) != Some("result") {
        return None;
    }
    let subtype = event
        .get("subtype")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let is_error = event
        .get("is_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if subtype == "success" && !is_error {
        return None;
    }
    Some(format!(
        "subtype={subtype}{}",
        if is_error { " is_error=true" } else { "" }
    ))
}

/// Read back the current contents of the log file so an
/// auto-resume on top of an API error can seed the new claude
/// session with everything that already happened. Capped at `cap`
/// bytes from the tail (the most recent events) so a huge log
/// doesn't blow the resume prompt budget. Returns `None` when the
/// file doesn't exist, is empty, or unreadable.
pub(crate) fn tail(path: &Path, cap: usize) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    if raw.len() <= cap {
        return Some(raw);
    }
    // Cut at a UTF-8 boundary near the tail start.
    let mut start = raw.len() - cap;
    while start < raw.len() && !raw.is_char_boundary(start) {
        start += 1;
    }
    // Find the next line break so we don't slice mid-bullet.
    let line_start = raw[start..]
        .find('\n')
        .map(|i| start + i + 1)
        .unwrap_or(start);
    let mut out = String::from("…(earlier log truncated for resume)\n\n");
    out.push_str(&raw[line_start..]);
    Some(out)
}

/// Append a "Resume attempt N" header to the log so the new run is
/// clearly demarcated from the prior failed run when an operator
/// reads back the file later.
pub(crate) fn append_resume_header(path: &Path, attempt: u32, reason: &str) -> Result<()> {
    let mut file = OpenOptions::new().append(true).open(path)?;
    writeln!(file, "\n## Resume attempt #{attempt}")?;
    writeln!(file)?;
    writeln!(file, "- **at**: `{}`", iso_now())?;
    writeln!(file, "- **reason**: `{reason}`")?;
    writeln!(file)?;
    Ok(())
}

/// Pick a log-file path for the given engagement target. Order:
///   1. If `MANTIS_LOG_FILE` env var is set, use that path.
///   2. If a target_url / target identifier is given, write to
///      `./mantishack-logs/<host>-<unix_secs>.md` (per-target,
///      multi-run accumulating).
///   3. Otherwise, write to `./logs.md` in the cwd.
pub(crate) fn pick_log_path(target_hint: Option<&str>) -> PathBuf {
    if let Ok(p) = std::env::var("MANTIS_LOG_FILE") {
        return PathBuf::from(p);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if let Some(t) = target_hint {
        let host = host_from_target(t);
        let dir = cwd.join("mantishack-logs");
        // best-effort directory create
        let _ = std::fs::create_dir_all(&dir);
        return dir.join(format!("{host}.md"));
    }
    cwd.join("logs.md")
}

fn host_from_target(t: &str) -> String {
    let after_scheme = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    let host = after_scheme
        .split(|c: char| matches!(c, '/' | '?' | '#'))
        .next()
        .unwrap_or(after_scheme);
    let cleaned: String = host
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    if cleaned.is_empty() {
        "run".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unix_to_ymdhms_known_dates() {
        // 2025-01-01 00:00:00 UTC = 1735689600
        assert_eq!(unix_to_ymdhms(1735689600), (2025, 1, 1, 0, 0, 0));
        // 2024-02-29 (leap day)
        assert_eq!(unix_to_ymdhms(1709164800), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn render_assistant_text_block() {
        let ev = json!({
            "type": "assistant",
            "message": {
                "content": [
                    { "type": "text", "text": "hello world" }
                ]
            }
        });
        let out = render_event(&ev, 1.5).unwrap();
        assert!(out.contains("assistant"));
        assert!(out.contains("> hello world"));
    }

    #[test]
    fn render_tool_use_with_inline_args() {
        let ev = json!({
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "name": "Bash",
                        "input": { "command": "ls -la" }
                    }
                ]
            }
        });
        let out = render_event(&ev, 2.0).unwrap();
        assert!(out.contains("`Bash`"));
        assert!(out.contains("`ls -la`"));
    }

    #[test]
    fn render_tool_result_ok() {
        let ev = json!({
            "type": "user",
            "message": {
                "content": [
                    { "type": "tool_result", "is_error": false,
                      "content": [{ "type": "text", "text": "done" }] }
                ]
            }
        });
        let out = render_event(&ev, 3.0).unwrap();
        assert!(out.contains("✅ ok"));
        assert!(out.contains("done"));
    }

    #[test]
    fn render_tool_result_error() {
        let ev = json!({
            "type": "user",
            "message": {
                "content": [
                    { "type": "tool_result", "is_error": true,
                      "content": [{ "type": "text", "text": "boom" }] }
                ]
            }
        });
        let out = render_event(&ev, 3.0).unwrap();
        assert!(out.contains("❌ error"));
    }

    #[test]
    fn render_result_event_has_cost_and_turns() {
        let ev = json!({
            "type": "result",
            "subtype": "success",
            "total_cost_usd": 0.842,
            "num_turns": 47
        });
        let out = render_event(&ev, 100.0).unwrap();
        assert!(out.contains("success"));
        assert!(out.contains("47"));
        assert!(out.contains("$0.8420"));
    }

    #[test]
    fn host_from_target_strips_scheme_and_path() {
        assert_eq!(host_from_target("https://app.example.com/foo"), "app.example.com");
        assert_eq!(host_from_target("api.example.com"), "api.example.com");
        assert_eq!(host_from_target("https://with:port.example/"), "with_port.example");
    }

    #[test]
    fn pick_log_path_uses_env_override() {
        std::env::set_var("MANTIS_LOG_FILE", "/tmp/explicit.md");
        let p = pick_log_path(Some("https://anything.example"));
        std::env::remove_var("MANTIS_LOG_FILE");
        assert_eq!(p, PathBuf::from("/tmp/explicit.md"));
    }

    #[test]
    fn detect_api_error_flags_error_subtypes() {
        let err = json!({
            "type": "result",
            "subtype": "error_during_execution",
            "is_error": true
        });
        assert!(detect_api_error(&err).is_some());

        let maxturns = json!({"type": "result", "subtype": "error_max_turns"});
        assert!(detect_api_error(&maxturns).is_some());

        let success = json!({"type": "result", "subtype": "success", "is_error": false});
        assert!(detect_api_error(&success).is_none());

        let not_result = json!({"type": "assistant"});
        assert!(detect_api_error(&not_result).is_none());
    }

    #[test]
    fn tail_returns_full_content_when_under_cap() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "small content\n").unwrap();
        let out = tail(tmp.path(), 1024).unwrap();
        assert_eq!(out, "small content\n");
    }

    #[test]
    fn tail_truncates_at_line_start_when_over_cap() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut body = String::new();
        for i in 0..200 {
            body.push_str(&format!("- line {i} with some padding text\n"));
        }
        std::fs::write(tmp.path(), &body).unwrap();
        let out = tail(tmp.path(), 256).unwrap();
        assert!(out.starts_with("…(earlier log truncated for resume)"));
        // tail should end with the latest lines, intact
        assert!(out.contains("line 199"));
    }

    #[test]
    fn append_resume_header_adds_block() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "# existing\n").unwrap();
        append_resume_header(tmp.path(), 2, "test reason").unwrap();
        let out = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(out.contains("## Resume attempt #2"));
        assert!(out.contains("reason"));
        assert!(out.contains("test reason"));
    }

    #[test]
    fn run_log_open_writes_header_then_appends_finalize() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("logs.md");
        let log = RunLog::open(p.clone(), "mantis hack", "example.com").unwrap();
        log.record(&json!({
            "type": "assistant",
            "message": { "content": [
                { "type": "text", "text": "ok" }
            ]}
        }));
        log.finalize("success");
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.starts_with("# Mantis run log"));
        assert!(body.contains("## mantis hack — example.com"));
        assert!(body.contains("> ok"));
        assert!(body.contains("finished"));
        assert!(body.contains("status: `success`"));
    }
}
