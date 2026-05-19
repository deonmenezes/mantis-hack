//! Claude-Code-style prompt TUI for `mantis` (no-args default).
//!
//! Layout (matches the Claude Code screenshot the user referenced):
//!
//! ```text
//!   ▲▼   Mantis vX.Y.Z
//!   ⟨⟩   <provider label> · <model> · ethical hacking
//!        <cwd>
//!
//!  ┌────────────────────────────────────────────────────────────────┐
//!  │ <output stream from the spawned AI CLI>                        │
//!  │                                                                │
//!  └────────────────────────────────────────────────────────────────┘
//!  ›  <input prompt, blinking cursor>
//!
//!  <provider> | <cwd-basename> | <engagement?> | <target?>           xhigh ·
//!  ▶▶ ethical hacking only (shift+tab to cycle provider) · ← agents
//! ```
//!
//! Keybinds:
//! - Enter           → submit the current prompt buffer; spawn the
//!                     selected provider's CLI in `-p` mode and stream
//!                     stdout into the output pane.
//! - Tab / Shift+Tab → cycle the active provider through installed
//!                     CLIs (claude, codex, opencode, gemini).
//! - Backspace       → delete one char from the prompt buffer.
//! - Ctrl-C / Esc    → quit.
//!
//! The prompt is wrapped with a Mantis-context system message so the
//! spawned CLI knows it's being invoked from an offensive-security
//! tool with operator-confirmed authorization.

use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;

// 4-line mantis silhouette mascot (mint-green). Tiny version of the
// detailed shaded-block mantis art — captures the four iconic
// elements in a tight ~4 rows × ~9 cols footprint:
//   row 1: two curved antennae crossing at the top (╲╳╱)
//   row 2: faceted armored head with central eye-band (▟◣▼◢▙)
//   row 3: raised "praying" forearms with body cavity (▝▆   ▆▘)
//   row 4: tapered abdomen tip (▜▛)
const MASCOT: &[&str] = &[
    "   ╲╳╱  ",
    "  ▟◣▼◢▙ ",
    " ▝▆   ▆▘",
    "    ▜▛  ",
];

const PROVIDERS: &[&str] = &["claude", "codex", "opencode", "gemini"];


/// Entry point. Initializes the terminal, runs the event loop, and
/// restores the terminal state on exit (even on panic).
pub async fn run() -> Result<()> {
    // Detect which providers are actually on PATH, so Tab only cycles
    // through installed ones.
    let providers = detected_providers();
    if providers.is_empty() {
        eprintln!(
            "mantis tui: no supported AI CLI on PATH. Install one of: \
             {} — then re-run `mantis`.",
            PROVIDERS.join(", ")
        );
        std::process::exit(1);
    }

    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).context("enter alt screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let mut app = App::new(providers);
    let result = run_app(&mut terminal, &mut app).await;

    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();

    result
}

#[derive(Debug, Clone)]
struct App {
    prompt: String,
    output_lines: Arc<Mutex<Vec<String>>>,
    providers: Vec<String>,
    active_provider_idx: usize,
    busy: bool,
    quit: bool,
    cwd_label: String,
}

impl App {
    fn new(providers: Vec<String>) -> Self {
        let cwd_label = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "?".into());
        Self {
            prompt: String::new(),
            output_lines: Arc::new(Mutex::new(welcome_lines())),
            providers,
            active_provider_idx: 0,
            busy: false,
            quit: false,
            cwd_label,
        }
    }

    fn active_provider(&self) -> &str {
        &self.providers[self.active_provider_idx]
    }

    fn cycle_provider(&mut self, forward: bool) {
        let len = self.providers.len();
        if forward {
            self.active_provider_idx = (self.active_provider_idx + 1) % len;
        } else {
            self.active_provider_idx = (self.active_provider_idx + len - 1) % len;
        }
    }
}

fn welcome_lines() -> Vec<String> {
    vec![
        String::new(),
        "  Mantis — offensive-security agent runner".into(),
        "  Type a request and press Enter.".into(),
        "  Examples:".into(),
        "    hack deonmenezes.com".into(),
        "    scan https://api.example.com for IDOR".into(),
        "    write a recon plan for app.example.com".into(),
        String::new(),
        "  Tab / Shift+Tab cycles AI providers. Ctrl-C exits.".into(),
        String::new(),
    ]
}

fn detected_providers() -> Vec<String> {
    PROVIDERS
        .iter()
        .filter(|&&name| which_bin(name).is_some())
        .map(|s| s.to_string())
        .collect()
}

fn which_bin(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let tick = Duration::from_millis(50);
    loop {
        terminal.draw(|f| draw(f, app))?;
        if app.quit {
            return Ok(());
        }
        if event::poll(tick)? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    handle_key(k, app).await;
                }
            }
        }
    }
}

async fn handle_key(k: KeyEvent, app: &mut App) {
    // Ctrl-C / Esc → quit
    if (k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c'))
        || k.code == KeyCode::Esc
    {
        app.quit = true;
        return;
    }
    // Don't accept new prompts while a previous one is still streaming.
    if app.busy {
        return;
    }
    match k.code {
        KeyCode::Enter => {
            let prompt = app.prompt.trim().to_string();
            if prompt.is_empty() {
                return;
            }
            app.prompt.clear();
            let provider = app.active_provider().to_string();
            let sink = app.output_lines.clone();
            app.busy = true;
            // Append an echo of the user's prompt to the output buffer.
            {
                let mut lines = sink.lock().await;
                lines.push(String::new());
                lines.push(format!("› {prompt}"));
                lines.push(format!("  ↳ spawning `{provider} -p ...`"));
            }
            // Spawn the provider as a child process. The tokio task
            // hooks the stdout pipe and appends each line to the
            // shared output buffer; the UI tick (50ms) picks them up.
            // `App` itself is not Send across .await for the long
            // task, so we capture by value.
            let busy_flag = Arc::clone(&sink);
            tokio::spawn(async move {
                let res = stream_provider(&provider, &prompt, &sink).await;
                let mut lines = busy_flag.lock().await;
                match res {
                    Ok(code) => {
                        lines.push(format!("  ↳ done (exit {code})"));
                    }
                    Err(e) => {
                        lines.push(format!("  ↳ error: {e}"));
                    }
                }
                lines.push(String::new());
            });
            // Mark not-busy immediately so the UI accepts the next
            // prompt; the streaming task keeps appending to the
            // output buffer independently.
            app.busy = false;
        }
        KeyCode::Tab => app.cycle_provider(true),
        KeyCode::BackTab => app.cycle_provider(false),
        KeyCode::Backspace => {
            app.prompt.pop();
        }
        KeyCode::Char(c) => app.prompt.push(c),
        _ => {}
    }
}

/// Build the system-context preamble that gets prepended to every
/// user prompt. Tells the spawned AI CLI it's being invoked from
/// Mantis, the operator has confirmed ethical use, and Mantis-side
/// MCP tools / scope enforcement are available.
fn build_full_prompt(user_prompt: &str) -> String {
    format!(
        "You are being invoked from the Mantis TUI for AUTHORIZED \
         offensive-security work. The operator has confirmed ethical \
         use (testing only systems they own or have written \
         authorization to test). When the user asks you to hack / \
         scan / recon a target, drive the engagement through the \
         `mantis` MCP server's tools and Task spawns — do not shell \
         out to `mantis hack` (you ARE the AI that mantis hack \
         invokes; calling it would recurse). For non-target requests \
         (planning, explaining concepts), just answer normally.\n\n\
         User: {user_prompt}"
    )
}

/// Spawn `<provider> -p "<prompt>"` and stream its stdout AND stderr
/// lines into the shared output buffer concurrently. Returns the
/// child's exit status code. Piping stderr matters because providers
/// often write progress / errors there, not stdout — without it the
/// TUI looked frozen forever on any error.
async fn stream_provider(
    provider: &str,
    user_prompt: &str,
    sink: &Arc<Mutex<Vec<String>>>,
) -> Result<i32> {
    let full = build_full_prompt(user_prompt);
    let mut cmd = Command::new(provider);
    match provider {
        "claude" => {
            cmd.arg("--print")
                .arg("--dangerously-skip-permissions")
                .arg(&full);
        }
        "codex" | "opencode" | "gemini" => {
            cmd.arg("-p").arg(&full);
        }
        other => {
            anyhow::bail!("unknown provider `{other}`");
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {provider}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("{provider} child has no stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("{provider} child has no stderr"))?;

    // Stream stdout and stderr concurrently. Each task appends every
    // line to the shared buffer as soon as it arrives, so the next
    // UI tick (50 ms) picks it up.
    let stdout_sink = Arc::clone(sink);
    let stderr_sink = Arc::clone(sink);
    let stdout_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            stdout_sink.lock().await.push(line);
        }
    });
    let stderr_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            stderr_sink.lock().await.push(format!("[stderr] {line}"));
        }
    });

    let status = child.wait().await?;
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    Ok(status.code().unwrap_or(0))
}

// --- Rendering (Claude-Code-style compact chrome) ----------------------
//
// Layout, top to bottom:
//   3 lines · header (mascot left, title/provider/cwd right)
//   1 line  · thin divider (─)
//   1 line  · input row (`›  <prompt>`)
//   1 line  · thin divider (─)
//   2 lines · status (provider | cwd | CLI count   ·   mode hint right-aligned)
//   rest    · output area, plain text (no border), tail-trimmed to fit
//
// The chrome is small and pinned to the top half so the eye is drawn
// to the input. Output flows beneath the chrome as plain lines, the
// way Claude Code's conversation pane does.

const MINT: Color = Color::Rgb(130, 240, 180);
const DIM: Color = Color::Rgb(140, 140, 160);
// Divider color tuned to match Claude Code's visible mid-grey
// horizontal rules — bright enough to read against a dark terminal
// background without competing with the input/output text.
const DIM_BORDER: Color = Color::Rgb(120, 130, 150);
const WHITE: Color = Color::Rgb(220, 220, 230);
const HOT: Color = Color::Rgb(220, 90, 90);
const HIGH: Color = Color::Rgb(255, 200, 90);

fn draw(f: &mut Frame<'_>, app: &App) {
    let area = f.area();
    // Claude Code v2.1.144 layout — input is FENCED between two
    // dividers, status bar sits below the second divider:
    //   header (mascot + info, 4 rows)
    //   output area, grows to fill
    //   ─── divider 1
    //   ❯ input row
    //   ─── divider 2
    //   status (2 rows, pinned bottom)
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // header
            Constraint::Min(0),    // output (fills available space)
            Constraint::Length(1), // divider 1 (above input)
            Constraint::Length(1), // input row
            Constraint::Length(1), // divider 2 (below input)
            Constraint::Length(2), // status (pinned bottom)
        ])
        .split(area);

    draw_header(f, layout[0], app);
    draw_output(f, layout[1], app);
    draw_divider(f, layout[2]);
    draw_input(f, layout[3], app);
    draw_divider(f, layout[4]);
    draw_status(f, layout[5], app);
}

fn draw_header(f: &mut Frame<'_>, area: Rect, app: &App) {
    let mint_b = Style::default().fg(MINT).add_modifier(Modifier::BOLD);
    let mint = Style::default().fg(MINT);
    let dim = Style::default().fg(DIM);

    // 4 rows total. Mascot on the left in mint green, info text on
    // the right of the first 3 rows. Row 4 is mascot tail only.
    // The {m:<N} formatter pads to a fixed column so the info
    // x-offset is stable even on rows where the mascot is shorter.
    let m0 = MASCOT.first().copied().unwrap_or("");
    let m1 = MASCOT.get(1).copied().unwrap_or("");
    let m2 = MASCOT.get(2).copied().unwrap_or("");
    let m3 = MASCOT.get(3).copied().unwrap_or("");

    let row1 = Line::from(vec![
        Span::styled(format!("{m0:<10}"), mint_b),
        Span::styled("Mantis ", mint_b),
        Span::styled(env!("CARGO_PKG_VERSION"), dim),
    ]);
    let row2 = Line::from(vec![
        Span::styled(format!("{m1:<10}"), mint_b),
        Span::styled(app.active_provider().to_string(), mint),
        Span::styled("  ·  ", dim),
        Span::styled(
            format!("{} CLI{}", app.providers.len(), if app.providers.len() == 1 { "" } else { "s" }),
            dim,
        ),
        Span::styled("  ·  ", dim),
        Span::styled("offensive-security agent runner", dim),
    ]);
    let row3 = Line::from(vec![
        Span::styled(format!("{m2:<10}"), mint),
        Span::styled(format!("~/{}", app.cwd_label), dim),
    ]);
    let row4 = Line::from(Span::styled(format!("{m3:<10}"), mint));

    let p = Paragraph::new(vec![row1, row2, row3, row4]).wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_divider(f: &mut Frame<'_>, area: Rect) {
    let line: String = "─".repeat(area.width as usize);
    let p = Paragraph::new(Line::from(Span::styled(
        line,
        Style::default().fg(DIM_BORDER),
    )));
    f.render_widget(p, area);
}

fn draw_input(f: &mut Frame<'_>, area: Rect, app: &App) {
    let cursor = if app.busy { "…" } else { "▌" };
    let body = Line::from(vec![
        // Match Claude Code's "❯" prompt char (heavy right-pointing
        // angle, U+276F) — visually distinct from the lighter "›" we
        // had before.
        Span::styled("❯ ", Style::default().fg(MINT).add_modifier(Modifier::BOLD)),
        Span::styled(app.prompt.clone(), Style::default().fg(WHITE)),
        Span::styled(
            cursor.to_string(),
            Style::default().fg(MINT).add_modifier(Modifier::SLOW_BLINK),
        ),
    ]);
    let p = Paragraph::new(body);
    f.render_widget(p, area);
}

fn draw_status(f: &mut Frame<'_>, area: Rect, app: &App) {
    let dim = Style::default().fg(DIM);
    let mint = Style::default().fg(MINT);
    let high = Style::default().fg(HIGH);
    let red = Style::default().fg(HOT);

    // Line 1 (matches Claude Code's "Opus 4.7 (1M context) | mantishack | CHAIN 4f | deonmenezes.com   xhigh ·")
    // Left: provider | cwd-label | "Mantis" mode tag
    // Right: a small accent the user expects ("xhigh ·" in the screenshot)
    let left1 = Line::from(vec![
        Span::styled(app.active_provider().to_string(), mint),
        Span::styled("  |  ", dim),
        Span::styled(app.cwd_label.clone(), dim),
        Span::styled("  |  ", dim),
        Span::styled("Mantis", Style::default().fg(MINT).add_modifier(Modifier::BOLD)),
        Span::styled(" agent runner", dim),
    ]);
    let right1 = Span::styled("● xhigh", high);

    // Line 2: yellow ⏵⏵ "ethical hacking … (shift+tab to cycle)"
    // (⏵⏵ = U+23F5 BLACK MEDIUM RIGHT-POINTING TRIANGLE — the same
    // double-play glyph Claude Code uses for its "auto mode on" hint)
    let line2 = Line::from(vec![
        Span::styled("⏵⏵ ", red),
        Span::styled(
            "ethical hacking with authorization only",
            Style::default().fg(HIGH).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "  (shift+tab to cycle providers) · ctrl-c exits",
            dim,
        ),
    ]);

    // Render line 1 in two halves to right-align the accent.
    let split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(10)])
        .split(Rect { x: area.x, y: area.y, width: area.width, height: 1 });
    f.render_widget(Paragraph::new(left1), split[0]);
    f.render_widget(
        Paragraph::new(Line::from(right1)).alignment(ratatui::layout::Alignment::Right),
        split[1],
    );

    // Render line 2 across the full status width.
    let row2 = Rect { x: area.x, y: area.y + 1, width: area.width, height: 1 };
    f.render_widget(Paragraph::new(line2), row2);
}

fn draw_output(f: &mut Frame<'_>, area: Rect, app: &App) {
    if area.height == 0 {
        return;
    }
    // Snapshot the shared buffer once per frame; try_lock so a brief
    // contention with the stream task doesn't stall the UI.
    let snapshot: Vec<String> = match app.output_lines.try_lock() {
        Ok(g) => g.clone(),
        Err(_) => return,
    };
    // Tail-trim to fit. No border — output reads as plain terminal
    // text below the chrome, the way Claude Code's conversation does.
    let inner_h = area.height as usize;
    let start = snapshot.len().saturating_sub(inner_h);
    let lines: Vec<Line<'_>> = snapshot[start..]
        .iter()
        .map(|s| Line::from(Span::styled(s.clone(), Style::default().fg(WHITE))))
        .collect();
    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(p, area);
}
