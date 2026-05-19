//! Mantis interactive REPL — Claude-Code-style **inline** rendering.
//!
//! Not a full alt-screen TUI: the mascot header prints once on
//! startup, then we drop into a rustyline read-eval-print loop.
//! Each line is fed to the active AI CLI (`claude -p ...` /
//! `codex -p ...` / etc.) with stdio inherited, so output flows to
//! the operator's normal terminal scrollback (copy-paste works,
//! terminal history works, resize works, no chrome to fight).
//!
//! Slash commands:
//!   /provider <name>  switch the active CLI (claude / codex /
//!                     opencode / gemini) — must be on PATH
//!   /providers        list installed CLIs
//!   /help             show command list
//!   /exit | /quit     exit (Ctrl-D also works)
//!
//! Ctrl-C clears the current input line (matches readline norms).
//! Ctrl-D / EOF exits.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command as StdCommand, Stdio};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use serde_json::Value;

/// PID of the currently-running provider child. Zero means idle.
/// The SIGINT handler reads this; when non-zero it forwards SIGINT
/// to the child instead of letting the signal kill the whole REPL.
static CURRENT_CHILD_PID: AtomicI32 = AtomicI32::new(0);

// ANSI escape codes. We render the header + inline status hints
// directly instead of going through ratatui — the whole point of
// this module is to BE the terminal, not paint over it.
const MINT: &str = "\x1b[38;2;130;240;180m";
const DIM: &str = "\x1b[38;2;140;140;160m";
const HIGH: &str = "\x1b[38;2;255;200;90m";
const HOT: &str = "\x1b[38;2;220;90;90m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

// 5-row praying-mantis mascot — captures the iconic mantis pose
// that actually reads as a mantis at a glance:
//   row 1: two long antennae rising and angling outward
//   row 2: triangular head with two compound eyes (◉_◉)
//   row 3: raised "praying" forearms (the most identifiable mantis
//          feature — held high in front of the body)
//   row 4: thorax
//   row 5: long thin abdomen tip
const MASCOT: &[&str] = &[
    "  \\  /  ",
    "  (◉_◉) ",
    "  /│ │\\ ",
    "   \\│/  ",
    "    │   ",
];

const PROVIDERS: &[&str] = &["claude", "codex", "opencode", "gemini"];

// Rotating verb pool for the spinner message — playful synonyms that
// fit Mantis's "stalk · wait · strike · hold" tagline. Cycled every
// ~2 seconds while a provider is running, matching the Claude Code
// rhythm ("Garnishing…" / "Thinking more" / etc.).
const VERBS: &[&str] = &[
    "Stalking",
    "Hunting",
    "Reconning",
    "Scoping",
    "Probing",
    "Striking",
    "Plotting",
    "Pondering",
    "Brewing",
    "Calculating",
    "Investigating",
    "Tracking",
    "Lurking",
    "Sniffing",
    "Pivoting",
    "Decoding",
    "Hypothesizing",
    "Cross-checking",
];

// Mantis-flavored tips shown above the spinner when a spawn starts.
// One is picked at pseudo-random per spawn — keeps the operator
// trickle-learning the tool's surface.
const TIPS: &[&str] = &[
    "/provider <name> switches between claude / codex / opencode / gemini mid-session",
    "Mantis enforces scope cryptographically at the egress proxy — the legal gate is yours",
    "hunters fan out ≥3 in parallel for every wave, even on a 1-surface target",
    "Ctrl-D exits cleanly; Ctrl-C just clears the current input line",
    "all Mantis testing requires written authorization from the target owner",
    "try `mantis hack <target> --i-have-authorization` for the full 7-phase FSM",
    "REPL history persists at ~/.Mantis/repl-history across sessions",
    "the 3-round verifier cascade catches false positives the brutalist round misses",
    "every state change becomes a BLAKE3 leaf in the per-engagement Merkle log",
    "render reports in 6 formats: markdown, pdf, hackerone, bugcrowd, sarif, openvex",
    "use `mantis goal \"find idor\"` for goal-directed multi-wave engagements",
    "the orchestrator never sends target HTTP itself — that's the hunters' job",
];

/// Entry point. Sync — readline is a blocking call and the
/// subprocess spawn uses std::process, so the whole loop runs on
/// the caller's thread. No tokio runtime required.
pub fn run() -> Result<()> {
    let providers: Vec<String> = PROVIDERS
        .iter()
        .filter(|&&n| which_bin(n).is_some())
        .map(|s| s.to_string())
        .collect();
    if providers.is_empty() {
        eprintln!(
            "mantis: no supported AI CLI on PATH. Install one of: {} — then re-run `mantis`.",
            PROVIDERS.join(", ")
        );
        std::process::exit(1);
    }

    let mut active = providers[0].clone();
    print_banner(&active, &providers);

    install_sigint_handler();

    let mut rl = DefaultEditor::new().context("init readline")?;
    let history_path = history_path();
    if let Some(p) = &history_path {
        let _ = rl.load_history(p);
    }

    loop {
        // Visually fence each input with a double horizontal line
        // (═ — U+2550) above the prompt. Width follows the terminal
        // so the rule spans the full screen; falls back to 80 if
        // the terminal size lookup fails.
        let width = terminal_width().unwrap_or(80);
        let rule: String = "═".repeat(width);
        let prompt = format!("{DIM}{rule}{RESET}\n{MINT}{BOLD}❯{RESET} ");
        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);

                if let Some(rest) = line.strip_prefix('/') {
                    if handle_slash(rest, &mut active, &providers) {
                        break;
                    }
                    continue;
                }

                if let Err(e) = spawn_provider(&active, line) {
                    eprintln!("{HOT}error:{RESET} {e}");
                }
            }
            // Ctrl-C: blank the current line, keep the REPL alive.
            Err(ReadlineError::Interrupted) => {
                println!("{DIM}(ctrl-c — press ctrl-d to exit){RESET}");
                continue;
            }
            // Ctrl-D / EOF: clean exit.
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("{HOT}readline error:{RESET} {e}");
                break;
            }
        }
    }

    if let Some(p) = &history_path {
        let _ = rl.save_history(p);
    }
    println!("{DIM}bye.{RESET}");
    Ok(())
}

fn print_banner(active: &str, providers: &[String]) {
    println!();
    let cwd_label = current_cwd_label();
    for (i, row) in MASCOT.iter().enumerate() {
        let info: String = match i {
            0 => format!(
                "{BOLD}Mantis{RESET} {DIM}{}{RESET}",
                env!("CARGO_PKG_VERSION")
            ),
            1 => format!(
                "{}{active}{RESET}  {DIM}·  {} CLI{}  ·  offensive-security agent runner{RESET}",
                MINT,
                providers.len(),
                if providers.len() == 1 { "" } else { "s" }
            ),
            2 => format!("{DIM}~/{cwd_label}{RESET}"),
            _ => String::new(),
        };
        println!("{MINT}{row}{RESET}  {info}");
    }
    println!();
    println!(
        "{DIM}Type a request and press Enter. Slash commands: /help, /provider <name>, /exit.{RESET}"
    );
    println!(
        "{HIGH}⏵⏵ ethical hacking with authorization only{RESET}  {DIM}(ctrl-d exits){RESET}"
    );
    println!();
    let _ = io::stdout().flush();
}

fn print_help() {
    println!();
    println!("{BOLD}commands{RESET}");
    println!("  {MINT}/provider <name>{RESET}   switch active AI CLI (claude / codex / opencode / gemini)");
    println!("  {MINT}/providers{RESET}         list AI CLIs detected on PATH");
    println!("  {MINT}/help{RESET}              this list");
    println!("  {MINT}/exit{RESET}              exit (ctrl-d also works)");
    println!();
}

/// Handle a slash command. Returns `true` if the REPL should exit.
fn handle_slash(cmd: &str, active: &mut String, providers: &[String]) -> bool {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    match parts.as_slice() {
        ["help"] | ["h"] => print_help(),
        ["exit"] | ["quit"] | ["q"] => return true,
        ["providers"] => {
            println!("{DIM}available:{RESET} {}", providers.join(", "));
            println!("{DIM}active:{RESET}    {MINT}{active}{RESET}");
        }
        ["provider", name] => {
            if providers.iter().any(|p| p == name) {
                *active = name.to_string();
                println!("{DIM}→ active provider: {RESET}{MINT}{active}{RESET}");
            } else {
                println!(
                    "{HOT}unknown provider{RESET} `{name}` (installed: {})",
                    providers.join(", ")
                );
            }
        }
        _ => println!("{DIM}unknown command. /help for the list{RESET}"),
    }
    false
}

/// Build the Mantis-context preamble that wraps every user prompt.
/// Tells the spawned CLI it's running under Mantis with confirmed
/// authorization, and explicitly forbids shelling out to `mantis hack`
/// (which would recurse since `mantis` may have spawned this CLI).
fn build_full_prompt(user_prompt: &str) -> String {
    format!(
        "You are being invoked from the Mantis REPL for AUTHORIZED \
         offensive-security work. The operator has confirmed ethical \
         use (testing only systems they own or have written permission \
         to test). When the user asks you to hack / scan / recon a \
         target, drive the engagement through the `mantis` MCP server's \
         tools and Task spawns — do not shell out to `mantis hack` (you \
         ARE the AI that mantis hack invokes; calling it would recurse). \
         For non-target requests (planning, explaining concepts), just \
         answer normally.\n\n\
         User: {user_prompt}"
    )
}

/// Spawn the selected AI CLI with a spinner + live event preview.
///
/// For `claude`, switch to `--output-format stream-json` so we get a
/// structured event stream — every tool call, sub-agent spawn, MCP
/// call, and assistant text block lands on its own JSON line. We
/// parse each event and pretty-print it above an indicatif spinner
/// whose message rotates through Mantis-flavored verbs ("Stalking",
/// "Hunting", …) and shows elapsed time.
///
/// Other providers (codex / opencode / gemini) don't have a common
/// structured-output mode; they use plain `-p` with stdio inherited
/// and just get the spinner shell.
fn spawn_provider(provider: &str, user_prompt: &str) -> Result<()> {
    let full = build_full_prompt(user_prompt);

    // Pre-flight: daemon up + MCP registered. Both sub-100ms when
    // already OK; fixes "no MCP configuration" mid-session when the
    // npm marker said init ran but state drifted (claude config
    // edited, daemon killed, etc).
    ensure_ready_for_spawn();

    // Pick + show a tip above the spinner.
    println!("{DIM}✦ tip: {}{RESET}", pick_tip());

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.enable_steady_tick(Duration::from_millis(80));

    let start = Instant::now();
    let last_tool: Arc<std::sync::Mutex<String>> = Arc::new(std::sync::Mutex::new(String::new()));

    // Background ticker: rotate the verb every 2 seconds, refresh
    // elapsed time every 200ms. Lives on its own thread so the
    // spinner stays animated even when the child is silent.
    let verb_idx = Arc::new(AtomicUsize::new(0));
    let pb_for_ticker = pb.clone();
    let verb_idx_for_ticker = Arc::clone(&verb_idx);
    let last_tool_for_ticker = Arc::clone(&last_tool);
    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_for_ticker = Arc::clone(&stop_flag);
    let ticker = thread::spawn(move || {
        let start = start;
        while !stop_for_ticker.load(Ordering::Relaxed) {
            let elapsed = start.elapsed().as_secs();
            // Rotate verb every 2s.
            let idx = (elapsed / 2) as usize % VERBS.len();
            verb_idx_for_ticker.store(idx, Ordering::Relaxed);
            let verb = VERBS[idx];
            let tool = last_tool_for_ticker.lock().unwrap().clone();
            let msg = if tool.is_empty() {
                format!("{HIGH}{verb}…{RESET} {DIM}({elapsed}s){RESET}")
            } else {
                format!(
                    "{HIGH}{verb}…{RESET} {DIM}({elapsed}s · {tool}){RESET}"
                )
            };
            pb_for_ticker.set_message(msg);
            thread::sleep(Duration::from_millis(200));
        }
    });

    let mut cmd = StdCommand::new(provider);
    let stream_json = provider == "claude";
    match provider {
        "claude" => {
            // `--disallowed-tools <tools...>` is variadic in claude's
            // CLI — separate arg form would consume the prompt as
            // another tool name. Use `--flag=value` so it takes
            // exactly one value and the prompt arg stays separate.
            cmd.arg("--print")
                .arg("--dangerously-skip-permissions")
                .arg("--output-format=stream-json")
                .arg("--verbose")
                .arg("--disallowed-tools=Skill")
                .arg(&full);
        }
        "codex" => {
            // codex's `-p` is `--profile` (config-profile name), NOT
            // prompt. The non-interactive prompt form is `codex exec
            // <prompt>`. Bypass-permissions equivalent.
            cmd.arg("exec")
                .arg("--dangerously-bypass-approvals-and-sandbox")
                .arg(&full);
        }
        "opencode" => {
            // OpenCode's non-interactive form is `opencode run <prompt>`.
            cmd.arg("run").arg(&full);
        }
        "gemini" => {
            // gemini-cli supports `-p <prompt>` for one-shot mode.
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
    // Publish the child PID so the SIGINT handler can route Ctrl+C
    // to it (instead of killing the whole REPL). Cleared right
    // after wait() returns.
    CURRENT_CHILD_PID.store(child.id() as i32, Ordering::Relaxed);
    let stdout = child.stdout.take().context("no stdout")?;
    let stderr = child.stderr.take().context("no stderr")?;

    // stderr → printed above the spinner with a [stderr] prefix.
    let pb_for_err = pb.clone();
    let stderr_thread = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(|r| r.ok()) {
            pb_for_err.println(format!("{DIM}[stderr] {line}{RESET}"));
        }
    });

    // stdout: parse stream-json events for claude, plain pass-through
    // for everyone else.
    let reader = BufReader::new(stdout);
    for line in reader.lines().map_while(|r| r.ok()) {
        if line.is_empty() {
            continue;
        }
        if stream_json {
            match serde_json::from_str::<Value>(&line) {
                Ok(event) => {
                    if let Some(tool) = current_tool_from_event(&event) {
                        *last_tool.lock().unwrap() = tool;
                    }
                    if let Some(pretty) = format_stream_event(&event) {
                        pb.println(pretty);
                    }
                }
                // Stream-json sometimes ends with a non-JSON banner —
                // pass it through.
                Err(_) => pb.println(line),
            }
        } else {
            pb.println(line);
        }
    }

    let _ = stderr_thread.join();
    let status = child.wait()?;
    CURRENT_CHILD_PID.store(0, Ordering::Relaxed);
    stop_flag.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    pb.finish_and_clear();

    let elapsed = start.elapsed().as_secs();
    if status.success() {
        println!(
            "{DIM}✓ {provider} done ({elapsed}s){RESET}"
        );
    } else {
        println!(
            "{HOT}✗ {provider} exited with status {} ({elapsed}s){RESET}",
            status.code().map(|c| c.to_string()).unwrap_or_else(|| "?".into())
        );
    }
    Ok(())
}

/// Pretty-print one stream-json event. Returns `None` for events we
/// don't surface (e.g. per-token partial deltas, unknown types).
fn format_stream_event(event: &Value) -> Option<String> {
    let ty = event.get("type")?.as_str()?;
    match ty {
        "system" => {
            let subtype = event.get("subtype").and_then(Value::as_str).unwrap_or("");
            Some(format!("{DIM}· session {subtype}{RESET}"))
        }
        "assistant" => {
            let content = event.pointer("/message/content")?.as_array()?;
            let mut out = Vec::new();
            for block in content {
                let bty = block.get("type")?.as_str()?;
                match bty {
                    "tool_use" => {
                        let name = block.get("name").and_then(Value::as_str).unwrap_or("?");
                        let args = summarize_tool_input(name, block.get("input"));
                        out.push(format!(
                            "  {MINT}→{RESET} {BOLD}{name}{RESET} {DIM}({args}){RESET}"
                        ));
                    }
                    "text" => {
                        let txt = block
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .trim();
                        for raw_line in txt.lines() {
                            let line = raw_line.trim_end();
                            if !line.is_empty() {
                                out.push(format!("  {line}"));
                            }
                        }
                    }
                    _ => {}
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(out.join("\n"))
            }
        }
        "user" => {
            let content = event.pointer("/message/content")?.as_array()?;
            for block in content {
                if block.get("type").and_then(Value::as_str) == Some("tool_result") {
                    let is_error = block
                        .get("is_error")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let marker = if is_error {
                        format!("{HOT}✗{RESET}")
                    } else {
                        format!("{MINT}✓{RESET}")
                    };
                    return Some(format!("    {marker} {DIM}result{RESET}"));
                }
            }
            None
        }
        "result" => {
            let subtype = event.get("subtype").and_then(Value::as_str).unwrap_or("");
            let cost = event
                .get("total_cost_usd")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let turns = event.get("num_turns").and_then(Value::as_u64).unwrap_or(0);
            Some(format!(
                "{DIM}· session {subtype} ({turns} turns, ${cost:.4}){RESET}"
            ))
        }
        _ => None,
    }
}

/// Extract a short identifier for the most recent tool the assistant
/// invoked, used as live spinner context ("Hunting… (12s · Bash)").
fn current_tool_from_event(event: &Value) -> Option<String> {
    if event.get("type")?.as_str()? != "assistant" {
        return None;
    }
    let content = event.pointer("/message/content")?.as_array()?;
    for block in content {
        if block.get("type").and_then(Value::as_str) == Some("tool_use") {
            let name = block.get("name").and_then(Value::as_str).unwrap_or("?");
            if name == "Task" {
                if let Some(sub) = block
                    .pointer("/input/subagent_type")
                    .and_then(Value::as_str)
                {
                    return Some(format!("Task→{sub}"));
                }
            }
            return Some(name.to_string());
        }
    }
    None
}

fn summarize_tool_input(name: &str, input: Option<&Value>) -> String {
    let Some(input) = input else {
        return String::new();
    };
    match name {
        "Task" => {
            let subtype = input
                .get("subagent_type")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let bg = input
                .get("run_in_background")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            format!("type={subtype}{}", if bg { ", background" } else { "" })
        }
        "Bash" => input
            .get("command")
            .and_then(Value::as_str)
            .map(|c| {
                let preview: String = c.chars().take(60).collect();
                format!("`{preview}`")
            })
            .unwrap_or_default(),
        n if n.starts_with("mcp__mantis__") => {
            let mut parts = Vec::new();
            for key in ["target_domain", "wave", "to_phase", "round", "auth_status"] {
                if let Some(v) = input.get(key).and_then(Value::as_str) {
                    let label = match key {
                        "to_phase" => format!("→{v}"),
                        _ => format!("{key}={v}"),
                    };
                    parts.push(label);
                }
            }
            parts.join(", ")
        }
        _ => input
            .as_object()
            .map(|m| format!("{} args", m.len()))
            .unwrap_or_default(),
    }
}

/// Install a SIGINT handler that forwards Ctrl+C to the running
/// child process when one is active. When no child is running the
/// signal falls through to rustyline's default behavior (blank the
/// current input line). Without this, Ctrl+C while a provider is
/// streaming would kill the whole REPL.
fn install_sigint_handler() {
    use signal_hook::consts::SIGINT;
    use signal_hook::iterator::Signals;
    let mut signals = match Signals::new([SIGINT]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{DIM}(could not install SIGINT handler: {e}){RESET}");
            return;
        }
    };
    thread::spawn(move || {
        for _ in signals.forever() {
            let pid = CURRENT_CHILD_PID.load(Ordering::Relaxed);
            if pid > 0 {
                // Forward SIGINT to the child. It usually exits;
                // its stdout pipe closes, the spawn_provider loop
                // returns, and we're back at the REPL prompt.
                // Shell out to /bin/kill instead of libc::kill so
                // we don't need an unsafe block (workspace lints
                // forbid those).
                let _ = StdCommand::new("kill")
                    .args(["-INT", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            // If pid == 0 (idle), rustyline's own SIGINT handling
            // (ReadlineError::Interrupted) takes care of clearing
            // the line.
        }
    });
}

/// Pre-spawn health check: make sure the daemon is reachable and
/// the `mantis` MCP server is registered with the `claude` CLI.
/// Both checks are <100 ms when already OK; we run them on every
/// spawn so a stale env doesn't produce the "no MCP configuration"
/// error mid-session.
fn ensure_ready_for_spawn() {
    if !daemon_is_up() {
        try_spawn_daemon();
    }
    if !mantis_mcp_registered_with_claude() {
        try_register_mantis_mcp();
    }
}

fn daemon_is_up() -> bool {
    let addr: SocketAddr = match "127.0.0.1:50451".parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

fn try_spawn_daemon() {
    let Some(daemon_bin) = which_bin("mantis-daemon") else {
        return;
    };
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let state_dir = PathBuf::from(home).join(".Mantis");
    let _ = std::fs::create_dir_all(&state_dir);
    let log_path = state_dir.join("daemon.log");
    let Ok(log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    else {
        return;
    };
    let Ok(log_err) = log.try_clone() else { return };
    let mut cmd = StdCommand::new(&daemon_bin);
    cmd.stdin(Stdio::null()).stdout(log).stderr(log_err);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    if let Ok(child) = cmd.spawn() {
        let _ = std::fs::write(state_dir.join("daemon.pid"), child.id().to_string());
        // Give it a moment to bind.
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if daemon_is_up() {
                eprintln!(
                    "{DIM}✓ started mantis-daemon (pid {}) → {}{RESET}",
                    child.id(),
                    log_path.display()
                );
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn mantis_mcp_registered_with_claude() -> bool {
    let Some(claude) = which_bin("claude") else {
        return true; // claude not installed — nothing to register
    };
    StdCommand::new(claude)
        .args(["mcp", "get", "mantis"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn try_register_mantis_mcp() {
    let Some(claude) = which_bin("claude") else {
        return;
    };
    let Some(mcp_bin) = which_bin("mantis-mcp") else {
        return;
    };
    // Best-effort cleanup of any stale registration so add succeeds.
    let _ = StdCommand::new(&claude)
        .args(["mcp", "remove", "mantis", "-s", "user"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let status = StdCommand::new(&claude)
        .args([
            "mcp",
            "add",
            "mantis",
            "-s",
            "user",
            "--",
            mcp_bin.to_string_lossy().as_ref(),
            "--daemon",
            "http://127.0.0.1:50451",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if matches!(status, Ok(s) if s.success()) {
        eprintln!("{DIM}✓ registered `mantis` MCP server with claude{RESET}");
    }
}

/// Pseudo-random tip selection — UNIX-time-modulo, no rand dep.
fn pick_tip() -> &'static str {
    use std::time::SystemTime;
    let idx = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| (d.as_nanos() as usize))
        .unwrap_or(0)
        % TIPS.len();
    TIPS[idx]
}

fn current_cwd_label() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "?".into())
}

fn history_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let dir = PathBuf::from(home).join(".Mantis");
    let _ = std::fs::create_dir_all(&dir);
    Some(dir.join("repl-history"))
}

/// Read the current terminal width in columns. Returns `None` when
/// not connected to a TTY (e.g. piped). Uses crossterm so we don't
/// add another dep — crossterm is already in this crate's Cargo.toml
/// for the alt-screen renderer.
fn terminal_width() -> Option<usize> {
    crossterm::terminal::size().ok().map(|(w, _)| w as usize)
}

fn which_bin(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
