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

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command as StdCommand, Stdio};

use anyhow::{Context, Result};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

// ANSI escape codes. We render the header + inline status hints
// directly instead of going through ratatui — the whole point of
// this module is to BE the terminal, not paint over it.
const MINT: &str = "\x1b[38;2;130;240;180m";
const DIM: &str = "\x1b[38;2;140;140;160m";
const HIGH: &str = "\x1b[38;2;255;200;90m";
const HOT: &str = "\x1b[38;2;220;90;90m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

// 4-row mantis mascot — same shaded-block silhouette the TUI used.
// Rendered in mint at startup, left of the info column.
const MASCOT: &[&str] = &[
    "   ╲╳╱  ",
    "  ▟◣▼◢▙ ",
    " ▝▆   ▆▘",
    "    ▜▛  ",
];

const PROVIDERS: &[&str] = &["claude", "codex", "opencode", "gemini"];

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

/// Spawn `<provider> -p "<prompt>"` with stdio inherited so output
/// flows to the operator's normal terminal scrollback. Blocks until
/// the child exits; returns its exit code.
fn spawn_provider(provider: &str, user_prompt: &str) -> Result<()> {
    let full = build_full_prompt(user_prompt);
    println!("{DIM}↳ {provider} -p ...{RESET}");
    let _ = io::stdout().flush();
    let mut cmd = StdCommand::new(provider);
    match provider {
        "claude" => {
            cmd.arg("--print")
                .arg("--dangerously-skip-permissions")
                .arg(&full);
        }
        _ => {
            cmd.arg("-p").arg(&full);
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = cmd
        .status()
        .with_context(|| format!("spawn {provider}"))?;
    if !status.success() {
        println!(
            "{DIM}↳ {provider} exited with status {}{RESET}",
            status.code().map(|c| c.to_string()).unwrap_or_else(|| "?".into())
        );
    }
    Ok(())
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
