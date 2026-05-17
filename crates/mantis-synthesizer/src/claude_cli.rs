//! Claude CLI LLM adapter.
//!
//! Instead of calling the Anthropic REST API directly, this adapter
//! shells out to the local `claude` CLI in non-interactive (`--print`)
//! mode. That lets the Mantis synthesizer reuse whatever Claude Code
//! authentication the user already has — no `ANTHROPIC_API_KEY`
//! required.
//!
//! Env vars:
//! - `MANTIS_CLAUDE_CLI_BIN`            override the binary (default: `claude`)
//! - `MANTIS_CLAUDE_CLI_MODEL`          override the model (passed as `--model`)
//! - `MANTIS_CLAUDE_CLI_TIMEOUT_SECS`   per-request timeout (default: 60s)

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::{LlmAdapter, SynthError};

const DEFAULT_BIN: &str = "claude";
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const SYSTEM_PROMPT: &str = "You are a payload generator for an offensive-security \
    synthesizer. Reply with ONLY the requested payload as plain text. No prose, \
    no markdown fences, no commentary, no tool calls.";

pub struct ClaudeCliAdapter {
    binary: String,
    model: Option<String>,
    timeout: Duration,
}

impl ClaudeCliAdapter {
    pub fn new() -> Self {
        let timeout_secs = std::env::var("MANTIS_CLAUDE_CLI_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        Self {
            binary: std::env::var("MANTIS_CLAUDE_CLI_BIN").unwrap_or_else(|_| DEFAULT_BIN.into()),
            model: std::env::var("MANTIS_CLAUDE_CLI_MODEL").ok(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.binary = binary.into();
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Default for ClaudeCliAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LlmAdapter for ClaudeCliAdapter {
    async fn complete(&self, prompt: &str) -> Result<String, SynthError> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("--print")
            .arg("--no-session-persistence")
            .arg("--system-prompt")
            .arg(SYSTEM_PROMPT);
        if let Some(m) = &self.model {
            cmd.arg("--model").arg(m);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| SynthError::Backend(format!("spawn `{}`: {e}", self.binary)))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(prompt.as_bytes())
                .await
                .map_err(|e| SynthError::Backend(format!("write prompt to claude cli: {e}")))?;
        }

        let out = match timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => return Err(SynthError::Backend(format!("wait claude cli: {e}"))),
            Err(_) => {
                return Err(SynthError::Backend(format!(
                    "claude cli timed out after {}s",
                    self.timeout.as_secs()
                )));
            }
        };
        if !out.status.success() {
            return Err(SynthError::Backend(format!(
                "claude cli exited with status {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if stdout.is_empty() {
            return Err(SynthError::Backend(
                "claude cli returned empty stdout".into(),
            ));
        }
        Ok(stdout)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_fake_cli(script: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake-claude");
        std::fs::write(&path, script).unwrap();
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&path, perm).unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn returns_subprocess_stdout() {
        // Script ignores its args and echoes stdin to stdout.
        let (_dir, bin) = write_fake_cli("#!/bin/sh\ncat\n");
        let adapter = ClaudeCliAdapter::new().with_binary(bin.to_str().unwrap());
        let out = adapter.complete("the-payload").await.unwrap();
        assert_eq!(out, "the-payload");
    }

    #[tokio::test]
    async fn nonzero_exit_becomes_backend_error() {
        let (_dir, bin) = write_fake_cli("#!/bin/sh\necho boom >&2\nexit 7\n");
        let adapter = ClaudeCliAdapter::new().with_binary(bin.to_str().unwrap());
        let err = adapter.complete("anything").await.unwrap_err();
        match err {
            SynthError::Backend(msg) => {
                assert!(msg.contains("exited"), "msg: {msg}");
                assert!(msg.contains("boom"), "msg: {msg}");
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_binary_becomes_backend_error() {
        let adapter =
            ClaudeCliAdapter::new().with_binary("/this/does/not/exist/at/all/nope-claude");
        let err = adapter.complete("anything").await.unwrap_err();
        assert!(matches!(err, SynthError::Backend(_)));
    }

    #[tokio::test]
    async fn empty_stdout_becomes_backend_error() {
        let (_dir, bin) = write_fake_cli("#!/bin/sh\nexit 0\n");
        let adapter = ClaudeCliAdapter::new().with_binary(bin.to_str().unwrap());
        let err = adapter.complete("anything").await.unwrap_err();
        match err {
            SynthError::Backend(msg) => assert!(msg.contains("empty"), "msg: {msg}"),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn timeout_becomes_backend_error() {
        let (_dir, bin) = write_fake_cli("#!/bin/sh\nsleep 5\n");
        let adapter = ClaudeCliAdapter::new()
            .with_binary(bin.to_str().unwrap())
            .with_timeout(Duration::from_millis(200));
        let err = adapter.complete("anything").await.unwrap_err();
        match err {
            SynthError::Backend(msg) => assert!(msg.contains("timed out"), "msg: {msg}"),
            other => panic!("expected Backend, got {other:?}"),
        }
    }
}
