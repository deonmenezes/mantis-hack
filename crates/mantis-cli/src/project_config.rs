//! `.mantis.json` — per-project config file (claude-code / claw-code style).
//!
//! Read at the top of `mantis hack` / `mantis prompt` / `mantis goal`
//! to apply repo-local defaults. The schema is intentionally narrow
//! — anything you'd reasonably want to pin per-repo, nothing else.
//!
//! Discovery walks up from the cwd looking for `.mantis.json` (the
//! first hit wins), matching the same shape users already expect from
//! `.editorconfig`, `.prettierrc`, `.claw.json`, etc.

use anyhow::Result;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Repo-local Mantis defaults. Every field is optional; missing
/// fields fall through to the next layer of the resolution chain.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct ProjectConfig {
    /// Default Claude model. Lower priority than `--model` and
    /// `MANTIS_MODEL`; higher than the global `~/.Mantis/model`.
    #[serde(default)]
    pub model: Option<String>,
    /// Default deep-recon mode for `mantis hack`. Lower priority
    /// than `--deep` (the flag is OR-only).
    #[serde(default)]
    pub deep: Option<bool>,
    /// Default `--no-auth` for `mantis hack`.
    #[serde(default)]
    pub no_auth: Option<bool>,
    /// Default egress profile name.
    #[serde(default)]
    pub egress: Option<String>,
    /// Default daemon endpoint (override the compiled default and
    /// `MANTIS_DAEMON` env when neither is set).
    #[serde(default)]
    pub daemon: Option<String>,
}

/// Path of the `.mantis.json` we'd load — when one exists in the
/// cwd or any ancestor. Returns `None` when no config is reachable
/// (which is the common case and is not an error).
pub(crate) fn discover() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let mut dir: &Path = &cwd;
    loop {
        let candidate = dir.join(".mantis.json");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
}

/// Read and parse the closest `.mantis.json`. Errors on malformed
/// JSON so the user sees the problem immediately instead of getting
/// silent default behavior.
pub(crate) fn load() -> Result<Option<(PathBuf, ProjectConfig)>> {
    let Some(path) = discover() else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    let cfg: ProjectConfig = serde_json::from_str(&raw)
        .with_context(|| format!("parse {} as JSON", path.display()))?;
    Ok(Some((path, cfg)))
}

use anyhow::Context;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_full_config() {
        let raw = r#"{
            "model": "claude-opus-4-7",
            "deep": true,
            "no_auth": false,
            "egress": "eu-west-1",
            "daemon": "http://127.0.0.1:50451"
        }"#;
        let cfg: ProjectConfig = serde_json::from_str(raw).unwrap();
        assert_eq!(cfg.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(cfg.deep, Some(true));
        assert_eq!(cfg.no_auth, Some(false));
        assert_eq!(cfg.egress.as_deref(), Some("eu-west-1"));
    }

    #[test]
    fn parses_partial_config() {
        let cfg: ProjectConfig = serde_json::from_str(r#"{"model":"claude-haiku-4-5-20251001"}"#).unwrap();
        assert_eq!(cfg.model.as_deref(), Some("claude-haiku-4-5-20251001"));
        assert!(cfg.deep.is_none());
        assert!(cfg.egress.is_none());
    }

    #[test]
    fn rejects_unknown_keys_silently() {
        // Forward-compat: ignore unknown keys so older binaries
        // don't choke on newer config schemas.
        let cfg: ProjectConfig = serde_json::from_str(r#"{"model":"x","future_key":42}"#).unwrap();
        assert_eq!(cfg.model.as_deref(), Some("x"));
    }

    #[test]
    fn discover_walks_up_from_subdir() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".mantis.json"), r#"{"model":"x"}"#).unwrap();
        let sub = dir.path().join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&sub).unwrap();
        let found = discover();
        std::env::set_current_dir(prev).unwrap();
        assert!(found.is_some());
        assert!(found.unwrap().ends_with(".mantis.json"));
    }
}
