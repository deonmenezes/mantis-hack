//! Dynamic (JS-executing) crawler that wraps headless Chromium
//! (PRD §5.3.5).
//!
//! The Mantis daemon does *not* embed Chromium directly because the
//! browser is a 100+ MB binary with platform-specific build issues.
//! Instead this crate shells out to whichever Chromium-family
//! binary the operator has on `$PATH`, dumps the post-JS-execution
//! DOM, and feeds that HTML into [`mantis_crawler`] for endpoint
//! extraction.
//!
//! Detection order: `chromium`, `chromium-browser`, `google-chrome`,
//! `chrome`, `brave-browser`, `microsoft-edge`. Set
//! `MANTIS_CHROMIUM` to override.
//!
//! When no Chromium-family binary is installed the
//! [`DynamicCrawler::fetch_rendered`] call returns
//! [`DynamicCrawlError::BrowserMissing`] and callers fall back to
//! [`mantis_crawler::extract`] over the raw HTTP response.

use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;
use tokio::process::Command;

use mantis_crawler::CrawlResult;

const DEFAULT_CANDIDATES: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "chrome",
    "brave-browser",
    "microsoft-edge",
];

const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

#[derive(Debug, Error)]
pub enum DynamicCrawlError {
    #[error("no Chromium-family browser found on PATH; set MANTIS_CHROMIUM or install chromium")]
    BrowserMissing,

    #[error("browser binary {0:?} exited with {1}: {2}")]
    BrowserFailed(PathBuf, i32, String),

    #[error("static extractor: {0}")]
    Static(#[from] mantis_crawler::CrawlError),

    #[error("io: {0}")]
    Io(String),

    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

#[derive(Debug, Clone)]
pub struct DynamicCrawler {
    binary: Option<PathBuf>,
    timeout: Duration,
}

impl Default for DynamicCrawler {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicCrawler {
    pub fn new() -> Self {
        Self {
            binary: detect_binary(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
        }
    }

    /// Explicitly set the Chromium binary path. Operators with a
    /// vendored Chromium build use this; CI environments without
    /// the binary skip dynamic crawl entirely.
    pub fn with_binary(mut self, path: impl AsRef<Path>) -> Self {
        self.binary = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn binary(&self) -> Option<&Path> {
        self.binary.as_deref()
    }

    pub fn available(&self) -> bool {
        self.binary.is_some()
    }

    /// Render `url` in headless Chromium and return the
    /// post-execution DOM as HTML.
    pub async fn fetch_rendered(&self, url: &str) -> Result<String, DynamicCrawlError> {
        let binary = self
            .binary
            .as_ref()
            .ok_or(DynamicCrawlError::BrowserMissing)?;
        let result = tokio::time::timeout(
            self.timeout,
            Command::new(binary)
                .args([
                    "--headless=new",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--virtual-time-budget=5000",
                    "--dump-dom",
                    url,
                ])
                .output(),
        )
        .await;
        let output = match result {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return Err(DynamicCrawlError::Io(format!("spawn: {e}"))),
            Err(_) => return Err(DynamicCrawlError::Timeout(self.timeout)),
        };
        if !output.status.success() {
            return Err(DynamicCrawlError::BrowserFailed(
                binary.clone(),
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Convenience: render then extract endpoints in one call.
    pub async fn crawl(&self, url: &str) -> Result<CrawlResult, DynamicCrawlError> {
        let rendered = self.fetch_rendered(url).await?;
        Ok(mantis_crawler::extract(&rendered, Some(url))?)
    }
}

fn detect_binary() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("MANTIS_CHROMIUM") {
        if !override_path.is_empty() {
            return Some(PathBuf::from(override_path));
        }
    }
    for candidate in DEFAULT_CANDIDATES {
        if which_on_path(candidate).is_some() {
            return Some(PathBuf::from(candidate));
        }
    }
    None
}

fn which_on_path(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_binary_respects_override() {
        // Use a path we know does not exist; detect_binary still
        // returns Some(path) when the env var is set, because the
        // override is taken at face value.
        std::env::set_var("MANTIS_CHROMIUM", "/explicit/path/to/chromium");
        let crawler = DynamicCrawler::new();
        assert_eq!(
            crawler.binary().map(|p| p.to_string_lossy().into_owned()),
            Some("/explicit/path/to/chromium".into())
        );
        std::env::remove_var("MANTIS_CHROMIUM");
    }

    #[test]
    fn available_reflects_binary_detection() {
        let with = DynamicCrawler::new().with_binary("/real/path");
        assert!(with.available());
        // Empty-override path: detect_binary returns None when the
        // env var is unset and no real binary is on PATH (this is
        // true on the CI macs in the workspace).
        std::env::remove_var("MANTIS_CHROMIUM");
    }

    #[tokio::test]
    async fn fetch_returns_browser_missing_when_unset() {
        let crawler = DynamicCrawler {
            binary: None,
            timeout: Duration::from_secs(5),
        };
        let err = crawler
            .fetch_rendered("https://x.example/")
            .await
            .unwrap_err();
        assert!(matches!(err, DynamicCrawlError::BrowserMissing));
    }

    #[tokio::test]
    async fn fetch_returns_io_or_browser_failed_for_bogus_binary() {
        let crawler = DynamicCrawler::new()
            .with_binary("/definitely/not/here")
            .with_timeout(Duration::from_secs(2));
        let err = crawler
            .fetch_rendered("https://x.example/")
            .await
            .unwrap_err();
        // Either Io (failed to spawn) or BrowserFailed depending on
        // OS; both are valid "Chromium isn't usable" outcomes.
        assert!(matches!(
            err,
            DynamicCrawlError::Io(_)
                | DynamicCrawlError::BrowserFailed(..)
                | DynamicCrawlError::Timeout(_)
        ));
    }

    #[tokio::test]
    async fn crawl_falls_through_to_browser_missing_when_unconfigured() {
        let crawler = DynamicCrawler {
            binary: None,
            timeout: Duration::from_secs(1),
        };
        let err = crawler.crawl("https://x.example/").await.unwrap_err();
        assert!(matches!(err, DynamicCrawlError::BrowserMissing));
    }

    #[test]
    fn with_timeout_overrides_default() {
        let c = DynamicCrawler::new().with_timeout(Duration::from_secs(5));
        assert_eq!(c.timeout, Duration::from_secs(5));
    }
}
