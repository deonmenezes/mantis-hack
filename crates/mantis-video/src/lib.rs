//! Headless-browser session video capture (PRD §5.9.4).
//!
//! PRD §5.9.4: "The system shall optionally produce a short
//! headless-browser video capture for visual exploits."
//!
//! Implementation contract — Mantis does not bundle Chromium or
//! ffmpeg. The operator installs both; this crate provides:
//!
//! 1. A capability probe ([`VideoCapture::available`]) that
//!    reports whether the necessary binaries are on `$PATH`.
//! 2. A frame-sequence -> mp4 encoder
//!    ([`VideoCapture::encode_frames`]) that shells out to ffmpeg
//!    with a deterministic command line.
//! 3. A screenshot-driver hook
//!    ([`VideoCapture::record_with_screenshotter`]) that takes a
//!    user-supplied async screenshot function, captures N frames
//!    at a configurable interval, then encodes the resulting
//!    PNGs to mp4.
//!
//! Why this shape — the headless browser (Chromium via
//! chromiumoxide / wdriver / etc.) lives outside this crate
//! because operators differ on which they want to run. The
//! interface here is intentionally pluggable: any function that
//! produces a PNG byte stream works as a screenshotter.

use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;
use tokio::process::Command;

const DEFAULT_FFMPEG: &str = "ffmpeg";
const DEFAULT_FRAMERATE: u32 = 4;

#[derive(Debug, Error)]
pub enum VideoError {
    #[error("ffmpeg binary not found at {0:?}; install ffmpeg or set MANTIS_FFMPEG")]
    FfmpegMissing(PathBuf),

    #[error("screenshotter returned no frames")]
    NoFrames,

    #[error("io: {0}")]
    Io(String),

    #[error("ffmpeg exited with {0}: {1}")]
    Ffmpeg(i32, String),
}

#[derive(Debug, Clone)]
pub struct VideoCapture {
    ffmpeg: PathBuf,
    framerate: u32,
}

impl Default for VideoCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoCapture {
    pub fn new() -> Self {
        Self {
            ffmpeg: PathBuf::from(
                std::env::var("MANTIS_FFMPEG").unwrap_or_else(|_| DEFAULT_FFMPEG.into()),
            ),
            framerate: DEFAULT_FRAMERATE,
        }
    }

    pub fn with_ffmpeg(mut self, path: impl AsRef<Path>) -> Self {
        self.ffmpeg = path.as_ref().to_path_buf();
        self
    }

    pub fn with_framerate(mut self, fps: u32) -> Self {
        self.framerate = fps.max(1);
        self
    }

    pub fn ffmpeg_path(&self) -> &Path {
        &self.ffmpeg
    }

    pub fn framerate(&self) -> u32 {
        self.framerate
    }

    /// Returns `true` if the configured ffmpeg binary is on PATH
    /// and reports a version. Callers use this to gate video
    /// capture: when false, fall back to a single screenshot per
    /// claim.
    pub async fn available(&self) -> bool {
        Command::new(&self.ffmpeg)
            .arg("-version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Encode an in-memory sequence of PNG frames to an mp4 byte
    /// stream. Frames are written to a temp directory and ffmpeg
    /// is invoked once over the directory. The temp directory is
    /// removed on success or error.
    pub async fn encode_frames(&self, frames: &[Vec<u8>]) -> Result<Vec<u8>, VideoError> {
        if frames.is_empty() {
            return Err(VideoError::NoFrames);
        }
        if !self.available().await {
            return Err(VideoError::FfmpegMissing(self.ffmpeg.clone()));
        }
        let workdir = tempfile::tempdir().map_err(|e| VideoError::Io(e.to_string()))?;
        for (idx, frame) in frames.iter().enumerate() {
            let name = format!("frame-{idx:05}.png");
            tokio::fs::write(workdir.path().join(&name), frame)
                .await
                .map_err(|e| VideoError::Io(format!("write {name}: {e}")))?;
        }
        let output_path = workdir.path().join("out.mp4");
        let status = Command::new(&self.ffmpeg)
            .args([
                "-y",
                "-framerate",
                &self.framerate.to_string(),
                "-i",
                workdir
                    .path()
                    .join("frame-%05d.png")
                    .to_string_lossy()
                    .as_ref(),
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-movflags",
                "+faststart",
                output_path.to_string_lossy().as_ref(),
            ])
            .output()
            .await
            .map_err(|e| VideoError::Io(format!("spawn ffmpeg: {e}")))?;
        if !status.status.success() {
            return Err(VideoError::Ffmpeg(
                status.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&status.stderr).into_owned(),
            ));
        }
        let bytes = tokio::fs::read(&output_path)
            .await
            .map_err(|e| VideoError::Io(format!("read mp4: {e}")))?;
        Ok(bytes)
    }

    /// Drive a user-supplied screenshotter for `frame_count` shots
    /// spaced `interval` apart, then encode the result. The
    /// screenshotter returns raw PNG bytes per call.
    pub async fn record_with_screenshotter<F, Fut>(
        &self,
        screenshotter: F,
        frame_count: usize,
        interval: Duration,
    ) -> Result<Vec<u8>, VideoError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
    {
        if frame_count == 0 {
            return Err(VideoError::NoFrames);
        }
        let mut frames = Vec::with_capacity(frame_count);
        for i in 0..frame_count {
            let frame = screenshotter()
                .await
                .map_err(|e| VideoError::Io(format!("screenshot {i}: {e}")))?;
            frames.push(frame);
            if i + 1 < frame_count {
                tokio::time::sleep(interval).await;
            }
        }
        self.encode_frames(&frames).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_ffmpeg_from_path() {
        let v = VideoCapture::new();
        assert_eq!(v.ffmpeg_path(), Path::new(DEFAULT_FFMPEG));
        assert_eq!(v.framerate(), DEFAULT_FRAMERATE);
    }

    #[test]
    fn with_ffmpeg_overrides_path() {
        let v = VideoCapture::new().with_ffmpeg("/usr/local/bin/ffmpeg");
        assert_eq!(v.ffmpeg_path(), Path::new("/usr/local/bin/ffmpeg"));
    }

    #[test]
    fn with_framerate_clamps_to_at_least_one() {
        let v = VideoCapture::new().with_framerate(0);
        assert_eq!(v.framerate(), 1);
    }

    #[tokio::test]
    async fn available_returns_false_for_missing_binary() {
        let v = VideoCapture::new().with_ffmpeg("/definitely/not/here/ffmpeg");
        assert!(!v.available().await);
    }

    #[tokio::test]
    async fn encode_frames_errors_on_missing_binary() {
        let v = VideoCapture::new().with_ffmpeg("/definitely/not/here");
        let err = v.encode_frames(&[vec![0u8; 4]]).await.unwrap_err();
        assert!(matches!(err, VideoError::FfmpegMissing(_)));
    }

    #[tokio::test]
    async fn encode_frames_errors_on_empty_input() {
        let v = VideoCapture::new();
        let err = v.encode_frames(&[]).await.unwrap_err();
        assert!(matches!(err, VideoError::NoFrames));
    }

    #[tokio::test]
    async fn record_with_screenshotter_errors_on_zero_frames() {
        let v = VideoCapture::new();
        let err = v
            .record_with_screenshotter(
                || async { Ok::<_, String>(vec![0u8; 4]) },
                0,
                Duration::from_millis(1),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, VideoError::NoFrames));
    }

    #[tokio::test]
    async fn record_with_screenshotter_collects_frames_before_encoding() {
        // ffmpeg is almost certainly not present on the CI mac
        // runner; we only assert that the screenshotter was called
        // `frame_count` times before the (expected) ffmpeg-missing
        // error.
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let count = Arc::new(AtomicUsize::new(0));
        let count_c = count.clone();
        let v = VideoCapture::new().with_ffmpeg("/never/here");
        let _ = v
            .record_with_screenshotter(
                move || {
                    let count = count_c.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, String>(vec![0u8; 4])
                    }
                },
                3,
                Duration::from_millis(0),
            )
            .await;
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}
