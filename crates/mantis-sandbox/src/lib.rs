//! Sandbox runtime (Phase 2 M2.1 + M2.1b).
//!
//! PRD §6.4.1 mandates all plugins execute in capability-typed
//! sandboxes with no host filesystem, network, or process access
//! except via declared capabilities. PRD §6.4.2 additionally
//! requires LLM-generated code to execute in ephemeral isolated
//! environments — record-replay during development and microVM
//! sandboxes for live verification.
//!
//! Backends behind the [`SandboxRuntime`] trait:
//! - [`RecordReplaySandbox`] (M2.1) — deterministic cache playback
//! - [`wasmtime_backend::WasmtimeBackend`] (M2.1b) — capability-typed
//!   WebAssembly execution with fuel-based CPU limiting and
//!   memory-growth caps
//! - microVM backend (Firecracker/QEMU) — lands in M2.1c

pub mod firecracker_backend;
pub mod wasmtime_backend;
pub use firecracker_backend::FirecrackerBackend;
pub use wasmtime_backend::WasmtimeBackend;

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("capability {0} not granted to this sandbox")]
    CapabilityRefused(String),

    #[error("execution exceeded time budget ({0:?})")]
    Timeout(std::time::Duration),

    #[error("execution exceeded memory budget ({0} bytes)")]
    MemoryExceeded(u64),

    #[error("record-replay cache miss for {0}")]
    CacheMiss(String),

    #[error("backend error: {0}")]
    Backend(String),

    #[error("internal lock poisoned")]
    Poisoned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionInput {
    pub bytes: Vec<u8>,
    pub mime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutput {
    pub bytes: Vec<u8>,
    pub exit_code: i32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SandboxBudget {
    pub max_wall_clock_seconds: u32,
    pub max_memory_bytes: u64,
}

impl Default for SandboxBudget {
    fn default() -> Self {
        Self {
            max_wall_clock_seconds: 60,
            max_memory_bytes: 128 * 1024 * 1024,
        }
    }
}

#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    fn id(&self) -> &'static str;
    async fn execute(
        &self,
        module_bytes: &[u8],
        input: &ExecutionInput,
        budget: &SandboxBudget,
    ) -> Result<ExecutionOutput, SandboxError>;
}

/// Record-replay sandbox. Records executions keyed by
/// `(module_hash, input_hash)` and serves later identical
/// invocations from the cache. Used during plugin development and
/// in CI where deterministic playback is required.
#[derive(Debug, Default)]
pub struct RecordReplaySandbox {
    cache: RwLock<HashMap<(String, String), ExecutionOutput>>,
}

impl RecordReplaySandbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seed the cache. The daemon does this on engagement
    /// hibernation/restore so a plugin's deterministic
    /// outputs survive across daemon restarts.
    pub fn record(
        &self,
        module_hash: impl Into<String>,
        input_hash: impl Into<String>,
        output: ExecutionOutput,
    ) -> Result<(), SandboxError> {
        let mut guard = self.cache.write().map_err(|_| SandboxError::Poisoned)?;
        guard.insert((module_hash.into(), input_hash.into()), output);
        Ok(())
    }

    pub fn entries(&self) -> usize {
        self.cache.read().map(|g| g.len()).unwrap_or(0)
    }
}

#[async_trait]
impl SandboxRuntime for RecordReplaySandbox {
    fn id(&self) -> &'static str {
        "record-replay"
    }

    async fn execute(
        &self,
        module_bytes: &[u8],
        input: &ExecutionInput,
        _budget: &SandboxBudget,
    ) -> Result<ExecutionOutput, SandboxError> {
        let module_hash = hash_hex(module_bytes);
        let input_hash = hash_hex(&input.bytes);
        let guard = self.cache.read().map_err(|_| SandboxError::Poisoned)?;
        guard
            .get(&(module_hash.clone(), input_hash.clone()))
            .cloned()
            .ok_or_else(|| SandboxError::CacheMiss(format!("{module_hash}:{input_hash}")))
    }
}

fn hash_hex(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// Backwards-compatible alias retained so any external code that
/// imported `WasmtimeStub` keeps compiling. New code should depend
/// on [`WasmtimeBackend`] directly.
#[deprecated(note = "WasmtimeStub was replaced by WasmtimeBackend in M2.1b")]
pub type WasmtimeStub = WasmtimeBackend;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_replay_serves_recorded_output() {
        let sandbox = RecordReplaySandbox::new();
        let module = b"module-bytes";
        let input = ExecutionInput {
            bytes: b"input-bytes".to_vec(),
            mime: None,
        };
        let module_hash = hash_hex(module);
        let input_hash = hash_hex(&input.bytes);
        let expected = ExecutionOutput {
            bytes: b"output".to_vec(),
            exit_code: 0,
        };
        sandbox
            .record(module_hash, input_hash, expected.clone())
            .unwrap();
        let got = sandbox
            .execute(module, &input, &SandboxBudget::default())
            .await
            .unwrap();
        assert_eq!(got.bytes, expected.bytes);
        assert_eq!(got.exit_code, expected.exit_code);
    }

    #[tokio::test]
    async fn record_replay_cache_miss() {
        let sandbox = RecordReplaySandbox::new();
        let err = sandbox
            .execute(
                b"m",
                &ExecutionInput {
                    bytes: b"i".to_vec(),
                    mime: None,
                },
                &SandboxBudget::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SandboxError::CacheMiss(_)));
    }

    #[tokio::test]
    async fn wasmtime_backend_constructs_with_id_set() {
        let backend = WasmtimeBackend::new().unwrap();
        assert_eq!(backend.id(), "wasmtime");
    }

    #[test]
    fn hash_hex_is_deterministic() {
        assert_eq!(hash_hex(b"hello"), hash_hex(b"hello"));
        assert_ne!(hash_hex(b"hello"), hash_hex(b"hello!"));
    }

    #[test]
    fn budget_defaults_are_reasonable() {
        let b = SandboxBudget::default();
        assert_eq!(b.max_wall_clock_seconds, 60);
        assert_eq!(b.max_memory_bytes, 128 * 1024 * 1024);
    }
}
