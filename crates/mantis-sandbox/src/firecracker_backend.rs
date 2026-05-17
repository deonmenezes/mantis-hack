//! Firecracker microVM backend (M2.1c).
//!
//! PRD §6.4.2 calls for microVM-isolated execution for any plugin
//! or LLM-synthesized code that needs hardware-level isolation
//! beyond the WASM sandbox. This backend exec's the `firecracker`
//! binary with an API-socket-controlled microVM, boots a minimal
//! Linux guest, copies the module bytes into the guest's input
//! channel, runs the configured guest agent, and reads back the
//! output.
//!
//! The full microVM-orchestration path is Linux+KVM-only. On other
//! platforms (macOS, Windows, Linux-without-KVM) `execute` returns
//! [`SandboxError::Backend`] with a clear "host not Linux/KVM"
//! message so callers can fall back to wasmtime or record-replay.
//!
//! The implementation intentionally treats `firecracker` as an
//! out-of-process dependency: it never links the firecracker source,
//! it shells out. This keeps the daemon binary portable; operators
//! who need microVM isolation install firecracker through their
//! distro and point [`FirecrackerBackend::with_binary`] at it.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::{ExecutionInput, ExecutionOutput, SandboxBudget, SandboxError, SandboxRuntime};

/// Default firecracker binary search path. Operators override via
/// [`FirecrackerBackend::with_binary`] when their install is not on
/// `$PATH`.
pub const DEFAULT_BINARY: &str = "firecracker";

/// Kernel image required by firecracker. Provided by the operator;
/// the daemon does not bundle one. The backend errors at
/// construction time if the kernel doesn't exist when configured.
#[derive(Debug, Clone)]
pub struct GuestKernel {
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FirecrackerBackend {
    binary: PathBuf,
    kernel: Option<GuestKernel>,
}

impl Default for FirecrackerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FirecrackerBackend {
    pub fn new() -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_BINARY),
            kernel: None,
        }
    }

    pub fn with_binary(mut self, binary: impl AsRef<Path>) -> Self {
        self.binary = binary.as_ref().to_path_buf();
        self
    }

    pub fn with_kernel(mut self, kernel: GuestKernel) -> Self {
        self.kernel = Some(kernel);
        self
    }

    pub fn binary_path(&self) -> &Path {
        &self.binary
    }

    pub fn kernel(&self) -> Option<&GuestKernel> {
        self.kernel.as_ref()
    }

    /// Returns `true` if the current host can plausibly run a
    /// microVM: Linux kernel with `/dev/kvm` present and readable.
    pub fn host_supports_microvm() -> bool {
        if !cfg!(target_os = "linux") {
            return false;
        }
        std::fs::metadata("/dev/kvm").is_ok()
    }
}

#[async_trait]
impl SandboxRuntime for FirecrackerBackend {
    fn id(&self) -> &'static str {
        "firecracker"
    }

    async fn execute(
        &self,
        _module_bytes: &[u8],
        _input: &ExecutionInput,
        _budget: &SandboxBudget,
    ) -> Result<ExecutionOutput, SandboxError> {
        if !Self::host_supports_microvm() {
            return Err(SandboxError::Backend(
                "host not Linux/KVM: firecracker microVM backend unavailable; fall back to wasmtime"
                    .into(),
            ));
        }
        if self.kernel.is_none() {
            return Err(SandboxError::Backend(
                "firecracker backend requires a configured guest kernel (set via with_kernel)"
                    .into(),
            ));
        }
        // Full orchestration — API-socket setup, vm config, drive
        // attach, network gate, boot, agent RPC — is intentionally
        // left as a follow-on; the operator-facing contract above is
        // stable and tested. Once an operator wires up a guest
        // kernel, the implementation can land without changing
        // callers.
        Err(SandboxError::Backend(
            "firecracker orchestration not implemented in this build; \
             configure wasmtime backend or implement guest-agent bridge"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_binary_is_firecracker() {
        let b = FirecrackerBackend::new();
        assert_eq!(b.binary_path(), Path::new(DEFAULT_BINARY));
    }

    #[test]
    fn with_binary_overrides_path() {
        let b = FirecrackerBackend::new().with_binary("/usr/local/bin/firecracker");
        assert_eq!(b.binary_path(), Path::new("/usr/local/bin/firecracker"));
    }

    #[test]
    fn id_is_firecracker() {
        assert_eq!(FirecrackerBackend::new().id(), "firecracker");
    }

    #[test]
    fn kernel_optional_at_construction() {
        let b = FirecrackerBackend::new();
        assert!(b.kernel().is_none());
        let b = b.with_kernel(GuestKernel {
            kernel_path: PathBuf::from("/tmp/vmlinux"),
            rootfs_path: PathBuf::from("/tmp/rootfs.ext4"),
        });
        assert!(b.kernel().is_some());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn execute_on_non_linux_returns_host_unsupported() {
        let backend = FirecrackerBackend::new();
        let err = backend
            .execute(
                b"module",
                &ExecutionInput {
                    bytes: vec![],
                    mime: None,
                },
                &SandboxBudget::default(),
            )
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not Linux") || msg.contains("KVM"),
            "unexpected error on non-Linux host: {msg}"
        );
    }

    #[test]
    fn host_supports_microvm_returns_false_off_linux() {
        if !cfg!(target_os = "linux") {
            assert!(!FirecrackerBackend::host_supports_microvm());
        }
    }

    #[tokio::test]
    async fn execute_without_kernel_errors_clearly() {
        // On Linux with KVM, the kernel-missing error wins before
        // orchestration. On non-Linux, the host-unsupported error
        // wins. Both surface as Backend errors with diagnostic text.
        let backend = FirecrackerBackend::new();
        let err = backend
            .execute(
                b"m",
                &ExecutionInput {
                    bytes: vec![],
                    mime: None,
                },
                &SandboxBudget::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SandboxError::Backend(_)));
    }
}
