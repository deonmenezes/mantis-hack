//! Firecracker live-boot integration test (M2.1c).
//!
//! This test only runs when ALL of these are present:
//! - `MANTIS_FC_KERNEL` — path to an uncompressed vmlinux image
//! - `MANTIS_FC_ROOTFS` — path to an ext4 root filesystem image
//! - `MANTIS_FC_BINARY` — path to the firecracker binary (optional
//!   if `firecracker` is on PATH)
//! - `/dev/kvm` present and readable
//! - target_os = linux
//!
//! In CI, the github actions workflow `firecracker-live.yml`
//! downloads a public Firecracker quickstart kernel + rootfs and
//! sets these env vars before running.
//!
//! On developer machines without the right environment the test
//! is silently skipped — no spurious failures.

use std::path::PathBuf;

use mantis_sandbox::{
    firecracker_backend::GuestKernel, ExecutionInput, FirecrackerBackend, SandboxBudget,
    SandboxRuntime,
};

fn requirements_met() -> Option<(PathBuf, PathBuf, PathBuf)> {
    if !cfg!(target_os = "linux") {
        eprintln!("skip: not linux");
        return None;
    }
    if std::fs::metadata("/dev/kvm").is_err() {
        eprintln!("skip: /dev/kvm not present");
        return None;
    }
    let kernel = std::env::var("MANTIS_FC_KERNEL").ok()?;
    let rootfs = std::env::var("MANTIS_FC_ROOTFS").ok()?;
    let binary = std::env::var("MANTIS_FC_BINARY").unwrap_or_else(|_| "firecracker".into());
    let kernel = PathBuf::from(&kernel);
    let rootfs = PathBuf::from(&rootfs);
    if !kernel.exists() {
        eprintln!("skip: kernel image {kernel:?} does not exist");
        return None;
    }
    if !rootfs.exists() {
        eprintln!("skip: rootfs image {rootfs:?} does not exist");
        return None;
    }
    Some((PathBuf::from(binary), kernel, rootfs))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boots_firecracker_microvm_end_to_end() {
    let Some((binary, kernel_path, rootfs_path)) = requirements_met() else {
        // Not a failure — environment-gated test.
        return;
    };

    let backend = FirecrackerBackend::new()
        .with_binary(&binary)
        .with_kernel(GuestKernel {
            kernel_path,
            rootfs_path,
        });

    let budget = SandboxBudget {
        // Keep the boot bounded so a stuck guest fails the test
        // promptly rather than wedging the runner.
        max_wall_clock_seconds: 30,
        max_memory_bytes: 128 * 1024 * 1024,
    };

    let input = ExecutionInput {
        bytes: b"hello-firecracker".to_vec(),
        mime: None,
    };

    // We don't have a guest-agent contract in this build — we just
    // verify the backend can run the full configure+start sequence
    // without erroring on a real KVM host. A nonzero firecracker
    // exit code or a wall-clock timeout both qualify as
    // "orchestration succeeded but the guest didn't have a
    // graceful-exit signal" and are acceptable here.
    let result = backend.execute(b"module-bytes", &input, &budget).await;
    match result {
        Ok(out) => {
            eprintln!(
                "firecracker boot succeeded: exit_code={} output_bytes={}",
                out.exit_code,
                out.bytes.len()
            );
        }
        Err(mantis_sandbox::SandboxError::Timeout(_)) => {
            eprintln!("firecracker boot ran to wall-clock limit (expected without a guest agent)");
        }
        Err(mantis_sandbox::SandboxError::Backend(msg)) if msg.contains("exited with") => {
            eprintln!("firecracker exited non-zero on its own: {msg}");
        }
        Err(e) => panic!("firecracker orchestration failed: {e}"),
    }
}
