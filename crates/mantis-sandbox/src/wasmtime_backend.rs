//! wasmtime-based sandbox backend (PRD §6.4.1, M2.1b).
//!
//! Executes a guest WebAssembly module with a deny-by-default
//! capability surface: the guest has only three host imports
//! (`mantis_host::{input_len, read_input, write_output}`) and no
//! WASI, no filesystem, no network, no process. Capability-bearing
//! imports (HTTP, filesystem under preopened roots, etc.) will be
//! injected by the daemon when the plugin manifest declares them;
//! they are intentionally **not** part of this crate so that any
//! sandbox built from `WasmtimeBackend::new()` alone is the
//! minimum-capability shape PRD §6.4.1 mandates.
//!
//! CPU enforcement uses wasmtime's fuel: 1 unit ≈ 1 wasm op.
//! `max_wall_clock_seconds` is translated to fuel via
//! [`FUEL_PER_SECOND`]. Memory enforcement uses a `ResourceLimiter`
//! that rejects any growth past `max_memory_bytes`.
//!
//! Guest contract — the module must export:
//! - `memory` (linear memory)
//! - `run() -> i32` returning the exit code.
//!
//! Guest may import (all under `mantis_host`):
//! - `input_len() -> i32`
//! - `read_input(ptr: i32, len: i32) -> i32` (returns bytes copied)
//! - `write_output(ptr: i32, len: i32)` (appends to the output buffer)

use async_trait::async_trait;
use wasmtime::{
    Caller, Config, Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use crate::{ExecutionInput, ExecutionOutput, SandboxBudget, SandboxError, SandboxRuntime};

/// Each second of wall-clock budget converts to this much fuel.
/// Tuned so that the default 60s budget (≈ 60 billion ops) handles
/// real plugin workloads without being effectively unbounded.
pub const FUEL_PER_SECOND: u64 = 1_000_000_000;

struct HostState {
    input: Vec<u8>,
    output: Vec<u8>,
    limits: StoreLimits,
}

#[derive(Clone)]
pub struct WasmtimeBackend {
    engine: Engine,
}

impl std::fmt::Debug for WasmtimeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmtimeBackend").finish_non_exhaustive()
    }
}

impl WasmtimeBackend {
    /// Construct a backend with a fresh, locked-down Engine.
    pub fn new() -> Result<Self, SandboxError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        // Async-friendly: epoch interruption lets us cooperate with
        // tokio without depending on signals. We don't drive epochs
        // explicitly here — fuel is the primary CPU limiter.
        config.epoch_interruption(false);
        // Determinism: NaN canonicalization on. We leave simd
        // enabled because wasmtime requires relaxed_simd to be
        // disabled in lockstep with simd, and the relaxed-simd
        // surface is the actual source of host-CPU divergence —
        // plain simd is deterministic.
        config.cranelift_nan_canonicalization(true);
        config.wasm_relaxed_simd(false);
        let engine =
            Engine::new(&config).map_err(|e| SandboxError::Backend(format!("engine init: {e}")))?;
        Ok(Self { engine })
    }
}

impl WasmtimeBackend {
    fn run_blocking(
        &self,
        module_bytes: &[u8],
        input: &ExecutionInput,
        budget: &SandboxBudget,
    ) -> Result<ExecutionOutput, SandboxError> {
        let module = Module::from_binary(&self.engine, module_bytes)
            .map_err(|e| SandboxError::Backend(format!("compile: {e}")))?;

        let limits = StoreLimitsBuilder::new()
            .memory_size(budget.max_memory_bytes as usize)
            .build();

        let mut store = Store::new(
            &self.engine,
            HostState {
                input: input.bytes.clone(),
                output: Vec::new(),
                limits,
            },
        );
        store.limiter(|s| &mut s.limits);

        let fuel = (budget.max_wall_clock_seconds as u64).saturating_mul(FUEL_PER_SECOND);
        store
            .set_fuel(fuel.max(1))
            .map_err(|e| SandboxError::Backend(format!("set_fuel: {e}")))?;

        let mut linker: Linker<HostState> = Linker::new(&self.engine);

        linker
            .func_wrap(
                "mantis_host",
                "input_len",
                |caller: Caller<'_, HostState>| -> i32 { caller.data().input.len() as i32 },
            )
            .map_err(|e| SandboxError::Backend(format!("linker input_len: {e}")))?;

        linker
            .func_wrap(
                "mantis_host",
                "read_input",
                |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
                    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1,
                    };
                    write_guest_slice(&mut caller, memory, ptr, len, true)
                },
            )
            .map_err(|e| SandboxError::Backend(format!("linker read_input: {e}")))?;

        linker
            .func_wrap(
                "mantis_host",
                "write_output",
                |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                    let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return,
                    };
                    read_guest_slice(&mut caller, memory, ptr, len);
                },
            )
            .map_err(|e| SandboxError::Backend(format!("linker write_output: {e}")))?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(classify_linker_error)?;

        let run = instance
            .get_typed_func::<(), i32>(&mut store, "run")
            .map_err(|e| SandboxError::Backend(format!("guest must export `run() -> i32`: {e}")))?;

        let exit_code = match run.call(&mut store, ()) {
            Ok(code) => code,
            Err(trap) => {
                if let Some(out_of_fuel) = trap
                    .downcast_ref::<wasmtime::Trap>()
                    .filter(|t| matches!(t, wasmtime::Trap::OutOfFuel))
                {
                    let _ = out_of_fuel;
                    return Err(SandboxError::Timeout(std::time::Duration::from_secs(
                        budget.max_wall_clock_seconds as u64,
                    )));
                }
                if format!("{trap}").contains("memory size exceeded") {
                    return Err(SandboxError::MemoryExceeded(budget.max_memory_bytes));
                }
                return Err(SandboxError::Backend(format!("guest trap: {trap}")));
            }
        };

        let output = std::mem::take(&mut store.data_mut().output);
        Ok(ExecutionOutput {
            bytes: output,
            exit_code,
        })
    }
}

fn write_guest_slice(
    caller: &mut Caller<'_, HostState>,
    memory: Memory,
    ptr: i32,
    len: i32,
    consume_input: bool,
) -> i32 {
    if ptr < 0 || len < 0 {
        return -1;
    }
    let ptr = ptr as usize;
    let len = len as usize;
    let data = caller.data().input.clone();
    let copy_n = data.len().min(len);
    let buf = memory.data_mut(caller);
    if ptr.saturating_add(copy_n) > buf.len() {
        return -1;
    }
    buf[ptr..ptr + copy_n].copy_from_slice(&data[..copy_n]);
    if consume_input {
        // We do not advance an input cursor; reads always start at
        // byte 0. Multi-pass readers can call `input_len` and slice
        // themselves. Keeping a cursor would invite double-read
        // bugs; the host contract is intentionally simple.
    }
    copy_n as i32
}

fn read_guest_slice(caller: &mut Caller<'_, HostState>, memory: Memory, ptr: i32, len: i32) {
    if ptr < 0 || len < 0 {
        return;
    }
    let ptr = ptr as usize;
    let len = len as usize;
    let mut buf = vec![0u8; len];
    let mem = memory.data(&caller);
    if ptr.saturating_add(len) > mem.len() {
        return;
    }
    buf.copy_from_slice(&mem[ptr..ptr + len]);
    caller.data_mut().output.extend_from_slice(&buf);
}

fn classify_linker_error(e: anyhow::Error) -> SandboxError {
    let msg = format!("{e}");
    // wasmtime's missing-import message is shaped like
    // "unknown import: `wasi_snapshot_preview1::fd_write` has not
    //  been defined".
    if msg.contains("unknown import") {
        if let Some(start) = msg.find('`') {
            if let Some(end) = msg[start + 1..].find('`') {
                let import = &msg[start + 1..start + 1 + end];
                return SandboxError::CapabilityRefused(import.to_string());
            }
        }
        return SandboxError::CapabilityRefused(msg);
    }
    SandboxError::Backend(format!("instantiate: {e}"))
}

#[async_trait]
impl SandboxRuntime for WasmtimeBackend {
    fn id(&self) -> &'static str {
        "wasmtime"
    }

    async fn execute(
        &self,
        module_bytes: &[u8],
        input: &ExecutionInput,
        budget: &SandboxBudget,
    ) -> Result<ExecutionOutput, SandboxError> {
        // wasmtime's synchronous instantiate/call API is blocking;
        // running it on a dedicated blocking-thread keeps the tokio
        // runtime responsive. We clone the inputs (cheap, since
        // module bytes are typically small for tests; production
        // callers can wrap larger modules in Arc themselves).
        let backend = self.clone();
        let module_bytes = module_bytes.to_vec();
        let input = input.clone();
        let budget = *budget;
        tokio::task::spawn_blocking(move || backend.run_blocking(&module_bytes, &input, &budget))
            .await
            .map_err(|e| SandboxError::Backend(format!("spawn_blocking: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wat_to_wasm(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("WAT must compile")
    }

    fn small_budget() -> SandboxBudget {
        SandboxBudget {
            max_wall_clock_seconds: 5,
            max_memory_bytes: 16 * 1024 * 1024,
        }
    }

    #[tokio::test]
    async fn empty_run_returns_zero() {
        let wasm = wat_to_wasm(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "run") (result i32) i32.const 0))
            "#,
        );
        let backend = WasmtimeBackend::new().unwrap();
        let out = backend
            .execute(
                &wasm,
                &ExecutionInput {
                    bytes: vec![],
                    mime: None,
                },
                &small_budget(),
            )
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.bytes.is_empty());
    }

    #[tokio::test]
    async fn run_can_return_nonzero_exit() {
        let wasm = wat_to_wasm(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "run") (result i32) i32.const 42))
            "#,
        );
        let backend = WasmtimeBackend::new().unwrap();
        let out = backend
            .execute(
                &wasm,
                &ExecutionInput {
                    bytes: vec![],
                    mime: None,
                },
                &small_budget(),
            )
            .await
            .unwrap();
        assert_eq!(out.exit_code, 42);
    }

    #[tokio::test]
    async fn echo_module_round_trips_input_to_output() {
        // Guest reads input into memory[0..], writes the same bytes
        // back through write_output. input_len is queried first.
        let wasm = wat_to_wasm(
            r#"
            (module
              (import "mantis_host" "input_len" (func $input_len (result i32)))
              (import "mantis_host" "read_input" (func $read_input (param i32 i32) (result i32)))
              (import "mantis_host" "write_output" (func $write_output (param i32 i32)))
              (memory (export "memory") 1)
              (func (export "run") (result i32)
                (local $n i32)
                (local.set $n (call $input_len))
                (drop (call $read_input (i32.const 0) (local.get $n)))
                (call $write_output (i32.const 0) (local.get $n))
                i32.const 0))
            "#,
        );
        let backend = WasmtimeBackend::new().unwrap();
        let out = backend
            .execute(
                &wasm,
                &ExecutionInput {
                    bytes: b"hello mantis".to_vec(),
                    mime: None,
                },
                &small_budget(),
            )
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.bytes, b"hello mantis");
    }

    #[tokio::test]
    async fn invalid_wasm_bytes_surface_as_backend_error() {
        let backend = WasmtimeBackend::new().unwrap();
        let err = backend
            .execute(
                b"not wasm at all",
                &ExecutionInput {
                    bytes: vec![],
                    mime: None,
                },
                &small_budget(),
            )
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("compile") || msg.contains("backend"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn missing_run_export_is_backend_error() {
        let wasm = wat_to_wasm(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "not_run") (result i32) i32.const 0))
            "#,
        );
        let backend = WasmtimeBackend::new().unwrap();
        let err = backend
            .execute(
                &wasm,
                &ExecutionInput {
                    bytes: vec![],
                    mime: None,
                },
                &small_budget(),
            )
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("run") || msg.contains("backend"));
    }

    #[tokio::test]
    async fn non_declared_import_yields_capability_refused() {
        // Guest tries to import a WASI fn that the deny-by-default
        // backend never provides. Linker should reject with a
        // CapabilityRefused error.
        let wasm = wat_to_wasm(
            r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write"
                (func $fd_write (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "run") (result i32) i32.const 0))
            "#,
        );
        let backend = WasmtimeBackend::new().unwrap();
        let err = backend
            .execute(
                &wasm,
                &ExecutionInput {
                    bytes: vec![],
                    mime: None,
                },
                &small_budget(),
            )
            .await
            .unwrap_err();
        match err {
            SandboxError::CapabilityRefused(cap) => {
                assert!(
                    cap.contains("fd_write") || cap.contains("wasi"),
                    "expected capability mention, got: {cap}"
                );
            }
            other => panic!("expected CapabilityRefused, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn infinite_loop_is_terminated_by_fuel() {
        let wasm = wat_to_wasm(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "run") (result i32)
                (loop (br 0))
                i32.const 0))
            "#,
        );
        let backend = WasmtimeBackend::new().unwrap();
        // Very small budget — single second translates to 1B ops,
        // which the loop will burn through almost instantly.
        let budget = SandboxBudget {
            max_wall_clock_seconds: 1,
            max_memory_bytes: 1024 * 1024,
        };
        let err = backend
            .execute(
                &wasm,
                &ExecutionInput {
                    bytes: vec![],
                    mime: None,
                },
                &budget,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::Timeout(_)),
            "expected Timeout from fuel exhaustion, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn divide_by_zero_trap_surfaces_as_backend_error() {
        let wasm = wat_to_wasm(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "run") (result i32)
                (i32.div_s (i32.const 1) (i32.const 0))))
            "#,
        );
        let backend = WasmtimeBackend::new().unwrap();
        let err = backend
            .execute(
                &wasm,
                &ExecutionInput {
                    bytes: vec![],
                    mime: None,
                },
                &small_budget(),
            )
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("trap") || msg.contains("divide") || msg.contains("backend"));
    }

    #[tokio::test]
    async fn backend_id_is_wasmtime() {
        let backend = WasmtimeBackend::new().unwrap();
        assert_eq!(backend.id(), "wasmtime");
    }
}
