//! Criterion benchmarks measuring against PRD §11 targets.
//!
//! Each `bench_*` function records a single metric. Run with:
//!
//! ```sh
//! cargo bench -p mantis-benches
//! ```
//!
//! HTML reports land in `target/criterion/`. The benchmarks
//! deliberately use small fixture sizes so they finish under the
//! default 5s/iteration criterion budget even on slow hardware;
//! scaling factors (events per engagement, plugin invocations)
//! are constants at the top of each function so operators can dial
//! them up when running on production-class hosts.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use mantis_benches::*;
use mantis_claim::{Claim, ClaimState, SurfaceSnapshot};
use mantis_core::{EngagementId, Signer};
use mantis_event_store::{EventKind, EventStore};
use mantis_primitive::{EvidenceItem, Reproducer};
use mantis_report::{Report, ReportMetadata};
use mantis_sandbox::{ExecutionInput, SandboxBudget, SandboxRuntime, WasmtimeBackend};
use ulid::Ulid;

struct ZeroSigner;
impl Signer for ZeroSigner {
    fn sign(&self, _ctx: &str, _payload: &[u8]) -> [u8; 64] {
        [0u8; 64]
    }
    fn public_key_bytes(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

fn bench_event_store_append(c: &mut Criterion) {
    let tmp = tempfile::tempdir().unwrap();
    let path = camino::Utf8PathBuf::from_path_buf(tmp.path().to_owned()).unwrap();
    let store = EventStore::open(&path).unwrap();
    let signer = ZeroSigner;
    let engagement = EngagementId(Ulid::new());

    let mut group = c.benchmark_group("event_store");
    group.throughput(Throughput::Elements(1));
    group.bench_function("append_one_event", |b| {
        b.iter(|| {
            store
                .append(engagement, EventKind::EngagementStarted, &signer)
                .unwrap();
        });
    });
    // PRD §11: event log query latency ≤ 1s for 1B events. The
    // micro-bench above measures single-append latency; query
    // latency at 1B-event scale is an integration-level test that
    // needs a dedicated load-generation harness — outside the
    // criterion micro-bench surface.
    println!(
        "TARGET event_log_query_latency_ms ≤ {}",
        TARGET_EVENT_LOG_QUERY_MS
    );
    group.finish();
}

fn bench_sandbox_invocation(c: &mut Criterion) {
    let backend = WasmtimeBackend::new().unwrap();
    let wasm = wat::parse_str(
        r#"
        (module
          (memory (export "memory") 1)
          (func (export "run") (result i32) i32.const 0))
        "#,
    )
    .unwrap();
    let budget = SandboxBudget {
        max_wall_clock_seconds: 2,
        max_memory_bytes: 4 * 1024 * 1024,
    };
    let input = ExecutionInput {
        bytes: vec![],
        mime: None,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut group = c.benchmark_group("sandbox");
    group.bench_function("wasm_warm_invocation", |b| {
        b.to_async(&rt).iter(|| async {
            backend.execute(&wasm, &input, &budget).await.unwrap();
        });
    });
    println!(
        "TARGET plugin_invocation_us ≤ {}",
        TARGET_PLUGIN_INVOCATION_US
    );
    group.finish();
}

fn bench_report_render(c: &mut Criterion) {
    let claims: Vec<Claim> = (0..10)
        .map(|i| Claim {
            primitive_id: format!("primitive-{i}"),
            vuln_class: "info-disclosure".into(),
            surface: SurfaceSnapshot {
                scheme: "https".into(),
                host: "x.example".into(),
                port: 443,
                path: format!("/v1/r/{i}"),
                status: 200,
            },
            evidence: vec![EvidenceItem {
                kind: "marker".into(),
                detail: "x".into(),
            }],
            reproducer: Reproducer::from_curl_and_raw(
                "curl https://x.example/",
                "GET / HTTP/1.1\r\nHost: x.example\r\n\r\n",
            ),
            state: ClaimState::Verified {
                verifier_id: "v.test".into(),
            },
        })
        .collect();

    let meta = ReportMetadata {
        engagement_id: "01HBENCH".into(),
        engagement_name: "bench".into(),
        operator_name: Some("alice".into()),
        generated_at_unix: 1_700_000_000,
        workspace_fingerprint: Some("dead".into()),
    };

    let mut group = c.benchmark_group("report");
    group.bench_function("render_markdown_10_claims", |b| {
        b.iter(|| {
            let r = Report::new(meta.clone(), &claims);
            let _ = r.to_markdown();
        });
    });
    group.bench_function("render_pdf_10_claims", |b| {
        b.iter(|| {
            let r = Report::new(meta.clone(), &claims);
            let _ = r.to_pdf();
        });
    });
    group.bench_function("render_sarif_10_claims", |b| {
        b.iter(|| {
            let r = Report::new(meta.clone(), &claims);
            let _ = r.to_sarif();
        });
    });
    group.finish();
}

fn bench_cold_start_proxy(c: &mut Criterion) {
    // Proxy for "daemon cold start" — we measure the time to spin
    // a fresh WasmtimeBackend, which is the heaviest single
    // engine the daemon initializes during boot. Real cold-start
    // includes RocksDB open and gRPC server bind; both are
    // platform-IO-bound and benched separately.
    c.bench_function("wasmtime_engine_init", |b| {
        b.iter(|| {
            let _ = WasmtimeBackend::new().unwrap();
        });
    });
    println!("TARGET cold_start_ms ≤ {}", TARGET_COLD_START_MS);
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(3))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_event_store_append, bench_sandbox_invocation, bench_report_render, bench_cold_start_proxy
}
criterion_main!(benches);
