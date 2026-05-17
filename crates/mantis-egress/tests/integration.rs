//! Integration tests for `mantis-egress`.
//!
//! Property: no out-of-scope hostname is ever dialed by the proxy,
//! regardless of input. We assert this by running a real proxy + real
//! target server in-process and inspecting both the wire responses
//! and the persisted event log.

#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use camino::Utf8PathBuf;
use mantis_core::{EngagementId, Signer};
use mantis_egress::{EgressConfig, EgressProxy};
use mantis_event_store::{EventKind, EventStore};
use mantis_scope::{
    BudgetEnvelope, BudgetTracker, HostPattern, PortMatcher, Protocol, ScopeEvaluator,
    ScopeManifest, ScopeRules, MANIFEST_SCHEMA_VERSION,
};
use mantis_workspace::Keypair;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use ulid::Ulid;

/// Fake TCP echo server. Returns its bound address. Stays alive for
/// the test process's lifetime.
async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct TestFixture {
    _tmp: TempDir,
    proxy_addr: SocketAddr,
    event_store: Arc<EventStore>,
    engagement_id: EngagementId,
}

async fn fixture_with_include(include: ScopeRules) -> TestFixture {
    fixture_with(include, ScopeRules::default(), default_budget()).await
}

async fn fixture_with(
    include: ScopeRules,
    exclude: ScopeRules,
    budget: BudgetEnvelope,
) -> TestFixture {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = Utf8PathBuf::from_path_buf(tmp.path().join("events.rocksdb")).expect("utf8 path");
    let event_store = Arc::new(EventStore::open(&db_path).unwrap());
    let kp: Arc<dyn Signer> = Arc::new(Keypair::generate());
    let engagement_id = EngagementId(Ulid::new());

    let manifest = ScopeManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        engagement_id,
        authorized_by: mantis_core::OperatorId(Ulid::new()),
        expires_at_unix: 9_000_000_000,
        budget: budget.clone(),
        include,
        exclude,
    };
    let evaluator = ScopeEvaluator::new(&manifest);
    let budget_tracker = BudgetTracker::new(budget);

    let cfg = EgressConfig {
        engagement_id,
        evaluator,
        budget: Arc::new(budget_tracker),
        event_store: event_store.clone(),
        signer: kp,
    };
    let proxy = EgressProxy::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), cfg)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = proxy.serve().await;
    });
    // Give the listener a moment to settle.
    tokio::time::sleep(Duration::from_millis(20)).await;
    TestFixture {
        _tmp: tmp,
        proxy_addr,
        event_store,
        engagement_id,
    }
}

fn default_budget() -> BudgetEnvelope {
    BudgetEnvelope {
        max_requests: 1000,
        max_egress_bytes: 1_000_000,
        max_wall_clock_seconds: 60,
        max_requests_per_second: 0, // disable rate limit for tests
    }
}

async fn send_request(addr: SocketAddr, request: &[u8]) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(request).await.unwrap();
    s.flush().await.unwrap();
    // Read the status line + body of any HTTP response.
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap_or(0);
    let resp = buf[..n].to_vec();
    let head = String::from_utf8_lossy(&resp[..resp.len().min(256)]).to_string();
    (head, resp)
}

async fn read_decisions(store: &EventStore, eng: EngagementId) -> Vec<(bool, String)> {
    store
        .replay(eng)
        .unwrap()
        .into_iter()
        .filter_map(|e| match e.kind {
            EventKind::ScopeDecisionLogged {
                in_scope,
                target,
                reason: _,
            } => Some((in_scope, target)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn in_scope_connect_to_localhost_target_succeeds() {
    let target = spawn_echo_server().await;
    let f = fixture_with_include(ScopeRules {
        hosts: vec![HostPattern::new("127.0.0.1")],
        ports: vec![PortMatcher::single(target.port())],
        paths: vec![],
        protocols: vec![Protocol::Https],
    })
    .await;

    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        target.port(),
        target.port()
    );
    let mut s = TcpStream::connect(f.proxy_addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    s.flush().await.unwrap();

    // Read the 200 response line + headers.
    let mut buf = vec![0u8; 256];
    let n = s.read(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");

    // Now use the tunnel: send "ping", expect "ping" back from echo.
    s.write_all(b"ping").await.unwrap();
    let mut echo = vec![0u8; 4];
    s.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");

    let decisions = read_decisions(&f.event_store, f.engagement_id).await;
    assert!(decisions.iter().any(|(in_scope, _)| *in_scope));
}

#[tokio::test]
async fn out_of_scope_host_returns_403() {
    let target = spawn_echo_server().await;
    // Only allow api.example.com — but the client will CONNECT to
    // 127.0.0.1, which must be rejected.
    let f = fixture_with_include(ScopeRules {
        hosts: vec![HostPattern::new("api.example.com")],
        ports: vec![PortMatcher::single(target.port())],
        paths: vec![],
        protocols: vec![Protocol::Https],
    })
    .await;

    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        target.port(),
        target.port()
    );
    let (head, _) = send_request(f.proxy_addr, req.as_bytes()).await;
    assert!(head.starts_with("HTTP/1.1 403"), "got: {head}");

    let decisions = read_decisions(&f.event_store, f.engagement_id).await;
    assert!(decisions
        .iter()
        .any(|(in_scope, target)| { !*in_scope && target.starts_with("127.0.0.1:") }));
}

#[tokio::test]
async fn malformed_request_returns_400() {
    let f = fixture_with_include(ScopeRules {
        hosts: vec![HostPattern::new("*")],
        ports: vec![PortMatcher::range(1, 65535).unwrap()],
        paths: vec![],
        protocols: vec![Protocol::Https],
    })
    .await;
    let (head, _) = send_request(
        f.proxy_addr,
        b"GET /not-a-proxy-request HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 400"), "got: {head}");
}

#[tokio::test]
async fn budget_exhaustion_returns_429() {
    let target = spawn_echo_server().await;
    let tight_budget = BudgetEnvelope {
        max_requests: 1,
        max_egress_bytes: 1_000_000,
        max_wall_clock_seconds: 60,
        max_requests_per_second: 0,
    };
    let f = fixture_with(
        ScopeRules {
            hosts: vec![HostPattern::new("127.0.0.1")],
            ports: vec![PortMatcher::single(target.port())],
            paths: vec![],
            protocols: vec![Protocol::Https],
        },
        ScopeRules::default(),
        tight_budget,
    )
    .await;

    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        target.port(),
        target.port()
    );

    // First request consumes the budget.
    let (head1, _) = send_request(f.proxy_addr, req.as_bytes()).await;
    assert!(head1.starts_with("HTTP/1.1 200"), "first req: {head1}");

    // Second request is rejected with 429.
    let (head2, _) = send_request(f.proxy_addr, req.as_bytes()).await;
    assert!(head2.starts_with("HTTP/1.1 429"), "second req: {head2}");
}

#[tokio::test]
async fn suffix_attack_hostname_rejected() {
    // Scope allows *.example.com only. Attacker tries to tunnel to
    // evil.example.com.attacker.tld which contains "example.com" as a
    // substring. Must be rejected.
    let f = fixture_with_include(ScopeRules {
        hosts: vec![HostPattern::new("*.example.com")],
        ports: vec![PortMatcher::single(443)],
        paths: vec![],
        protocols: vec![Protocol::Https],
    })
    .await;
    let req = b"CONNECT evil.example.com.attacker.tld:443 HTTP/1.1\r\nHost: x\r\n\r\n";
    let (head, _) = send_request(f.proxy_addr, req).await;
    assert!(head.starts_with("HTTP/1.1 403"), "got: {head}");
}

#[tokio::test]
async fn http_protocol_disallowed_when_only_https_in_scope() {
    // Phase 0 only supports CONNECT (HTTPS tunneling). But the scope
    // evaluator still ought to refuse if protocols: [http] only. We
    // simulate by using a scope that allows only http, and confirm
    // even a CONNECT request gets rejected since we evaluate as https.
    let target = spawn_echo_server().await;
    let f = fixture_with_include(ScopeRules {
        hosts: vec![HostPattern::new("127.0.0.1")],
        ports: vec![PortMatcher::single(target.port())],
        paths: vec![],
        protocols: vec![Protocol::Http],
    })
    .await;
    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        target.port(),
        target.port()
    );
    let (head, _) = send_request(f.proxy_addr, req.as_bytes()).await;
    assert!(head.starts_with("HTTP/1.1 403"), "got: {head}");
}
