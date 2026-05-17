//! Integration tests for claim verifier.
//!
//! Same fake-HTTP-server pattern as the primitive tests. The
//! verifier re-issues the request and applies vuln-class-specific
//! checks.

#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::time::Duration;

use mantis_claim::{verify_claim, Claim, ClaimState, SurfaceSnapshot};
use mantis_primitive::{EvidenceItem, Reproducer};
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn spawn_server(response_headers: &'static [(&'static str, &'static str)]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let headers = response_headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}\r\n"))
                .collect::<String>();
            let body = "ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{headers}Content-Length: {}\r\n\r\n{body}",
                body.len()
            );
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn make_claim(addr: SocketAddr, missing_headers: &[&str]) -> Claim {
    let evidence = missing_headers
        .iter()
        .map(|h| EvidenceItem {
            kind: "missing-header".into(),
            detail: (*h).into(),
        })
        .collect();
    Claim::pending(
        "info-disclosure.missing-security-headers".into(),
        "info-disclosure".into(),
        SurfaceSnapshot {
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: addr.port(),
            path: "/".into(),
            status: 200,
        },
        evidence,
        Reproducer::from_curl_and_raw("curl ...", "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
    )
}

fn client() -> Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

#[tokio::test]
async fn verifier_verifies_when_headers_still_missing() {
    let addr = spawn_server(&[]).await;
    let claim = make_claim(
        addr,
        &[
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
        ],
    );
    let state = verify_claim(&claim, &client()).await.unwrap();
    match state {
        ClaimState::Verified { verifier_id } => {
            assert!(verifier_id.contains("missing-security-headers"));
        }
        other => panic!("expected Verified, got {other:?}"),
    }
}

#[tokio::test]
async fn verifier_rejects_when_headers_appear() {
    // Primitive claimed XFO was missing, but the verifier finds it
    // present this time around. Claim must be rejected.
    let addr = spawn_server(&[("X-Frame-Options", "DENY")]).await;
    let claim = make_claim(addr, &["x-frame-options"]);
    let state = verify_claim(&claim, &client()).await.unwrap();
    match state {
        ClaimState::Rejected { reason } => {
            assert!(reason.contains("x-frame-options"));
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn verifier_partial_present_is_still_rejected() {
    // Primitive claimed two missing. Verifier finds one now present.
    // Reject (any-present means reject).
    let addr = spawn_server(&[("Content-Security-Policy", "default-src 'self'")]).await;
    let claim = make_claim(addr, &["content-security-policy", "x-frame-options"]);
    let state = verify_claim(&claim, &client()).await.unwrap();
    assert!(matches!(state, ClaimState::Rejected { .. }));
}

#[tokio::test]
async fn verifier_retains_on_network_error() {
    // No server bound on this port — connection will be refused.
    let bad_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let claim = make_claim(bad_addr, &["x-frame-options"]);
    let state = verify_claim(&claim, &client()).await.unwrap();
    assert!(matches!(state, ClaimState::Retained { .. }));
}

#[tokio::test]
async fn verifier_errors_on_unknown_vuln_class() {
    let claim = Claim::pending(
        "made-up.primitive".into(),
        "no-such-class".into(),
        SurfaceSnapshot {
            scheme: "http".into(),
            host: "x".into(),
            port: 80,
            path: "/".into(),
            status: 200,
        },
        vec![],
        Reproducer::from_curl_and_raw("", ""),
    );
    let r = verify_claim(&claim, &client()).await;
    assert!(r.is_err());
}
