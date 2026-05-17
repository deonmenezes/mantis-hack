//! Integration tests for primitives.
//!
//! Spin up a fake HTTP server, point a primitive at it, assert the
//! verdict matches the test scenario.

#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::time::Duration;

use mantis_primitive::{
    CorsWildcard, MissingSecurityHeaders, OpenRedirect, Primitive, PrimitiveResult,
};
use mantis_scanner_http::{ProbeTarget, Surface};
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
            let body = "hello";
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

fn make_surface(addr: SocketAddr) -> Surface {
    Surface {
        target: ProbeTarget {
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: addr.port(),
            path: "/".into(),
        },
        status: 200,
        server: Some("nginx/1.0".into()),
        content_length: Some(5),
        tech_hints: vec!["content:html".into()],
    }
}

fn client() -> Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

#[tokio::test]
async fn confirmed_when_no_security_headers() {
    let addr = spawn_server(&[]).await;
    let surface = make_surface(addr);
    let result = MissingSecurityHeaders
        .execute(&surface, &client())
        .await
        .unwrap();
    match result {
        PrimitiveResult::Confirmed {
            evidence,
            reproducer,
        } => {
            assert_eq!(evidence.len(), 4); // all four checked are missing
            assert!(reproducer.curl.contains("strict-transport-security"));
            assert!(reproducer.raw_http.starts_with("HEAD "));
        }
        other => panic!("expected Confirmed, got {other:?}"),
    }
}

#[tokio::test]
async fn denied_when_all_headers_present() {
    let addr = spawn_server(&[
        ("Strict-Transport-Security", "max-age=63072000"),
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
    ])
    .await;
    let surface = make_surface(addr);
    let result = MissingSecurityHeaders
        .execute(&surface, &client())
        .await
        .unwrap();
    assert!(matches!(result, PrimitiveResult::Denied { .. }));
}

#[tokio::test]
async fn confirmed_partial_when_some_headers_missing() {
    let addr = spawn_server(&[
        ("Strict-Transport-Security", "max-age=63072000"),
        ("X-Frame-Options", "DENY"),
        // CSP and X-Content-Type-Options missing
    ])
    .await;
    let surface = make_surface(addr);
    let result = MissingSecurityHeaders
        .execute(&surface, &client())
        .await
        .unwrap();
    match result {
        PrimitiveResult::Confirmed { evidence, .. } => {
            assert_eq!(evidence.len(), 2);
            let kinds: Vec<&str> = evidence.iter().map(|e| e.detail.as_str()).collect();
            assert!(kinds.contains(&"content-security-policy"));
            assert!(kinds.contains(&"x-content-type-options"));
        }
        other => panic!("expected Confirmed, got {other:?}"),
    }
}

#[test]
fn matches_surface_filters_correctly() {
    let mk = |status| Surface {
        target: ProbeTarget {
            scheme: "https".into(),
            host: "x".into(),
            port: 443,
            path: "/".into(),
        },
        status,
        server: None,
        content_length: None,
        tech_hints: vec![],
    };
    assert!(MissingSecurityHeaders.matches_surface(&mk(200)));
    assert!(MissingSecurityHeaders.matches_surface(&mk(304)));
    assert!(!MissingSecurityHeaders.matches_surface(&mk(404)));
    assert!(!MissingSecurityHeaders.matches_surface(&mk(500)));
}

#[test]
fn primitive_id_and_vuln_class() {
    let p = MissingSecurityHeaders;
    assert_eq!(p.id(), "info-disclosure.missing-security-headers");
    assert_eq!(p.vuln_class(), "info-disclosure");
}

// --- open-redirect ---

async fn spawn_redirect_server(reflect_param: Option<&'static str>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let response = if let Some(param) = reflect_param {
                    // Extract param value (very rough) and Location-reflect it.
                    let needle = format!("{param}=");
                    let location = req
                        .split(&needle)
                        .nth(1)
                        .and_then(|s| s.split([' ', '&']).next())
                        .unwrap_or("/");
                    let location = url_decode(location);
                    format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned()
                };
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn url_decode(s: &str) -> String {
    // Just enough to handle test inputs.
    s.replace("%3A", ":").replace("%2F", "/")
}

fn redirect_surface(addr: SocketAddr, path: &str) -> Surface {
    Surface {
        target: ProbeTarget {
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: addr.port(),
            path: path.into(),
        },
        status: 200,
        server: None,
        content_length: None,
        tech_hints: vec![],
    }
}

#[tokio::test]
async fn open_redirect_confirmed_when_location_reflects_payload() {
    let addr = spawn_redirect_server(Some("next")).await;
    let surface = redirect_surface(addr, "/login");
    let result = OpenRedirect.execute(&surface, &client()).await.unwrap();
    match result {
        PrimitiveResult::Confirmed {
            evidence,
            reproducer,
        } => {
            assert!(evidence.iter().any(|e| e.kind == "redirect-param"));
            assert!(evidence.iter().any(|e| e.kind == "location-header"));
            assert!(reproducer.curl.contains("Location"));
        }
        other => panic!("expected Confirmed, got {other:?}"),
    }
}

#[tokio::test]
async fn open_redirect_denied_when_server_does_not_redirect() {
    let addr = spawn_redirect_server(None).await;
    let surface = redirect_surface(addr, "/login");
    let result = OpenRedirect.execute(&surface, &client()).await.unwrap();
    assert!(matches!(result, PrimitiveResult::Denied { .. }));
}

#[test]
fn open_redirect_matches_login_paths() {
    let mk = |path: &str, status: u16| Surface {
        target: ProbeTarget {
            scheme: "https".into(),
            host: "x".into(),
            port: 443,
            path: path.into(),
        },
        status,
        server: None,
        content_length: None,
        tech_hints: vec![],
    };
    assert!(OpenRedirect.matches_surface(&mk("/login", 200)));
    assert!(OpenRedirect.matches_surface(&mk("/auth/oauth", 200)));
    assert!(OpenRedirect.matches_surface(&mk("/redirect", 200)));
    assert!(OpenRedirect.matches_surface(&mk("/", 200)));
    assert!(!OpenRedirect.matches_surface(&mk("/static/css", 200)));
    assert!(!OpenRedirect.matches_surface(&mk("/login", 500)));
}

// --- cors-misconfig ---

async fn spawn_cors_server(
    response_headers: &'static [(&'static str, &'static str)],
    reflect_origin: bool,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let origin = req
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("origin:")
                            .map(|rest| rest.trim().to_owned())
                    })
                    .unwrap_or_default();
                let mut hdr = String::new();
                // Realistic apps don't reflect the literal "null" origin.
                if reflect_origin && !origin.is_empty() && origin != "null" {
                    hdr.push_str(&format!("Access-Control-Allow-Origin: {origin}\r\n"));
                }
                for (k, v) in response_headers {
                    hdr.push_str(&format!("{k}: {v}\r\n"));
                }
                let body = "{\"ok\":true}";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{hdr}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn api_surface(addr: SocketAddr) -> Surface {
    Surface {
        target: ProbeTarget {
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port: addr.port(),
            path: "/api/v1/me".into(),
        },
        status: 200,
        server: None,
        content_length: None,
        tech_hints: vec!["content:json".into()],
    }
}

#[tokio::test]
async fn cors_confirmed_reflected_origin_with_credentials() {
    let addr = spawn_cors_server(&[("Access-Control-Allow-Credentials", "true")], true).await;
    let surface = api_surface(addr);
    let result = CorsWildcard.execute(&surface, &client()).await.unwrap();
    match result {
        PrimitiveResult::Confirmed { evidence, .. } => {
            assert!(evidence.iter().any(|e| e.detail == "reflected"));
            assert!(evidence
                .iter()
                .any(|e| e.kind == "access-control-allow-credentials"));
        }
        other => panic!("expected Confirmed, got {other:?}"),
    }
}

#[tokio::test]
async fn cors_denied_without_credentials_header() {
    let addr = spawn_cors_server(&[], true).await;
    let surface = api_surface(addr);
    let result = CorsWildcard.execute(&surface, &client()).await.unwrap();
    // Reflected origin without credentials is not the dangerous case.
    assert!(matches!(result, PrimitiveResult::Denied { .. }));
}

#[tokio::test]
async fn cors_denied_when_no_cors_headers() {
    let addr = spawn_cors_server(&[], false).await;
    let surface = api_surface(addr);
    let result = CorsWildcard.execute(&surface, &client()).await.unwrap();
    assert!(matches!(result, PrimitiveResult::Denied { .. }));
}

#[test]
fn cors_matches_json_or_api_surfaces() {
    let mk = |path: &str, hints: Vec<String>| Surface {
        target: ProbeTarget {
            scheme: "https".into(),
            host: "x".into(),
            port: 443,
            path: path.into(),
        },
        status: 200,
        server: None,
        content_length: None,
        tech_hints: hints,
    };
    assert!(CorsWildcard.matches_surface(&mk("/foo", vec!["content:json".into()])));
    assert!(CorsWildcard.matches_surface(&mk("/api/v1/users", vec![])));
    assert!(!CorsWildcard.matches_surface(&mk("/static/style.css", vec![])));
}
