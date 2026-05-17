//! HTTP/1.1 server. Three routes, hand-rolled parser via
//! `httparse` so the crate stays cheap to compile.

use std::net::SocketAddr;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::state::{EventChannel, SharedState};

const INDEX_HTML: &str = include_str!("../static/index.html");

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("bind: {0}")]
    Bind(String),
    #[error("io: {0}")]
    Io(String),
}

pub struct ServeHandle {
    pub addr: SocketAddr,
    pub task: JoinHandle<()>,
}

pub async fn serve(
    addr: impl tokio::net::ToSocketAddrs,
    state: SharedState,
    events: EventChannel,
) -> Result<ServeHandle, ServerError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| ServerError::Bind(e.to_string()))?;
    let bound = listener
        .local_addr()
        .map_err(|e| ServerError::Bind(e.to_string()))?;
    let task = tokio::spawn(run_accept_loop(listener, state, events));
    Ok(ServeHandle { addr: bound, task })
}

async fn run_accept_loop(listener: TcpListener, state: SharedState, events: EventChannel) {
    while let Ok((stream, _)) = listener.accept().await {
        let state = state.clone();
        let events = events.clone();
        tokio::spawn(async move {
            let _ = handle_connection(stream, state, events).await;
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    state: SharedState,
    events: EventChannel,
) -> Result<(), ServerError> {
    let mut buf = vec![0u8; 8192];
    let mut filled = 0usize;
    loop {
        let n = stream
            .read(&mut buf[filled..])
            .await
            .map_err(|e| ServerError::Io(e.to_string()))?;
        if n == 0 {
            return Ok(());
        }
        filled += n;
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf[..filled]) {
            Ok(httparse::Status::Complete(_)) => {
                let method = req.method.unwrap_or("GET").to_string();
                let path = req.path.unwrap_or("/").to_string();
                return route(&mut stream, &method, &path, state, events).await;
            }
            Ok(httparse::Status::Partial) => {
                if filled == buf.len() {
                    buf.resize(buf.len() * 2, 0);
                }
            }
            Err(_) => {
                write_response(&mut stream, 400, "text/plain", b"bad request").await?;
                return Ok(());
            }
        }
    }
}

async fn route(
    stream: &mut TcpStream,
    method: &str,
    path: &str,
    state: SharedState,
    events: EventChannel,
) -> Result<(), ServerError> {
    if method != "GET" {
        return write_response(stream, 405, "text/plain", b"method not allowed").await;
    }
    let route_path = path.split('?').next().unwrap_or(path);
    match route_path {
        "/" | "/index.html" => {
            write_response(
                stream,
                200,
                "text/html; charset=utf-8",
                INDEX_HTML.as_bytes(),
            )
            .await
        }
        "/api/state" => {
            let snapshot = state.read().map(|s| s.clone()).unwrap_or_default();
            let body = serde_json::to_vec(&snapshot)
                .map_err(|e| ServerError::Io(format!("serialize state: {e}")))?;
            write_response(stream, 200, "application/json", &body).await
        }
        "/api/events" => stream_events(stream, events).await,
        "/healthz" => write_response(stream, 200, "text/plain", b"ok").await,
        _ => write_response(stream, 404, "text/plain", b"not found").await,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), ServerError> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Status",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| ServerError::Io(e.to_string()))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| ServerError::Io(e.to_string()))?;
    stream
        .shutdown()
        .await
        .map_err(|e| ServerError::Io(e.to_string()))?;
    Ok(())
}

async fn stream_events(stream: &mut TcpStream, events: EventChannel) -> Result<(), ServerError> {
    let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| ServerError::Io(e.to_string()))?;

    let mut rx = events.subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => {
                let line = match serde_json::to_string(&event) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let frame = format!("data: {line}\n\n");
                if stream.write_all(frame.as_bytes()).await.is_err() {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ClaimView, EngagementView, Event, WebState};
    use std::sync::Arc;
    use std::sync::RwLock;

    async fn read_full(stream: &mut TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        out
    }

    async fn fetch(addr: SocketAddr, path: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        String::from_utf8_lossy(&read_full(&mut s).await).into_owned()
    }

    fn split_response(resp: &str) -> (String, String) {
        match resp.split_once("\r\n\r\n") {
            Some((h, b)) => (h.into(), b.into()),
            None => (resp.into(), String::new()),
        }
    }

    #[tokio::test]
    async fn root_serves_html_shell() {
        let state = Arc::new(RwLock::new(WebState::default()));
        let events = EventChannel::new(8);
        let handle = serve("127.0.0.1:0", state, events).await.unwrap();
        let resp = fetch(handle.addr, "/").await;
        let (head, body) = split_response(&resp);
        assert!(head.contains("200 OK"));
        assert!(head.to_lowercase().contains("content-type: text/html"));
        assert!(body.contains("<html") || body.contains("<!DOCTYPE"));
        assert!(body.contains("Mantis"));
        handle.task.abort();
    }

    #[tokio::test]
    async fn api_state_returns_current_snapshot_as_json() {
        let state = Arc::new(RwLock::new(WebState::default()));
        state.write().unwrap().engagements.push(EngagementView {
            id: "01HA".into(),
            name: "demo".into(),
            state: "active".into(),
            events: 3,
        });
        let events = EventChannel::new(8);
        let handle = serve("127.0.0.1:0", state, events).await.unwrap();
        let resp = fetch(handle.addr, "/api/state").await;
        let (head, body) = split_response(&resp);
        assert!(head.contains("200 OK"));
        assert!(head
            .to_lowercase()
            .contains("content-type: application/json"));
        let parsed: WebState = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.engagements.len(), 1);
        assert_eq!(parsed.engagements[0].id, "01HA");
        handle.task.abort();
    }

    #[tokio::test]
    async fn api_state_updates_visible_between_requests() {
        let state = Arc::new(RwLock::new(WebState::default()));
        let events = EventChannel::new(8);
        let handle = serve("127.0.0.1:0", state.clone(), events).await.unwrap();

        let (_, body1) = split_response(&fetch(handle.addr, "/api/state").await);
        let s1: WebState = serde_json::from_str(&body1).unwrap();
        assert_eq!(s1.engagements.len(), 0);

        state.write().unwrap().claims.push(ClaimView {
            vuln_class: "sqli".into(),
            severity: "High".into(),
            status: "verified".into(),
            url: "https://x".into(),
        });
        let (_, body2) = split_response(&fetch(handle.addr, "/api/state").await);
        let s2: WebState = serde_json::from_str(&body2).unwrap();
        assert_eq!(s2.claims.len(), 1);
        assert_eq!(s2.claims[0].vuln_class, "sqli");

        handle.task.abort();
    }

    #[tokio::test]
    async fn api_events_streams_sse_frames() {
        let state = Arc::new(RwLock::new(WebState::default()));
        let events = EventChannel::new(8);
        let handle = serve("127.0.0.1:0", state, events.clone()).await.unwrap();

        let mut s = TcpStream::connect(handle.addr).await.unwrap();
        s.write_all(b"GET /api/events HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();

        // Read headers first.
        let mut header_buf = Vec::new();
        let mut byte = [0u8; 1];
        while s.read_exact(&mut byte).await.is_ok() {
            header_buf.extend_from_slice(&byte);
            if header_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&header_buf);
        assert!(head.contains("200 OK"));
        assert!(head.to_lowercase().contains("text/event-stream"));

        // Give the subscriber side a moment to register.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        events.send(Event::LogLine {
            line: "hello".into(),
        });

        let mut frame = [0u8; 256];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), s.read(&mut frame))
            .await
            .expect("event arrives within timeout")
            .unwrap();
        let text = String::from_utf8_lossy(&frame[..n]);
        assert!(text.starts_with("data: "));
        assert!(text.contains("\"type\":\"LogLine\""));
        assert!(text.contains("hello"));

        handle.task.abort();
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let state = Arc::new(RwLock::new(WebState::default()));
        let events = EventChannel::new(8);
        let handle = serve("127.0.0.1:0", state, events).await.unwrap();
        let resp = fetch(handle.addr, "/nowhere").await;
        assert!(resp.contains("404"));
        handle.task.abort();
    }

    #[tokio::test]
    async fn non_get_method_returns_405() {
        let state = Arc::new(RwLock::new(WebState::default()));
        let events = EventChannel::new(8);
        let handle = serve("127.0.0.1:0", state, events).await.unwrap();
        let mut s = TcpStream::connect(handle.addr).await.unwrap();
        s.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let resp = String::from_utf8_lossy(&read_full(&mut s).await).into_owned();
        assert!(resp.contains("405"));
        handle.task.abort();
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let state = Arc::new(RwLock::new(WebState::default()));
        let events = EventChannel::new(8);
        let handle = serve("127.0.0.1:0", state, events).await.unwrap();
        let resp = fetch(handle.addr, "/healthz").await;
        let (head, body) = split_response(&resp);
        assert!(head.contains("200 OK"));
        assert_eq!(body.trim(), "ok");
        handle.task.abort();
    }
}
