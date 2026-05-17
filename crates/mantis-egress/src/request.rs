//! Parse a single HTTP/1.1 CONNECT request from a client TCP stream.
//!
//! Only CONNECT is supported in Phase 0. Other methods are rejected at
//! the parser level so the rest of the proxy can assume tunneling
//! semantics. A future milestone adds plain HTTP forwarding.

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::error::EgressError;

const MAX_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
}

/// Read up to the end of the HTTP request headers, then parse a
/// CONNECT line. The body of CONNECT is the tunneled bytes that come
/// after — those are handled by the caller.
pub async fn read_connect_request(
    reader: &mut BufReader<&mut TcpStream>,
) -> Result<ConnectRequest, EgressError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    loop {
        if buf.len() >= MAX_REQUEST_BYTES {
            return Err(EgressError::RequestTooLarge {
                max: MAX_REQUEST_BYTES,
            });
        }
        let mut chunk = [0u8; 1024];
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Err(EgressError::PrematureClose);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    parse_connect(&buf)
}

pub fn parse_connect(bytes: &[u8]) -> Result<ConnectRequest, EgressError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    let parsed = req
        .parse(bytes)
        .map_err(|e| EgressError::Malformed(format!("parse: {e}")))?;
    if !parsed.is_complete() {
        return Err(EgressError::Malformed("incomplete headers".into()));
    }
    let method = req
        .method
        .ok_or_else(|| EgressError::Malformed("missing method".into()))?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(EgressError::Malformed(format!(
            "only CONNECT supported in Phase 0, got {method}"
        )));
    }
    let target = req
        .path
        .ok_or_else(|| EgressError::Malformed("missing request target".into()))?;
    let (host, port) = split_host_port(target)?;
    Ok(ConnectRequest { host, port })
}

fn split_host_port(target: &str) -> Result<(String, u16), EgressError> {
    // CONNECT requests look like "host:port" or "[ipv6]:port".
    if let Some(rest) = target.strip_prefix('[') {
        // IPv6 literal.
        let Some(end) = rest.find(']') else {
            return Err(EgressError::Malformed(format!(
                "unterminated IPv6 literal in {target}"
            )));
        };
        let host = &rest[..end];
        let after_bracket = &rest[end + 1..];
        let port_str = after_bracket
            .strip_prefix(':')
            .ok_or_else(|| EgressError::Malformed(format!("missing port in {target}")))?;
        let port = port_str
            .parse::<u16>()
            .map_err(|e| EgressError::Malformed(format!("port parse: {e}")))?;
        return Ok((host.to_owned(), port));
    }
    let Some((host, port_str)) = target.rsplit_once(':') else {
        return Err(EgressError::Malformed(format!(
            "expected host:port, got {target}"
        )));
    };
    if host.is_empty() {
        return Err(EgressError::Malformed("empty host".into()));
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|e| EgressError::Malformed(format!("port parse: {e}")))?;
    Ok((host.to_owned(), port))
}

/// Write the proxy's response back to the client. Returns when the
/// bytes have been flushed.
pub async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
) -> Result<(), EgressError> {
    let body =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

// Reserved for tests that exercise the line-based parser; keep the
// helper available via `pub(crate)`.
pub(crate) async fn _drain_line<R: AsyncBufReadExt + Unpin>(
    r: &mut R,
) -> Result<String, io::Error> {
    let mut line = String::new();
    r.read_line(&mut line).await?;
    Ok(line)
}

use std::io;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_connect() {
        let req = parse_connect(
            b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n",
        )
        .unwrap();
        assert_eq!(req.host, "api.example.com");
        assert_eq!(req.port, 443);
    }

    #[test]
    fn parse_connect_ipv6() {
        let req =
            parse_connect(b"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n").unwrap();
        assert_eq!(req.host, "::1");
        assert_eq!(req.port, 8443);
    }

    #[test]
    fn parse_rejects_get() {
        let r = parse_connect(b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        assert!(matches!(r, Err(EgressError::Malformed(_))));
    }

    #[test]
    fn parse_rejects_missing_port() {
        let r = parse_connect(b"CONNECT api.example.com HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        assert!(matches!(r, Err(EgressError::Malformed(_))));
    }

    #[test]
    fn parse_rejects_incomplete() {
        let r = parse_connect(b"CONNECT api.example.com:443 HTTP/1.1\r\n");
        assert!(matches!(r, Err(EgressError::Malformed(_))));
    }

    #[test]
    fn parse_rejects_bad_port() {
        let r = parse_connect(b"CONNECT api.example.com:notaport HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(matches!(r, Err(EgressError::Malformed(_))));
    }
}
