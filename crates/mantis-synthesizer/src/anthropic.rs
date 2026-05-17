//! Anthropic Messages API adapter (PRD §5.7.4, M2.2b).
//!
//! Talks to the Anthropic Messages endpoint (`/v1/messages`) and
//! returns the concatenated text of the first non-empty text block.
//! The default model is `claude-opus-4-7` (the most-capable model
//! at the time of writing); pass any other model id via
//! [`AnthropicAdapter::with_model`].

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{LlmAdapter, SynthError};

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const DEFAULT_MODEL: &str = "claude-opus-4-7";
const DEFAULT_API_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_TOKENS: u32 = 1024;

#[derive(Debug, Clone)]
pub struct AnthropicAdapter {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    api_version: String,
    max_tokens: u32,
}

impl AnthropicAdapter {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.into(),
            model: DEFAULT_MODEL.into(),
            api_version: DEFAULT_API_VERSION.into(),
            max_tokens: DEFAULT_MAX_TOKENS,
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }
}

#[async_trait]
impl LlmAdapter for AnthropicAdapter {
    async fn complete(&self, prompt: &str) -> Result<String, SynthError> {
        let body = Request {
            model: &self.model,
            max_tokens: self.max_tokens,
            messages: vec![Message {
                role: "user",
                content: prompt,
            }],
        };

        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", &self.api_version)
            .json(&body)
            .send()
            .await
            .map_err(|e| SynthError::Backend(format!("anthropic request: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| SynthError::Backend(format!("anthropic body: {e}")))?;

        if !status.is_success() {
            return Err(SynthError::Backend(format!(
                "anthropic {}: {text}",
                status.as_u16()
            )));
        }

        let parsed: Response = serde_json::from_str(&text)
            .map_err(|e| SynthError::Backend(format!("anthropic parse: {e}")))?;
        parsed
            .content
            .into_iter()
            .find_map(|block| match block {
                ContentBlock::Text { text } if !text.is_empty() => Some(text),
                _ => None,
            })
            .ok_or_else(|| SynthError::Backend("anthropic returned no text block".into()))
    }
}

#[derive(Serialize)]
struct Request<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<Message<'a>>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct Response {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(other)]
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    struct CapturedRequest {
        headers_blob: String,
        body: String,
    }

    /// Spawn a one-shot HTTP server that captures the first request
    /// and replies with `response_body` (JSON).
    async fn mock_server(
        response_body: String,
        captured: Arc<Mutex<Option<CapturedRequest>>>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let (headers_blob, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
            *captured.lock().await = Some(CapturedRequest {
                headers_blob: headers_blob.to_string(),
                body: body.to_string(),
            });

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn returns_text_from_first_text_block() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            r#"{"content":[{"type":"text","text":"hello world"}]}"#.into(),
            captured.clone(),
        )
        .await;
        let adapter = AnthropicAdapter::new("test-key").with_base_url(base);
        let result = adapter.complete("ping").await.unwrap();
        assert_eq!(result, "hello world");
    }

    #[tokio::test]
    async fn sends_required_headers_and_body() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            r#"{"content":[{"type":"text","text":"ok"}]}"#.into(),
            captured.clone(),
        )
        .await;
        let adapter = AnthropicAdapter::new("sk-test")
            .with_base_url(base)
            .with_model("claude-sonnet-4-6");
        let _ = adapter.complete("prompt-x").await.unwrap();

        let req = captured.lock().await.take().unwrap();
        assert!(req.headers_blob.contains("POST /v1/messages"));
        assert!(req
            .headers_blob
            .to_lowercase()
            .contains("x-api-key: sk-test"));
        assert!(req
            .headers_blob
            .to_lowercase()
            .contains("anthropic-version: 2023-06-01"));
        assert!(req.body.contains("\"model\":\"claude-sonnet-4-6\""));
        assert!(req.body.contains("\"content\":\"prompt-x\""));
        assert!(req.body.contains("\"role\":\"user\""));
    }

    #[tokio::test]
    async fn http_error_surfaces_as_backend_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"error":{"message":"bad key"}}"#;
            let resp = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        });

        let adapter = AnthropicAdapter::new("bad").with_base_url(format!("http://{addr}"));
        let err = adapter.complete("hi").await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("401") || msg.contains("anthropic"));
    }

    #[tokio::test]
    async fn empty_content_array_is_error() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(r#"{"content":[]}"#.into(), captured).await;
        let adapter = AnthropicAdapter::new("k").with_base_url(base);
        let err = adapter.complete("p").await.unwrap_err();
        assert!(format!("{err}").contains("no text block"));
    }

    #[test]
    fn defaults_match_published_constants() {
        let a = AnthropicAdapter::new("k");
        assert_eq!(a.base_url, DEFAULT_BASE_URL);
        assert_eq!(a.model, DEFAULT_MODEL);
        assert_eq!(a.api_version, DEFAULT_API_VERSION);
        assert_eq!(a.max_tokens, DEFAULT_MAX_TOKENS);
    }
}
