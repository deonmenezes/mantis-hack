//! OpenAI Chat Completions API adapter (PRD §5.7.4, M2.2b).
//!
//! Posts to `/v1/chat/completions` and returns the text of the first
//! choice's message content. Default model is `gpt-4o-mini` — the
//! caller can swap in any chat-completions-compatible model id.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::retry::{classify_status, parse_retry_after, RetryDecision, RetryPolicy};
use crate::{LlmAdapter, SynthError};

const DEFAULT_BASE_URL: &str = "https://api.openai.com";
const DEFAULT_MODEL: &str = "gpt-4o-mini";
const DEFAULT_MAX_TOKENS: u32 = 1024;

#[derive(Debug, Clone)]
pub struct OpenAIAdapter {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    retry: RetryPolicy,
}

impl OpenAIAdapter {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.into(),
            model: DEFAULT_MODEL.into(),
            max_tokens: DEFAULT_MAX_TOKENS,
            retry: RetryPolicy::default(),
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

    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }
}

#[async_trait]
impl LlmAdapter for OpenAIAdapter {
    async fn complete(&self, prompt: &str) -> Result<String, SynthError> {
        let body = Request {
            model: &self.model,
            max_tokens: self.max_tokens,
            messages: vec![Message {
                role: "user",
                content: prompt,
            }],
        };
        let url = format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        );
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| SynthError::Backend(format!("openai serialize: {e}")))?;

        let mut last_error = String::new();
        for attempt in 1..=self.retry.max_attempts {
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&self.api_key)
                .header("content-type", "application/json")
                .body(body_bytes.clone())
                .send()
                .await
                .map_err(|e| SynthError::Backend(format!("openai request: {e}")))?;

            let status = resp.status().as_u16();
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after);
            let text = resp
                .text()
                .await
                .map_err(|e| SynthError::Backend(format!("openai body: {e}")))?;

            match classify_status(status, retry_after, &self.retry, attempt) {
                RetryDecision::Done => {
                    let parsed: Response = serde_json::from_str(&text)
                        .map_err(|e| SynthError::Backend(format!("openai parse: {e}")))?;
                    return parsed
                        .choices
                        .into_iter()
                        .find_map(|c| {
                            if c.message.content.is_empty() {
                                None
                            } else {
                                Some(c.message.content)
                            }
                        })
                        .ok_or_else(|| {
                            SynthError::Backend("openai returned no choice content".into())
                        });
                }
                RetryDecision::Retry(delay) => {
                    last_error = format!("openai {status}: {text}");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                RetryDecision::Fatal => {
                    return Err(SynthError::Backend(format!("openai {status}: {text}")));
                }
            }
        }
        Err(SynthError::Backend(format!(
            "openai exhausted retries: {last_error}"
        )))
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
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: String,
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
    async fn returns_first_choice_content() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            r#"{"choices":[{"message":{"content":"hi there"}}]}"#.into(),
            captured.clone(),
        )
        .await;
        let adapter = OpenAIAdapter::new("sk-test").with_base_url(base);
        let result = adapter.complete("ping").await.unwrap();
        assert_eq!(result, "hi there");
    }

    #[tokio::test]
    async fn sends_bearer_auth_and_chat_completions_path() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(
            r#"{"choices":[{"message":{"content":"ok"}}]}"#.into(),
            captured.clone(),
        )
        .await;
        let adapter = OpenAIAdapter::new("sk-AAA")
            .with_base_url(base)
            .with_model("gpt-4o");
        let _ = adapter.complete("hello").await.unwrap();

        let req = captured.lock().await.take().unwrap();
        assert!(req.headers_blob.contains("POST /v1/chat/completions"));
        assert!(req
            .headers_blob
            .to_lowercase()
            .contains("authorization: bearer sk-aaa"));
        assert!(req.body.contains("\"model\":\"gpt-4o\""));
        assert!(req.body.contains("\"role\":\"user\""));
        assert!(req.body.contains("\"content\":\"hello\""));
    }

    #[tokio::test]
    async fn http_error_surfaces_as_backend_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"error":{"message":"rate limited"}}"#;
            let resp = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        });

        let adapter = OpenAIAdapter::new("bad").with_base_url(format!("http://{addr}"));
        let err = adapter.complete("hi").await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("429") || msg.contains("openai"));
    }

    #[tokio::test]
    async fn empty_choices_array_is_error() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(r#"{"choices":[]}"#.into(), captured).await;
        let adapter = OpenAIAdapter::new("k").with_base_url(base);
        let err = adapter.complete("p").await.unwrap_err();
        assert!(format!("{err}").contains("no choice content"));
    }

    #[test]
    fn defaults_match_published_constants() {
        let a = OpenAIAdapter::new("k");
        assert_eq!(a.base_url, DEFAULT_BASE_URL);
        assert_eq!(a.model, DEFAULT_MODEL);
        assert_eq!(a.max_tokens, DEFAULT_MAX_TOKENS);
    }
}
