//! Real Telegram Bot API client.
//!
//! Talks to `https://api.telegram.org/bot<TOKEN>/<METHOD>`.
//! Implements [`MessagingPlatform::send`] via `sendMessage` and
//! exposes [`TelegramPlatform::poll_updates`] for long-polling
//! `getUpdates` (PRD §9.4 inbound commands).
//!
//! The notification body is rendered as Markdown so severity stays
//! visually obvious in mobile clients.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::identity::IdentityBinding;
use crate::platform::{MessagingPlatform, Notification, NotificationKind, PlatformId, Severity};
use crate::GatewayError;

const DEFAULT_BASE_URL: &str = "https://api.telegram.org";
const POLL_TIMEOUT_SECONDS: u64 = 30;

#[derive(Debug, Clone)]
pub struct TelegramPlatform {
    client: reqwest::Client,
    token: String,
    base_url: String,
}

impl TelegramPlatform {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            token: token.into(),
            base_url: DEFAULT_BASE_URL.into(),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn method_url(&self, method: &str) -> String {
        format!(
            "{}/bot{}/{method}",
            self.base_url.trim_end_matches('/'),
            self.token
        )
    }

    /// Long-poll `getUpdates`. Returns one batch of messages plus
    /// the new offset that the caller stores for the next call.
    /// Empty batches are normal — long-poll waits up to
    /// [`POLL_TIMEOUT_SECONDS`] for new updates.
    pub async fn poll_updates(&self, offset: i64) -> Result<UpdateBatch, GatewayError> {
        let url = self.method_url("getUpdates");
        let resp = self
            .client
            .get(&url)
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", POLL_TIMEOUT_SECONDS.to_string()),
            ])
            .send()
            .await
            .map_err(|e| GatewayError::Backend(format!("telegram getUpdates: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GatewayError::Backend(format!("telegram body: {e}")))?;
        if !status.is_success() {
            return Err(GatewayError::Backend(format!(
                "telegram {}: {text}",
                status.as_u16()
            )));
        }
        let parsed: GetUpdatesResponse = serde_json::from_str(&text)
            .map_err(|e| GatewayError::Backend(format!("telegram parse: {e}")))?;
        if !parsed.ok {
            return Err(GatewayError::Backend(format!(
                "telegram not ok: {:?}",
                parsed.description
            )));
        }
        let next_offset = parsed
            .result
            .iter()
            .map(|u| u.update_id + 1)
            .max()
            .unwrap_or(offset);
        let messages = parsed
            .result
            .into_iter()
            .filter_map(|u| u.message)
            .map(|m| InboundMessage {
                chat_id: m.chat.id,
                from_username: m.from.and_then(|f| f.username),
                text: m.text.unwrap_or_default(),
            })
            .collect();
        Ok(UpdateBatch {
            messages,
            next_offset,
        })
    }
}

#[async_trait]
impl MessagingPlatform for TelegramPlatform {
    fn platform_id(&self) -> PlatformId {
        PlatformId::Telegram
    }

    async fn send(
        &self,
        binding: &IdentityBinding,
        notification: &Notification,
    ) -> Result<(), GatewayError> {
        let chat_id: i64 = binding.remote_id.parse().map_err(|_| {
            GatewayError::Backend(format!(
                "telegram remote_id `{}` is not a valid chat id",
                binding.remote_id
            ))
        })?;
        let body = SendMessage {
            chat_id,
            text: render_notification(notification),
            parse_mode: Some("Markdown"),
        };
        let resp = self
            .client
            .post(self.method_url("sendMessage"))
            .json(&body)
            .send()
            .await
            .map_err(|e| GatewayError::Backend(format!("telegram sendMessage: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Backend(format!(
                "telegram {}: {text}",
                status.as_u16()
            )));
        }
        Ok(())
    }
}

fn render_notification(n: &Notification) -> String {
    match &n.kind {
        NotificationKind::NewClaim {
            primitive_id,
            severity,
            surface_url,
        } => format!(
            "*Mantis — new claim* {}\n`{primitive_id}`\non `{surface_url}`",
            severity_badge(*severity)
        ),
        NotificationKind::BudgetWarning {
            engagement_id,
            remaining_pct,
        } => format!(
            "*Mantis — budget warning*\nEngagement `{engagement_id}` at {remaining_pct}% remaining"
        ),
        NotificationKind::ScheduledRunComplete {
            engagement_id,
            verified,
        } => format!(
            "*Mantis — scheduled run done*\n`{engagement_id}` — {verified} verified finding(s)"
        ),
        NotificationKind::LiveVerificationApprovalRequest {
            engagement_id,
            primitive_id,
        } => format!(
            "*Mantis — approval requested*\n`{engagement_id}` wants to run `{primitive_id}` against the live target"
        ),
    }
}

fn severity_badge(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴 Critical",
        Severity::High => "🟠 High",
        Severity::Medium => "🟡 Medium",
        Severity::Low => "🟢 Low",
        Severity::Informational => "⚪ Info",
    }
}

#[derive(Debug, Clone)]
pub struct UpdateBatch {
    pub messages: Vec<InboundMessage>,
    pub next_offset: i64,
}

#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub chat_id: i64,
    pub from_username: Option<String>,
    pub text: String,
}

#[derive(Serialize)]
struct SendMessage {
    chat_id: i64,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_mode: Option<&'static str>,
}

#[derive(Deserialize)]
struct GetUpdatesResponse {
    ok: bool,
    #[serde(default)]
    result: Vec<Update>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
struct Update {
    update_id: i64,
    message: Option<Message>,
}

#[derive(Deserialize)]
struct Message {
    chat: Chat,
    from: Option<User>,
    text: Option<String>,
}

#[derive(Deserialize)]
struct Chat {
    id: i64,
}

#[derive(Deserialize)]
struct User {
    username: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_core::OperatorId;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use ulid::Ulid;

    struct CapturedRequest {
        request_line: String,
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
            let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
            let request_line = head.lines().next().unwrap_or("").to_string();
            *captured.lock().await = Some(CapturedRequest {
                request_line,
                body: body.to_string(),
            });
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
        });
        format!("http://{addr}")
    }

    fn binding(remote_id: &str) -> IdentityBinding {
        IdentityBinding {
            operator: OperatorId(Ulid::new()),
            platform: PlatformId::Telegram,
            remote_id: remote_id.into(),
            created_at_unix: 0,
        }
    }

    fn budget_notif() -> Notification {
        Notification {
            kind: NotificationKind::BudgetWarning {
                engagement_id: "01HXX".into(),
                remaining_pct: 5,
            },
            generated_at_unix: 0,
        }
    }

    #[tokio::test]
    async fn send_message_posts_to_bot_token_endpoint() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(r#"{"ok":true,"result":{}}"#.into(), captured.clone()).await;
        let platform = TelegramPlatform::new("123:abc").with_base_url(base);
        platform
            .send(&binding("4242"), &budget_notif())
            .await
            .unwrap();

        let req = captured.lock().await.take().unwrap();
        assert!(req.request_line.contains("POST /bot123:abc/sendMessage"));
        assert!(req.body.contains("\"chat_id\":4242"));
        assert!(req.body.contains("01HXX"));
        assert!(req.body.contains("parse_mode"));
    }

    #[tokio::test]
    async fn send_message_rejects_non_numeric_chat_id() {
        let platform = TelegramPlatform::new("123:abc").with_base_url("http://127.0.0.1:1");
        let err = platform
            .send(&binding("not-a-number"), &budget_notif())
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("not a valid chat id"));
    }

    #[tokio::test]
    async fn http_error_surfaces() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"ok":false,"description":"Unauthorized"}"#;
            let resp = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        });
        let platform = TelegramPlatform::new("bad").with_base_url(format!("http://{addr}"));
        let err = platform
            .send(&binding("1"), &budget_notif())
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("401"));
    }

    #[tokio::test]
    async fn poll_updates_returns_messages_and_advances_offset() {
        let captured = Arc::new(Mutex::new(None));
        let body = r#"{"ok":true,"result":[{"update_id":42,"message":{"chat":{"id":100},"from":{"username":"alice"},"text":"hello"}},{"update_id":43,"message":{"chat":{"id":100},"text":"world"}}]}"#;
        let base = mock_server(body.into(), captured.clone()).await;
        let platform = TelegramPlatform::new("123:abc").with_base_url(base);
        let batch = platform.poll_updates(0).await.unwrap();

        assert_eq!(batch.next_offset, 44);
        assert_eq!(batch.messages.len(), 2);
        assert_eq!(batch.messages[0].text, "hello");
        assert_eq!(batch.messages[0].from_username.as_deref(), Some("alice"));
        assert_eq!(batch.messages[1].chat_id, 100);

        let req = captured.lock().await.take().unwrap();
        assert!(req.request_line.contains("GET /bot123:abc/getUpdates"));
        assert!(req.request_line.contains("offset=0"));
    }

    #[tokio::test]
    async fn poll_updates_empty_batch_preserves_offset() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(r#"{"ok":true,"result":[]}"#.into(), captured).await;
        let platform = TelegramPlatform::new("t").with_base_url(base);
        let batch = platform.poll_updates(99).await.unwrap();
        assert_eq!(batch.next_offset, 99);
        assert!(batch.messages.is_empty());
    }

    #[tokio::test]
    async fn poll_updates_ok_false_surfaces_as_error() {
        let captured = Arc::new(Mutex::new(None));
        let base = mock_server(r#"{"ok":false,"description":"bad token"}"#.into(), captured).await;
        let platform = TelegramPlatform::new("t").with_base_url(base);
        let err = platform.poll_updates(0).await.unwrap_err();
        assert!(format!("{err}").contains("bad token"));
    }

    #[test]
    fn render_notification_includes_severity_badge() {
        let n = Notification {
            kind: NotificationKind::NewClaim {
                primitive_id: "xss".into(),
                severity: Severity::Critical,
                surface_url: "https://x".into(),
            },
            generated_at_unix: 0,
        };
        let text = render_notification(&n);
        assert!(text.contains("Critical"));
        assert!(text.contains("xss"));
    }
}
