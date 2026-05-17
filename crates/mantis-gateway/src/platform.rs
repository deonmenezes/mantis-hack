//! Per-platform abstraction.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::GatewayError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformId {
    Telegram,
    Signal,
    Discord,
    Slack,
    WhatsApp,
    Matrix,
    Email,
}

impl PlatformId {
    pub fn name(self) -> &'static str {
        match self {
            PlatformId::Telegram => "telegram",
            PlatformId::Signal => "signal",
            PlatformId::Discord => "discord",
            PlatformId::Slack => "slack",
            PlatformId::WhatsApp => "whatsapp",
            PlatformId::Matrix => "matrix",
            PlatformId::Email => "email",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationKind {
    NewClaim {
        primitive_id: String,
        severity: Severity,
        surface_url: String,
    },
    BudgetWarning {
        engagement_id: String,
        remaining_pct: u32,
    },
    ScheduledRunComplete {
        engagement_id: String,
        verified: u32,
    },
    LiveVerificationApprovalRequest {
        engagement_id: String,
        primitive_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub kind: NotificationKind,
    pub generated_at_unix: u64,
}

/// Trait every platform adapter implements. Adapters live in
/// `platforms/<name>.rs` and may pull in their own deps.
#[async_trait]
pub trait MessagingPlatform: Send + Sync {
    fn platform_id(&self) -> PlatformId;
    async fn send(
        &self,
        binding: &crate::identity::IdentityBinding,
        notification: &Notification,
    ) -> Result<(), GatewayError>;
}
