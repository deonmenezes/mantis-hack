//! Operator gateway (Phase 4 M4.2).
//!
//! Exposes the daemon to operators over messaging platforms.
//! Each platform implements [`MessagingPlatform`]; the gateway
//! routes outbound notifications and inbound commands through
//! the impl.
//!
//! Phase 4 M4.2 ships the trait + per-platform stub crates for the
//! 7 platforms PRD §9.4 names. Real network adapters (HTTP-bot
//! API clients) land in M4.2b–M4.2h, one platform per milestone,
//! so each adapter can be reviewed independently.

pub mod identity;
pub mod inbound;
pub mod platform;
pub mod platforms;
pub mod registry;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::identity::{IdentityBinding, IdentityStore};
pub use crate::inbound::{Command, InboundMessage};
pub use crate::platform::{
    MessagingPlatform, Notification, NotificationKind, PlatformId, Severity,
};
pub use crate::platforms::{
    DiscordPlatform, EmailPlatform, MatrixPlatform, SignalPlatform, SlackPlatform,
    TelegramPlatform, WhatsAppPlatform,
};
pub use crate::registry::GatewayRegistry;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("platform {0} not registered")]
    PlatformNotFound(String),

    #[error("identity binding {0} not found")]
    IdentityNotFound(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("internal lock poisoned")]
    Poisoned,
}

/// Common envelope for any outbound notification before the
/// platform-specific adapter renders it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundEnvelope {
    pub notification: Notification,
    pub target_operator: mantis_core::OperatorId,
}
