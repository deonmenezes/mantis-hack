//! Per-platform stub adapters. Each adapter is a `pub struct` that
//! implements [`crate::MessagingPlatform`]. Phase 4 M4.2 ships
//! Send/log stubs; real network adapters land per platform in
//! M4.2b–M4.2h.

use async_trait::async_trait;

use crate::identity::IdentityBinding;
use crate::platform::{MessagingPlatform, Notification, PlatformId};
use crate::GatewayError;

macro_rules! stub_platform {
    ($name:ident, $id:expr) => {
        #[derive(Debug, Default, Clone, Copy)]
        pub struct $name;
        #[async_trait]
        impl MessagingPlatform for $name {
            fn platform_id(&self) -> PlatformId {
                $id
            }
            async fn send(
                &self,
                _binding: &IdentityBinding,
                _notification: &Notification,
            ) -> Result<(), GatewayError> {
                tracing_stub::log_send($id);
                Ok(())
            }
        }
    };
}

stub_platform!(TelegramPlatform, PlatformId::Telegram);
stub_platform!(SignalPlatform, PlatformId::Signal);
stub_platform!(DiscordPlatform, PlatformId::Discord);
stub_platform!(SlackPlatform, PlatformId::Slack);
stub_platform!(WhatsAppPlatform, PlatformId::WhatsApp);
stub_platform!(MatrixPlatform, PlatformId::Matrix);
stub_platform!(EmailPlatform, PlatformId::Email);

mod tracing_stub {
    use crate::platform::PlatformId;

    /// Test-friendly send hook. Phase 4 M4.2b–M4.2h replace this
    /// with real HTTP client calls per platform.
    pub(super) fn log_send(_platform: PlatformId) {
        // No-op stub.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantis_core::OperatorId;
    use ulid::Ulid;

    fn binding(platform: PlatformId) -> IdentityBinding {
        IdentityBinding {
            operator: OperatorId(Ulid::new()),
            platform,
            remote_id: "remote".into(),
            created_at_unix: 0,
        }
    }

    fn notif() -> Notification {
        Notification {
            kind: crate::platform::NotificationKind::BudgetWarning {
                engagement_id: "01HXX".into(),
                remaining_pct: 10,
            },
            generated_at_unix: 0,
        }
    }

    #[tokio::test]
    async fn each_platform_reports_its_id() {
        let cases: [(Box<dyn MessagingPlatform>, PlatformId); 7] = [
            (Box::new(TelegramPlatform), PlatformId::Telegram),
            (Box::new(SignalPlatform), PlatformId::Signal),
            (Box::new(DiscordPlatform), PlatformId::Discord),
            (Box::new(SlackPlatform), PlatformId::Slack),
            (Box::new(WhatsAppPlatform), PlatformId::WhatsApp),
            (Box::new(MatrixPlatform), PlatformId::Matrix),
            (Box::new(EmailPlatform), PlatformId::Email),
        ];
        for (p, expected) in cases {
            assert_eq!(p.platform_id(), expected);
            p.send(&binding(expected), &notif()).await.unwrap();
        }
    }
}
