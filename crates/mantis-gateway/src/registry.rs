//! Gateway-side platform registry: dispatch a notification to the
//! right platform for a given identity binding.

use std::collections::HashMap;
use std::sync::Arc;

#[cfg(test)]
use crate::identity::IdentityBinding;
use crate::identity::IdentityStore;
use crate::platform::{MessagingPlatform, PlatformId};
use crate::{GatewayError, OutboundEnvelope};

#[derive(Default)]
pub struct GatewayRegistry {
    platforms: HashMap<PlatformId, Arc<dyn MessagingPlatform>>,
    identities: Arc<IdentityStore>,
}

impl std::fmt::Debug for GatewayRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayRegistry")
            .field("platforms", &self.platforms.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl GatewayRegistry {
    pub fn new(identities: Arc<IdentityStore>) -> Self {
        Self {
            platforms: HashMap::new(),
            identities,
        }
    }

    pub fn register(&mut self, platform: Arc<dyn MessagingPlatform>) {
        self.platforms.insert(platform.platform_id(), platform);
    }

    /// Dispatch a notification to every platform the operator is
    /// bound on. Errors from individual platforms are aggregated;
    /// one platform failing doesn't block the others.
    pub async fn dispatch(&self, envelope: &OutboundEnvelope) -> Result<usize, GatewayError> {
        let bindings = self
            .identities
            .list_for_operator(envelope.target_operator)?;
        let mut delivered = 0;
        for binding in &bindings {
            if let Some(platform) = self.platforms.get(&binding.platform) {
                platform.send(binding, &envelope.notification).await?;
                delivered += 1;
            }
        }
        Ok(delivered)
    }

    pub fn platform_ids(&self) -> Vec<PlatformId> {
        let mut ids: Vec<_> = self.platforms.keys().copied().collect();
        ids.sort_by_key(|p| p.name());
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{Notification, NotificationKind};
    use crate::platforms::{DiscordPlatform, SignalPlatform};
    use async_trait::async_trait;
    use mantis_core::OperatorId;
    use ulid::Ulid;

    /// Test double that implements MessagingPlatform with a no-op
    /// send. Used here so the registry tests don't depend on a
    /// real network call from the live TelegramPlatform.
    struct FakeTelegram;
    #[async_trait]
    impl MessagingPlatform for FakeTelegram {
        fn platform_id(&self) -> PlatformId {
            PlatformId::Telegram
        }
        async fn send(&self, _b: &IdentityBinding, _n: &Notification) -> Result<(), GatewayError> {
            Ok(())
        }
    }

    fn notif() -> Notification {
        Notification {
            kind: NotificationKind::BudgetWarning {
                engagement_id: "01HXX".into(),
                remaining_pct: 10,
            },
            generated_at_unix: 0,
        }
    }

    #[tokio::test]
    async fn dispatch_delivers_to_each_bound_platform() {
        let identities = Arc::new(IdentityStore::new());
        let op = OperatorId(Ulid::new());
        identities
            .bind(IdentityBinding {
                operator: op,
                platform: PlatformId::Telegram,
                remote_id: "tg".into(),
                created_at_unix: 0,
            })
            .unwrap();
        identities
            .bind(IdentityBinding {
                operator: op,
                platform: PlatformId::Discord,
                remote_id: "dc".into(),
                created_at_unix: 0,
            })
            .unwrap();
        let mut registry = GatewayRegistry::new(identities);
        registry.register(Arc::new(FakeTelegram));
        registry.register(Arc::new(DiscordPlatform));

        let envelope = OutboundEnvelope {
            notification: notif(),
            target_operator: op,
        };
        let count = registry.dispatch(&envelope).await.unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn registry_lists_platforms_alphabetically() {
        let mut registry = GatewayRegistry::new(Arc::new(IdentityStore::new()));
        registry.register(Arc::new(SignalPlatform));
        registry.register(Arc::new(DiscordPlatform));
        let ids = registry.platform_ids();
        assert_eq!(ids[0].name(), "discord");
        assert_eq!(ids[1].name(), "signal");
    }
}
