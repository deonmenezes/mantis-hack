//! ScheduledScan Custom Resource.

use serde::{Deserialize, Serialize};

use crate::{ObjectMeta, API_VERSION};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScan {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: ScheduledScanSpec,
}

impl ScheduledScan {
    pub fn new(name: impl Into<String>, spec: ScheduledScanSpec) -> Self {
        Self {
            api_version: API_VERSION.into(),
            kind: "ScheduledScan".into(),
            metadata: ObjectMeta::new(name),
            spec,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScanSpec {
    /// Cron expression — must match the restricted grammar of
    /// `mantis-scheduler`.
    pub cron: String,
    pub engagement_ref: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_round_trip() {
        let s = ScheduledScan::new(
            "daily-monitor",
            ScheduledScanSpec {
                cron: "0 2 * * *".into(),
                engagement_ref: "acme-monitor".into(),
            },
        );
        let yaml = serde_yaml_ng::to_string(&s).unwrap();
        let back: ScheduledScan = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(back.spec.cron, "0 2 * * *");
        assert_eq!(back.kind, "ScheduledScan");
    }
}
