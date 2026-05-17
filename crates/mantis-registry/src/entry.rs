//! Registry-side entry (one plugin, many versions).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ArtifactRef;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: EntryId,
    pub display_name: String,
    pub description: String,
    pub publisher: String,
    /// Tag → version metadata.
    pub versions: BTreeMap<String, EntryVersion>,
    pub status: EntryStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryStatus {
    Active,
    Deprecated,
    Yanked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryVersion {
    pub artifact_ref: ArtifactRef,
    /// Hex SHA-256 of the OCI manifest.
    pub manifest_digest: String,
    pub signed_by: String,
    pub published_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Distribution {
    pub entries: Vec<Entry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Entry {
        let mut versions = BTreeMap::new();
        versions.insert(
            "1.0.0".into(),
            EntryVersion {
                artifact_ref: ArtifactRef {
                    registry: "registry.example.com".into(),
                    plugin: "scanner".into(),
                    tag: "1.0.0".into(),
                },
                manifest_digest: "a".repeat(64),
                signed_by: "alice".into(),
                published_at_unix: 1_000_000,
            },
        );
        Entry {
            id: EntryId("scanner".into()),
            display_name: "Scanner".into(),
            description: "An example scanner".into(),
            publisher: "alice".into(),
            versions,
            status: EntryStatus::Active,
        }
    }

    #[test]
    fn entry_round_trips() {
        let e = sample();
        let json = serde_json::to_string(&e).unwrap();
        let back: Entry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id.0, "scanner");
        assert_eq!(back.versions.len(), 1);
    }

    #[test]
    fn distribution_holds_many_entries() {
        let d = Distribution {
            entries: vec![sample(), sample()],
        };
        assert_eq!(d.entries.len(), 2);
    }
}
