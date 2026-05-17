//! Registry search.

use serde::{Deserialize, Serialize};

use crate::entry::{Entry, EntryStatus};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: Option<String>,
    pub publisher: Option<String>,
    pub include_deprecated: bool,
    pub include_yanked: bool,
}

pub fn search(entries: &[Entry], query: &SearchQuery) -> Vec<Entry> {
    let text = query.text.as_deref().map(|s| s.to_ascii_lowercase());
    let publisher = query.publisher.as_deref();
    entries
        .iter()
        .filter(|e| match e.status {
            EntryStatus::Deprecated => query.include_deprecated,
            EntryStatus::Yanked => query.include_yanked,
            EntryStatus::Active => true,
        })
        .filter(|e| match publisher {
            Some(p) => e.publisher == p,
            None => true,
        })
        .filter(|e| match &text {
            Some(t) => {
                e.id.0.to_ascii_lowercase().contains(t)
                    || e.display_name.to_ascii_lowercase().contains(t)
                    || e.description.to_ascii_lowercase().contains(t)
            }
            None => true,
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{EntryId, EntryVersion};
    use crate::ArtifactRef;
    use std::collections::BTreeMap;

    fn entry(id: &str, publisher: &str, status: EntryStatus) -> Entry {
        let mut versions = BTreeMap::new();
        versions.insert(
            "1.0.0".into(),
            EntryVersion {
                artifact_ref: ArtifactRef {
                    registry: "r".into(),
                    plugin: id.into(),
                    tag: "1.0.0".into(),
                },
                manifest_digest: "x".repeat(64),
                signed_by: publisher.into(),
                published_at_unix: 0,
            },
        );
        Entry {
            id: EntryId(id.into()),
            display_name: id.into(),
            description: format!("description of {id}"),
            publisher: publisher.into(),
            versions,
            status,
        }
    }

    #[test]
    fn search_filters_yanked_by_default() {
        let entries = vec![
            entry("a", "alice", EntryStatus::Active),
            entry("b", "alice", EntryStatus::Yanked),
        ];
        let q = SearchQuery::default();
        let results = search(&entries, &q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id.0, "a");
    }

    #[test]
    fn search_includes_yanked_when_requested() {
        let entries = vec![
            entry("a", "alice", EntryStatus::Active),
            entry("b", "alice", EntryStatus::Yanked),
        ];
        let q = SearchQuery {
            include_yanked: true,
            ..Default::default()
        };
        assert_eq!(search(&entries, &q).len(), 2);
    }

    #[test]
    fn search_by_text_matches_id_name_description() {
        let entries = vec![
            entry("sqli-scanner", "alice", EntryStatus::Active),
            entry("xss-scanner", "alice", EntryStatus::Active),
            entry("ssrf-prober", "bob", EntryStatus::Active),
        ];
        let q = SearchQuery {
            text: Some("scanner".into()),
            ..Default::default()
        };
        let results = search(&entries, &q);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_by_publisher() {
        let entries = vec![
            entry("a", "alice", EntryStatus::Active),
            entry("b", "bob", EntryStatus::Active),
            entry("c", "alice", EntryStatus::Active),
        ];
        let q = SearchQuery {
            publisher: Some("alice".into()),
            ..Default::default()
        };
        assert_eq!(search(&entries, &q).len(), 2);
    }
}
