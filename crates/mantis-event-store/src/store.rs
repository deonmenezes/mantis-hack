//! RocksDB-backed [`EventStore`].
//!
//! Storage layout:
//!
//! - Column family `events`: keys are
//!   `engagement_id_ulid_bytes (16) || seq_be (8)`; values are the
//!   serialized [`Event`] bytes (also the bytes that were leaf-hashed).
//! - Column family `meta`: keys are
//!   `engagement_id_ulid_bytes (16) || tag (1)`. Tags:
//!     - `0x01`: serialized [`SignedTreeHead`] (latest).
//!     - `0x02`: cached event count, big-endian u64.
//!
//! Appends serialize per engagement via a single global mutex. Phase 0
//! tolerates the contention; Phase 1 introduces per-engagement locking.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use camino::Utf8Path;
use mantis_core::{EngagementId, Signer};
use rocksdb::{
    ColumnFamilyDescriptor, DBWithThreadMode, IteratorMode, MultiThreaded, Options, WriteBatch,
};
use ulid::Ulid;

type Db = DBWithThreadMode<MultiThreaded>;

use crate::error::EventStoreError;
use crate::event::{Event, EventKind};
use crate::head::SignedTreeHead;
use crate::merkle::{inclusion_path, leaf_hash, merkle_root};

const CF_EVENTS: &str = "events";
const CF_META: &str = "meta";
const META_HEAD: u8 = 0x01;
const META_COUNT: u8 = 0x02;

const ULID_BYTES: usize = 16;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InclusionProof {
    pub engagement_id: String,
    pub leaf_index: u64,
    pub leaf_count: u64,
    #[serde(with = "crate::hex32")]
    pub leaf_hash: [u8; 32],
    pub path: Vec<HexHash>,
    pub signed_head: SignedTreeHead,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HexHash(#[serde(with = "crate::hex32")] pub [u8; 32]);

pub struct EventStore {
    db: Arc<Db>,
    append_lock: Mutex<()>,
}

impl std::fmt::Debug for EventStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventStore").finish_non_exhaustive()
    }
}

impl EventStore {
    pub fn open(path: &Utf8Path) -> Result<Self, EventStoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_EVENTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];
        let db = Db::open_cf_descriptors(&opts, Path::new(path.as_str()), cfs)?;
        Ok(Self {
            db: Arc::new(db),
            append_lock: Mutex::new(()),
        })
    }

    /// Append a single event to an engagement's log. Returns the
    /// assigned sequence number and the updated signed tree head.
    pub fn append(
        &self,
        engagement_id: EngagementId,
        kind: EventKind,
        signer: &dyn Signer,
    ) -> Result<(u64, SignedTreeHead), EventStoreError> {
        let _guard = self
            .append_lock
            .lock()
            .map_err(|_| EventStoreError::Invariant("append mutex poisoned".into()))?;

        let count = self.event_count(engagement_id)?;
        let seq = count;
        let wall_clock_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let event = Event::new(seq, wall_clock_unix, kind);
        let bytes = event.canonical_bytes()?;

        let events_cf = self.cf(CF_EVENTS)?;
        let meta_cf = self.cf(CF_META)?;

        let mut batch = WriteBatch::default();
        batch.put_cf(&events_cf, event_key(engagement_id, seq), &bytes);
        let new_count = count + 1;
        batch.put_cf(
            &meta_cf,
            meta_key(engagement_id, META_COUNT),
            new_count.to_be_bytes(),
        );

        let leaves = read_leaves(&self.db, engagement_id, count)?;
        let mut all_leaves = leaves;
        all_leaves.push(leaf_hash(&bytes));
        let root = merkle_root(&all_leaves);
        let head = SignedTreeHead::create(signer, engagement_id, new_count, root);
        let head_bytes = serde_json::to_vec(&head)?;
        batch.put_cf(&meta_cf, meta_key(engagement_id, META_HEAD), &head_bytes);

        self.db.write(batch)?;
        Ok((seq, head))
    }

    /// Replay all events for an engagement in seq order.
    pub fn replay(&self, engagement_id: EngagementId) -> Result<Vec<Event>, EventStoreError> {
        let events_cf = self.cf(CF_EVENTS)?;
        let prefix = engagement_prefix(engagement_id);
        let mut out = vec![];
        let iter = self.db.iterator_cf(
            &events_cf,
            IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            let event: Event = serde_json::from_slice(&value)?;
            out.push(event);
        }
        Ok(out)
    }

    /// Latest signed tree head for an engagement (None if no events
    /// have been appended).
    pub fn head(
        &self,
        engagement_id: EngagementId,
    ) -> Result<Option<SignedTreeHead>, EventStoreError> {
        let meta_cf = self.cf(CF_META)?;
        let key = meta_key(engagement_id, META_HEAD);
        match self.db.get_cf(&meta_cf, key)? {
            Some(bytes) => {
                let head: SignedTreeHead = serde_json::from_slice(&bytes)?;
                Ok(Some(head))
            }
            None => Ok(None),
        }
    }

    /// Number of events appended for an engagement.
    pub fn event_count(&self, engagement_id: EngagementId) -> Result<u64, EventStoreError> {
        let meta_cf = self.cf(CF_META)?;
        let key = meta_key(engagement_id, META_COUNT);
        match self.db.get_cf(&meta_cf, key)? {
            Some(bytes) if bytes.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(arr))
            }
            Some(_) => Err(EventStoreError::Invariant(
                "count meta entry has wrong length".into(),
            )),
            None => Ok(0),
        }
    }

    /// Produce an inclusion proof for the event at `leaf_index`.
    pub fn inclusion_proof(
        &self,
        engagement_id: EngagementId,
        leaf_index: u64,
    ) -> Result<InclusionProof, EventStoreError> {
        let head = self
            .head(engagement_id)?
            .ok_or_else(|| EventStoreError::EngagementNotFound(engagement_id.to_string()))?;
        if leaf_index >= head.leaf_count {
            return Err(EventStoreError::LeafOutOfRange {
                index: leaf_index,
                count: head.leaf_count,
            });
        }
        let leaves = read_leaves(&self.db, engagement_id, head.leaf_count)?;
        let leaf = leaves[leaf_index as usize];
        let path = inclusion_path(&leaves, leaf_index)
            .into_iter()
            .map(HexHash)
            .collect();
        Ok(InclusionProof {
            engagement_id: engagement_id.to_string(),
            leaf_index,
            leaf_count: head.leaf_count,
            leaf_hash: leaf,
            path,
            signed_head: head,
        })
    }

    /// List every engagement ID with at least one persisted event.
    /// Used by the daemon at startup to repopulate its in-memory
    /// engagement state map.
    pub fn list_engagement_ids(&self) -> Result<Vec<EngagementId>, EventStoreError> {
        let events_cf = self.cf(CF_EVENTS)?;
        let mut out: Vec<EngagementId> = vec![];
        let mut last_prefix: Option<[u8; ULID_BYTES]> = None;
        let iter = self.db.iterator_cf(&events_cf, IteratorMode::Start);
        for item in iter {
            let (key, _) = item?;
            if key.len() < ULID_BYTES {
                continue;
            }
            let mut prefix = [0u8; ULID_BYTES];
            prefix.copy_from_slice(&key[..ULID_BYTES]);
            if Some(prefix) != last_prefix {
                let ulid = Ulid::from_bytes(prefix);
                out.push(EngagementId(ulid));
                last_prefix = Some(prefix);
            }
        }
        Ok(out)
    }

    fn cf(&self, name: &str) -> Result<Arc<rocksdb::BoundColumnFamily<'_>>, EventStoreError> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| EventStoreError::Invariant(format!("missing column family: {name}")))
    }
}

fn event_key(engagement_id: EngagementId, seq: u64) -> [u8; ULID_BYTES + 8] {
    let mut key = [0u8; ULID_BYTES + 8];
    let ulid_bytes = ulid_to_bytes(engagement_id.0);
    key[..ULID_BYTES].copy_from_slice(&ulid_bytes);
    key[ULID_BYTES..].copy_from_slice(&seq.to_be_bytes());
    key
}

fn meta_key(engagement_id: EngagementId, tag: u8) -> [u8; ULID_BYTES + 1] {
    let mut key = [0u8; ULID_BYTES + 1];
    let ulid_bytes = ulid_to_bytes(engagement_id.0);
    key[..ULID_BYTES].copy_from_slice(&ulid_bytes);
    key[ULID_BYTES] = tag;
    key
}

fn engagement_prefix(engagement_id: EngagementId) -> [u8; ULID_BYTES] {
    ulid_to_bytes(engagement_id.0)
}

fn ulid_to_bytes(ulid: Ulid) -> [u8; 16] {
    ulid.to_bytes()
}

fn read_leaves(
    db: &Db,
    engagement_id: EngagementId,
    count: u64,
) -> Result<Vec<[u8; 32]>, EventStoreError> {
    let events_cf = db
        .cf_handle(CF_EVENTS)
        .ok_or_else(|| EventStoreError::Invariant("missing events CF".into()))?;
    let prefix = engagement_prefix(engagement_id);
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(count as usize);
    let iter = db.iterator_cf(
        &events_cf,
        IteratorMode::From(&prefix, rocksdb::Direction::Forward),
    );
    for item in iter {
        let (key, value) = item?;
        if !key.starts_with(&prefix) {
            break;
        }
        leaves.push(leaf_hash(&value));
    }
    if leaves.len() as u64 != count {
        return Err(EventStoreError::Invariant(format!(
            "leaf count mismatch: meta says {count}, on-disk has {}",
            leaves.len()
        )));
    }
    Ok(leaves)
}
