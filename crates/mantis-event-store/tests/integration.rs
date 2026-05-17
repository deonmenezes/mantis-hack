//! Integration tests for `mantis-event-store`.
//!
//! Exercises append, replay, head, and inclusion-proof flows against
//! the real RocksDB backend in a temporary directory.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

use camino::Utf8PathBuf;
use mantis_core::{EngagementId, Signer};
use mantis_event_store::{verify_inclusion, EventKind, EventStore, EventStoreError};
use mantis_workspace::Keypair;
use tempfile::TempDir;
use ulid::Ulid;

fn temp_db() -> (TempDir, Utf8PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path =
        Utf8PathBuf::from_path_buf(dir.path().join("events.rocksdb").to_path_buf()).expect("utf8");
    (dir, path)
}

fn new_engagement() -> EngagementId {
    EngagementId(Ulid::new())
}

#[test]
fn append_and_replay_round_trip() {
    let (_tmp, db_path) = temp_db();
    let store = EventStore::open(&db_path).unwrap();
    let kp = Keypair::generate();
    let eng = new_engagement();

    let (seq0, head0) = store
        .append(
            eng,
            EventKind::EngagementCreated {
                name: "demo".into(),
            },
            &kp,
        )
        .unwrap();
    assert_eq!(seq0, 0);
    assert_eq!(head0.leaf_count, 1);

    let (seq1, head1) = store
        .append(eng, EventKind::EngagementStarted, &kp)
        .unwrap();
    assert_eq!(seq1, 1);
    assert_eq!(head1.leaf_count, 2);

    let replay = store.replay(eng).unwrap();
    assert_eq!(replay.len(), 2);
    assert_eq!(replay[0].seq, 0);
    assert_eq!(replay[1].seq, 1);
    assert!(matches!(
        replay[0].kind,
        EventKind::EngagementCreated { .. }
    ));
    assert!(matches!(replay[1].kind, EventKind::EngagementStarted));
}

#[test]
fn event_count_progresses() {
    let (_tmp, db_path) = temp_db();
    let store = EventStore::open(&db_path).unwrap();
    let kp = Keypair::generate();
    let eng = new_engagement();

    assert_eq!(store.event_count(eng).unwrap(), 0);
    for i in 0..5 {
        store
            .append(
                eng,
                EventKind::ObservationRecorded {
                    payload_hex: format!("{i:02x}"),
                },
                &kp,
            )
            .unwrap();
        assert_eq!(store.event_count(eng).unwrap(), (i as u64) + 1);
    }
}

#[test]
fn head_updates_root_on_every_append() {
    let (_tmp, db_path) = temp_db();
    let store = EventStore::open(&db_path).unwrap();
    let kp = Keypair::generate();
    let eng = new_engagement();

    let mut prev_root = [0u8; 32];
    for i in 0..6 {
        let (_, head) = store
            .append(
                eng,
                EventKind::ObservationRecorded {
                    payload_hex: format!("{i:02x}"),
                },
                &kp,
            )
            .unwrap();
        assert_eq!(head.leaf_count, (i as u64) + 1);
        assert_ne!(head.root, prev_root, "root did not change at step {i}");
        prev_root = head.root;
    }
}

#[test]
fn inclusion_proof_verifies_in_rust() {
    let (_tmp, db_path) = temp_db();
    let store = EventStore::open(&db_path).unwrap();
    let kp = Keypair::generate();
    let eng = new_engagement();

    for i in 0..7 {
        store
            .append(
                eng,
                EventKind::ObservationRecorded {
                    payload_hex: format!("{i:02x}"),
                },
                &kp,
            )
            .unwrap();
    }
    let head = store.head(eng).unwrap().unwrap();

    for i in 0..head.leaf_count {
        let proof = store.inclusion_proof(eng, i).unwrap();
        let path_hashes: Vec<[u8; 32]> = proof.path.iter().map(|h| h.0).collect();
        assert!(
            verify_inclusion(
                proof.leaf_hash,
                proof.leaf_index,
                proof.leaf_count,
                &path_hashes,
                head.root
            ),
            "in-Rust verify failed for leaf {i}",
        );
    }
}

#[test]
fn inclusion_proof_rejects_out_of_range_leaf() {
    let (_tmp, db_path) = temp_db();
    let store = EventStore::open(&db_path).unwrap();
    let kp = Keypair::generate();
    let eng = new_engagement();

    store
        .append(eng, EventKind::EngagementStarted, &kp)
        .unwrap();
    let err = store.inclusion_proof(eng, 5).unwrap_err();
    assert!(matches!(err, EventStoreError::LeafOutOfRange { .. }));
}

#[test]
fn head_signature_verifies_against_workspace_public_key() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let (_tmp, db_path) = temp_db();
    let store = EventStore::open(&db_path).unwrap();
    let kp = Keypair::generate();
    let eng = new_engagement();

    let (_, head) = store
        .append(eng, EventKind::EngagementStarted, &kp)
        .unwrap();

    let canonical = head.canonical_bytes();
    let mut signed_bytes = Vec::with_capacity(canonical.len() + 16);
    signed_bytes.extend_from_slice(b"Mantis-v1:tree:");
    signed_bytes.extend_from_slice(&canonical);

    let public_bytes = kp.public_key_bytes();
    let vk = VerifyingKey::from_bytes(&public_bytes).unwrap();
    let sig = Signature::from_bytes(&head.signature);
    vk.verify(&signed_bytes, &sig)
        .expect("signature should verify");
}

#[test]
fn head_persists_across_open() {
    let (_tmp, db_path) = temp_db();
    let kp = Keypair::generate();
    let eng = new_engagement();

    {
        let store = EventStore::open(&db_path).unwrap();
        store
            .append(eng, EventKind::EngagementCreated { name: "x".into() }, &kp)
            .unwrap();
        store
            .append(eng, EventKind::EngagementStarted, &kp)
            .unwrap();
    }

    let store = EventStore::open(&db_path).unwrap();
    let head = store.head(eng).unwrap().unwrap();
    assert_eq!(head.leaf_count, 2);
    let replay = store.replay(eng).unwrap();
    assert_eq!(replay.len(), 2);
}

#[test]
fn engagements_are_isolated() {
    let (_tmp, db_path) = temp_db();
    let store = EventStore::open(&db_path).unwrap();
    let kp = Keypair::generate();
    let a = new_engagement();
    let b = new_engagement();

    store.append(a, EventKind::EngagementStarted, &kp).unwrap();
    store
        .append(b, EventKind::EngagementCreated { name: "b1".into() }, &kp)
        .unwrap();
    store.append(b, EventKind::EngagementStarted, &kp).unwrap();

    assert_eq!(store.event_count(a).unwrap(), 1);
    assert_eq!(store.event_count(b).unwrap(), 2);
    assert_ne!(
        store.head(a).unwrap().unwrap().root,
        store.head(b).unwrap().unwrap().root
    );
}

#[test]
fn mantis_verify_binary_accepts_valid_proof() {
    let (_tmp, db_path) = temp_db();
    let store = EventStore::open(&db_path).unwrap();
    let kp = Keypair::generate();
    let eng = new_engagement();

    for i in 0..5 {
        store
            .append(
                eng,
                EventKind::ObservationRecorded {
                    payload_hex: format!("{i:02x}"),
                },
                &kp,
            )
            .unwrap();
    }

    let proof = store.inclusion_proof(eng, 2).unwrap();
    let proof_path = _tmp.path().join("proof.json");
    std::fs::write(&proof_path, serde_json::to_vec_pretty(&proof).unwrap()).unwrap();

    let public_hex = hex::encode(kp.public_key_bytes());
    let output = run_verifier(&proof_path, &public_hex);
    assert!(
        output.status.success(),
        "verifier rejected valid proof.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("OK"));
}

#[test]
fn mantis_verify_binary_rejects_wrong_public_key() {
    let (_tmp, db_path) = temp_db();
    let store = EventStore::open(&db_path).unwrap();
    let kp = Keypair::generate();
    let eng = new_engagement();

    store
        .append(eng, EventKind::EngagementStarted, &kp)
        .unwrap();
    let proof = store.inclusion_proof(eng, 0).unwrap();
    let proof_path = _tmp.path().join("proof.json");
    std::fs::write(&proof_path, serde_json::to_vec_pretty(&proof).unwrap()).unwrap();

    let imposter = Keypair::generate();
    let wrong_hex = hex::encode(imposter.public_key_bytes());
    let output = run_verifier(&proof_path, &wrong_hex);
    assert!(!output.status.success(), "verifier accepted wrong key");
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("FAIL"));
}

#[test]
fn mantis_verify_binary_rejects_tampered_proof() {
    let (_tmp, db_path) = temp_db();
    let store = EventStore::open(&db_path).unwrap();
    let kp = Keypair::generate();
    let eng = new_engagement();

    for i in 0..4 {
        store
            .append(
                eng,
                EventKind::ObservationRecorded {
                    payload_hex: format!("{i:02x}"),
                },
                &kp,
            )
            .unwrap();
    }
    let mut proof = store.inclusion_proof(eng, 1).unwrap();
    // Flip a byte in the leaf hash.
    proof.leaf_hash[0] ^= 0xff;

    let proof_path = _tmp.path().join("proof.json");
    std::fs::write(&proof_path, serde_json::to_vec_pretty(&proof).unwrap()).unwrap();

    let public_hex = hex::encode(kp.public_key_bytes());
    let output = run_verifier(&proof_path, &public_hex);
    assert!(!output.status.success(), "verifier accepted tampered proof");
}

fn run_verifier(proof_path: &std::path::Path, public_hex: &str) -> std::process::Output {
    let binary = find_verifier_binary();
    Command::new(&binary)
        .args([
            "--proof",
            proof_path.to_str().unwrap(),
            "--public-key",
            public_hex,
        ])
        .output()
        .unwrap_or_else(|e| panic!("failed to exec {}: {e}", binary.display()))
}

fn find_verifier_binary() -> PathBuf {
    // The test binary lives at target/<profile>/deps/<test-name>-HASH. The
    // mantis-verify binary lives at target/<profile>/mantis-verify.
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop(); // <test-name>-HASH
    if path.ends_with("deps") {
        path.pop(); // deps/
    }
    path.push(if cfg!(windows) {
        "mantis-verify.exe"
    } else {
        "mantis-verify"
    });
    path
}
