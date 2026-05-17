//! Integration tests for `mantis-workspace`.
//!
//! These exercise the full init/open/operator flow against the
//! [`InMemoryKeyStore`]. The OS keychain is never touched here — that
//! path is exercised manually via the CLI in M0.1 verification.

#![allow(clippy::unwrap_used)]

use camino::Utf8PathBuf;
use mantis_workspace::{
    run_doctor, DoctorReport, InMemoryKeyStore, OperatorProfile, Workspace, WorkspaceError,
};
use tempfile::TempDir;

fn temp_root() -> (TempDir, Utf8PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("temp dir path is utf8");
    (dir, path)
}

#[test]
fn init_creates_workspace_files_and_subdirs() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();

    assert!(root.join("workspace.config.toml").exists());
    assert!(root.join("operators").is_dir());
    assert!(root.join("engagements").is_dir());
    assert!(root.join("playbooks").is_dir());
    assert!(root.join("primitives").is_dir());
    assert!(root.join("trajectories").is_dir());
    assert_eq!(ws.fingerprint().len(), 16);
    assert_eq!(ws.config().schema_version, mantis_workspace::SCHEMA_VERSION);
}

#[test]
fn init_then_open_round_trip() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws1 = Workspace::init(&root, &ks).unwrap();
    let ws2 = Workspace::open(&root, &ks).unwrap();

    assert_eq!(ws1.id(), ws2.id());
    assert_eq!(ws1.fingerprint(), ws2.fingerprint());

    let sig = ws1.sign("ctx", b"payload");
    assert!(ws2.verify("ctx", b"payload", &sig));
}

#[test]
fn init_rejects_existing() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let _ = Workspace::init(&root, &ks).unwrap();
    let result = Workspace::init(&root, &ks);
    assert!(matches!(
        result,
        Err(WorkspaceError::AlreadyInitialized { .. })
    ));
}

#[test]
fn open_rejects_missing_workspace() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let result = Workspace::open(&root, &ks);
    assert!(matches!(result, Err(WorkspaceError::NotFound { .. })));
}

#[test]
fn open_rejects_missing_keystore_secret() {
    let (_tmp, root) = temp_root();
    let ks1 = InMemoryKeyStore::new();
    let _ = Workspace::init(&root, &ks1).unwrap();

    let ks2 = InMemoryKeyStore::new();
    let result = Workspace::open(&root, &ks2);
    assert!(result.is_err());
}

#[test]
fn open_rejects_when_keystore_secret_does_not_match_config() {
    use mantis_workspace::{workspace_keystore_service, KeyStore, Keypair};
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();

    // Replace the keystore secret with a different keypair's secret.
    let imposter = Keypair::generate();
    let imposter_secret = imposter.secret_bytes();
    ks.put(
        &workspace_keystore_service(ws.id()),
        "signing-key",
        imposter_secret.as_ref(),
    )
    .unwrap();

    let result = Workspace::open(&root, &ks);
    assert!(matches!(result, Err(WorkspaceError::KeyMismatch)));
}

#[test]
fn sign_and_verify_round_trip() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();

    let sig = ws.sign("test-context", b"payload");
    assert!(ws.verify("test-context", b"payload", &sig));
    assert!(!ws.verify("other-context", b"payload", &sig));
    assert!(!ws.verify("test-context", b"other", &sig));
}

#[test]
fn create_and_list_operators() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();

    let alice = ws.create_operator("alice", &ks).unwrap();
    let bob = ws.create_operator("bob", &ks).unwrap();

    let listed = ws.list_operators().unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().any(|o| o.name == "alice"));
    assert!(listed.iter().any(|o| o.name == "bob"));
    assert_eq!(alice.name, "alice");
    assert_eq!(bob.name, "bob");
    assert_ne!(alice.fingerprint(), bob.fingerprint());
}

#[test]
fn duplicate_operator_name_rejected() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();

    let _ = ws.create_operator("alice", &ks).unwrap();
    let result = ws.create_operator("alice", &ks);
    assert!(matches!(
        result,
        Err(WorkspaceError::OperatorNameTaken { .. })
    ));
}

#[test]
fn empty_operator_name_rejected() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();

    let result = ws.create_operator("", &ks);
    assert!(matches!(result, Err(WorkspaceError::OperatorNameEmpty)));

    let result = ws.create_operator("   ", &ks);
    assert!(matches!(result, Err(WorkspaceError::OperatorNameEmpty)));
}

#[test]
fn delete_operator_removes_files_and_keystore() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();

    let alice = ws.create_operator("alice", &ks).unwrap();
    assert_eq!(ws.list_operators().unwrap().len(), 1);

    ws.delete_operator(alice.id, &ks).unwrap();
    assert_eq!(ws.list_operators().unwrap().len(), 0);
    assert!(!root.join("operators").join(alice.id.to_string()).exists());
}

#[test]
fn delete_missing_operator_errors() {
    use mantis_core::OperatorId;
    use ulid::Ulid;
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();

    let result = ws.delete_operator(OperatorId(Ulid::new()), &ks);
    assert!(matches!(
        result,
        Err(WorkspaceError::OperatorNotFound { .. })
    ));
}

#[test]
fn operator_profile_persists_across_open() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();
    let alice = ws.create_operator("alice", &ks).unwrap();
    drop(ws);

    let ws = Workspace::open(&root, &ks).unwrap();
    let listed = ws.list_operators().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, alice.id);
    assert_eq!(listed[0].fingerprint, alice.fingerprint());
}

#[test]
fn doctor_reports_no_workspace_initially() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let report: DoctorReport = run_doctor(&root, &ks).unwrap();

    assert!(!report.workspace_exists);
    assert_eq!(report.operator_count, 0);
    assert!(report.workspace_id.is_none());
    assert!(report.keystore_available);
}

#[test]
fn doctor_reports_healthy_workspace() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let _ws = Workspace::init(&root, &ks).unwrap();
    let _ = _ws.create_operator("alice", &ks).unwrap();

    let report = run_doctor(&root, &ks).unwrap();
    assert!(report.workspace_exists);
    assert!(report.is_healthy());
    assert_eq!(report.operator_count, 1);
    assert!(report.workspace_id.is_some());
    assert!(report.fingerprint.is_some());
    assert_eq!(
        report.schema_version,
        Some(mantis_workspace::SCHEMA_VERSION)
    );
}

#[test]
fn workspace_config_toml_is_human_readable() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let _ = Workspace::init(&root, &ks).unwrap();

    let toml_str = std::fs::read_to_string(root.join("workspace.config.toml")).unwrap();
    assert!(toml_str.contains("schema_version"));
    assert!(toml_str.contains("workspace_key"));
    assert!(toml_str.contains("created_at_unix"));
}

#[test]
fn operator_profile_json_is_human_readable() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();
    let alice = ws.create_operator("alice", &ks).unwrap();

    let profile_path = root
        .join("operators")
        .join(alice.id.to_string())
        .join("profile.json");
    let json_str = std::fs::read_to_string(&profile_path).unwrap();
    let back: OperatorProfile = serde_json::from_str(&json_str).unwrap();
    assert_eq!(back.id, alice.id);
    assert_eq!(back.name, "alice");
}

#[test]
fn identity_pub_file_is_hex_32_bytes() {
    let (_tmp, root) = temp_root();
    let ks = InMemoryKeyStore::new();
    let ws = Workspace::init(&root, &ks).unwrap();
    let alice = ws.create_operator("alice", &ks).unwrap();

    let pub_path = root
        .join("operators")
        .join(alice.id.to_string())
        .join("identity.pub");
    let hex_str = std::fs::read_to_string(&pub_path).unwrap();
    let bytes = hex::decode(hex_str.trim()).unwrap();
    assert_eq!(bytes.len(), 32);
    assert_eq!(&bytes[..], alice.public_key.as_bytes());
}
