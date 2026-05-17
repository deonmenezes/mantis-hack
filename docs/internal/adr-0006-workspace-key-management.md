# ADR-0006: Workspace key management

**Status:** Accepted
**Date:** 2026-05-16
**Milestone:** M0.1

## Context

The Mantis workspace key signs all per-engagement artifacts: scope
manifests (M0.3), event-log Merkle tree heads (M0.2), and exported
reports (M0.5+). Operator identities have their own keypairs used for
authorizing engagements (PRD §5.14.4) and approving live verifications.
Where these secret keys live, and how they round-trip across daemon
restarts, is foundational — getting it wrong here corrupts every later
milestone.

PRD §6.4.4 requires that secrets be stored in OS-keychain integration
where available and never logged. PRD §7.3 names a `workspace.key` file
that holds an encrypted Ed25519 signing key.

## Decision

### KeyStore abstraction

A trait, `KeyStore`, abstracts the secret-storage backend:

```rust
trait KeyStore: Send + Sync {
    fn put(&self, service: &str, account: &str, secret: &[u8]) -> Result<()>;
    fn get(&self, service: &str, account: &str) -> Result<Vec<u8>>;
    fn delete(&self, service: &str, account: &str) -> Result<()>;
    fn is_available(&self) -> bool;
    fn backend_name(&self) -> &'static str;
}
```

Two implementations land in M0.1:

1. **`OsKeyStore`** — wraps the `keyring` crate with the
   `apple-native`, `windows-native`, and `sync-secret-service` features
   enabled. macOS uses the Keychain via Security framework. Windows
   uses Credential Manager. Linux uses Secret Service over D-Bus
   (gnome-keyring, KeePassXC, etc.).

2. **`InMemoryKeyStore`** — used by every test in the workspace. Real
   Keychain access is interactive on macOS and platform-dependent on
   Linux, so unit and integration tests use the in-memory backend
   exclusively. Real-Keychain coverage is provided by the manual smoke
   test recorded in this ADR.

### Storage layout

The workspace key:

- **Public half:** persisted on disk in `workspace.config.toml` as a
  hex-encoded 32-byte string under the `workspace_key` key.
- **Secret half:** stored in the keystore under service
  `mantis-workspace-<workspace-ulid>`, account `signing-key`.

Operator identities:

- **Public half:** persisted on disk at
  `operators/<operator-ulid>/identity.pub` (hex) plus an `OperatorProfile`
  in `operators/<operator-ulid>/profile.json`.
- **Secret half:** stored in the keystore under service
  `mantis-operator-<operator-ulid>`, account `signing-key`.

Secrets never appear on disk. The disk layout reveals public keys and
metadata only; even if the workspace directory is exfiltrated, no
signing operation is possible.

### Domain-separated signing

Every signed payload has a domain-separation prefix of the form
`Mantis-v1:<context>:` prepended before the bytes that get signed.
Contexts used in M0.1+ include:

- `Mantis-v1:tree:` for event-log Merkle tree heads (M0.2)
- `Mantis-v1:scope:` for scope manifests (M0.3)
- `Mantis-v1:engagement-authorize:` for engagement authorization (M0.4)

This prevents cross-protocol attacks: a signature over a scope manifest
cannot be replayed against a Merkle tree-head verifier.

### Public-key fingerprints

A fingerprint is the first 8 bytes (16 hex characters) of
`BLAKE3(public_key)`. Used everywhere a user-visible short name for a
key is needed.

### Open-time invariant

`Workspace::open` verifies that the secret returned by the keystore
derives a public key bit-identical to the one in `workspace.config.toml`.
A mismatch returns `WorkspaceError::KeyMismatch` and refuses to proceed.
This catches:

- A keystore entry corrupted independently of the config file.
- An attacker who substitutes the disk-stored public key without
  controlling the keystore (the daemon refuses to operate with the
  wrong key, so the attack is detected at open time).
- An accidental copy of `workspace.config.toml` between workspaces
  with different secrets.

## Alternatives considered

1. **Single PEM file with passphrase encryption.** Considered and
   rejected. Requires the operator to enter the passphrase on every
   daemon start, which breaks ambient operation (PRD §14.3 hibernating
   serverless model). Also harder to securely wipe from memory than a
   Keychain query.

2. **PRD §7.3's `workspace.key` file as the primary store.** Possible
   future addition for portability/backup. Deferred to M0.6 because
   layering it on top of the keystore-as-primary model is mechanical;
   the inverse (file-primary, keystore-as-cache) is harder to retrofit
   security for.

3. **Hardware-backed signing (Yubikey, TPM).** Mentioned in PRD §17 as
   a mitigation for high-value engagements. Out of scope for Phase 0;
   trait-based [`KeyStore`] design leaves the door open for a future
   `HardwareKeyStore` implementation without changes to call sites.

4. **No keychain integration; secrets as encrypted blobs on disk.**
   Considered for simplicity. Rejected because the encryption key has
   to live somewhere too — recursion ends only at the keychain or a
   passphrase prompt, and we already need one of those.

## Consequences

- **+** Day-to-day operation is non-interactive: macOS Keychain
  auto-unlocks at user login, so `mantis operator create` doesn't
  prompt after the first install.
- **+** Tests are deterministic and headless. `InMemoryKeyStore` lets
  the 34 unit + integration tests run on CI without touching any OS
  facility.
- **+** Migration to hardware-backed keys later is a trait
  implementation, not a refactor.
- **−** Workspace portability is reduced: moving the workspace
  directory to a new machine requires re-creating the keystore entries.
  Mitigation: M0.6 will add an exportable encrypted backup of the
  workspace key (the `workspace.key` file PRD §7.3 mentions).
- **−** Headless Linux servers without a Secret Service implementation
  (no gnome-keyring, no KeePassXC, etc.) cannot run Mantis as-is.
  Mitigation deferred: M0.6 cut-list option A2 ("Windows keychain
  fallback to age + passphrase") will also cover this case for Linux.

## Verification

- 16 unit tests in `mantis-workspace` exercise the key types, the
  in-memory keystore, and signing semantics.
- 18 integration tests exercise workspace init/open, operator
  lifecycle, doctor reports, and round-trips across save/load.
- Manual smoke test on macOS (2026-05-16):
  ```
  $ MANTIS_HOME=/tmp/probe mantis workspace init
  Workspace initialized.
    id:          01KRRVCR2C53MVG9TWVE6AS967
    fingerprint: e0f217f32561ce98
  $ mantis operator create alice
  Operator created.
    id:          01KRRVCR3RDPHPCAXAWCNTWCDK
    fingerprint: 41eb45792e38e518
  $ mantis operator list   # alice and bob shown
  $ mantis doctor          # Status: OK
  ```

  The Keychain entry `mantis-workspace-<id>` was confirmed present via
  `security find-generic-password` and cleaned up at the end of the
  test. The same flow on Linux + Windows is M0.0's CI matrix
  responsibility to confirm — currently the integration tests use
  `InMemoryKeyStore` so CI does not require a real Secret Service.
  Real-Keychain CI coverage lands in M0.6.
