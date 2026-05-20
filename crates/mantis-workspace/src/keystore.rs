//! Cross-platform key storage.
//!
//! [`KeyStore`] is the trait every workspace operation depends on. The
//! production implementation [`OsKeyStore`] wraps the `keyring` crate
//! (macOS Keychain, Linux Secret Service, Windows Credential Manager).
//! [`InMemoryKeyStore`] is the test implementation.
//!
//! Stored secrets are hex-encoded on the way in and decoded on the way
//! out, so backends that require text-only storage (the keyring crate's
//! default) work transparently.

use std::collections::HashMap;
use std::sync::Mutex;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyStoreError {
    #[error("entry not found: {service}/{account}")]
    NotFound { service: String, account: String },

    #[error("keystore unavailable: {0}")]
    Unavailable(String),

    #[error("keyring: {0}")]
    Keyring(String),

    #[error("internal lock poisoned")]
    Poisoned,
}

pub trait KeyStore: Send + Sync {
    fn put(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeyStoreError>;
    fn get(&self, service: &str, account: &str) -> Result<Vec<u8>, KeyStoreError>;
    fn delete(&self, service: &str, account: &str) -> Result<(), KeyStoreError>;
    fn is_available(&self) -> bool;
    fn backend_name(&self) -> &'static str;
}

#[derive(Debug, Default)]
pub struct OsKeyStore;

impl OsKeyStore {
    pub const fn new() -> Self {
        Self
    }
}

impl KeyStore for OsKeyStore {
    fn put(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
        let entry = keyring::Entry::new(service, account)
            .map_err(|e| KeyStoreError::Keyring(e.to_string()))?;
        let encoded = hex::encode(secret);
        entry
            .set_password(&encoded)
            .map_err(|e| KeyStoreError::Keyring(e.to_string()))
    }

    fn get(&self, service: &str, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        let entry = keyring::Entry::new(service, account)
            .map_err(|e| KeyStoreError::Keyring(e.to_string()))?;
        let encoded = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeyStoreError::NotFound {
                service: service.to_owned(),
                account: account.to_owned(),
            },
            other => KeyStoreError::Keyring(other.to_string()),
        })?;
        hex::decode(&encoded).map_err(|e| KeyStoreError::Keyring(format!("hex decode: {e}")))
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeyStoreError> {
        let entry = keyring::Entry::new(service, account)
            .map_err(|e| KeyStoreError::Keyring(e.to_string()))?;
        entry.delete_credential().map_err(|e| match e {
            keyring::Error::NoEntry => KeyStoreError::NotFound {
                service: service.to_owned(),
                account: account.to_owned(),
            },
            other => KeyStoreError::Keyring(other.to_string()),
        })
    }

    fn is_available(&self) -> bool {
        let Ok(entry) = keyring::Entry::new("mantis-probe", "availability-check") else {
            return false;
        };
        match entry.get_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => true,
            Err(_) => false,
        }
    }

    fn backend_name(&self) -> &'static str {
        "os-keychain"
    }
}

/// A simple file-based key store that reads/writes hex-encoded secrets
/// from a directory (`<root>/<service>-<account>.hex`). Used as a
/// fallback on macOS when the OS keychain is inaccessible in dark wake.
#[derive(Debug)]
pub struct FileKeyStore {
    root: std::path::PathBuf,
}

impl FileKeyStore {
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path(&self, service: &str, account: &str) -> std::path::PathBuf {
        // Sanitize slashes/colons to avoid path traversal or invalid filenames.
        let name = format!("{}-{}", service, account).replace(['/', '\\', ':'], "_");
        self.root.join(format!("{name}.hex"))
    }
}

impl KeyStore for FileKeyStore {
    fn put(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
        std::fs::create_dir_all(&self.root)
            .map_err(|e| KeyStoreError::Unavailable(format!("create dir: {e}")))?;
        // Lock down the keystore directory on Unix so other local users
        // can't peek at workspace / operator signing keys. Best-effort:
        // if the chmod fails (rare, e.g. exotic FS) we don't bail out
        // — the file write would have failed first anyway.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700));
        }
        let encoded = hex::encode(secret);
        let path = self.path(service, account);
        std::fs::write(&path, encoded)
            .map_err(|e| KeyStoreError::Unavailable(format!("write key file: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn get(&self, service: &str, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        let path = self.path(service, account);
        let encoded = std::fs::read_to_string(&path).map_err(|_| KeyStoreError::NotFound {
            service: service.to_owned(),
            account: account.to_owned(),
        })?;
        hex::decode(encoded.trim())
            .map_err(|e| KeyStoreError::Unavailable(format!("hex decode: {e}")))
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeyStoreError> {
        std::fs::remove_file(self.path(service, account)).map_err(|_| KeyStoreError::NotFound {
            service: service.to_owned(),
            account: account.to_owned(),
        })
    }

    fn is_available(&self) -> bool {
        true
    }

    fn backend_name(&self) -> &'static str {
        "file"
    }
}

#[derive(Debug, Default)]
pub struct InMemoryKeyStore {
    inner: Mutex<HashMap<(String, String), Vec<u8>>>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for InMemoryKeyStore {
    fn put(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
        let mut guard = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        guard.insert((service.to_owned(), account.to_owned()), secret.to_vec());
        Ok(())
    }

    fn get(&self, service: &str, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        let guard = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        guard
            .get(&(service.to_owned(), account.to_owned()))
            .cloned()
            .ok_or_else(|| KeyStoreError::NotFound {
                service: service.to_owned(),
                account: account.to_owned(),
            })
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeyStoreError> {
        let mut guard = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        guard
            .remove(&(service.to_owned(), account.to_owned()))
            .map(|_| ())
            .ok_or_else(|| KeyStoreError::NotFound {
                service: service.to_owned(),
                account: account.to_owned(),
            })
    }

    fn is_available(&self) -> bool {
        true
    }

    fn backend_name(&self) -> &'static str {
        "in-memory"
    }
}

/// Returns the default keystore for this platform.
///
/// Selection (highest to lowest priority):
///   1. `MANTIS_KEYSTORE=file`     → `FileKeyStore` rooted at `<workspace_root>/keystore/`
///   2. `MANTIS_KEYSTORE=keychain` → `OsKeyStore` (macOS Keychain / Linux Secret Service / etc.)
///   3. Default                    → `FileKeyStore` (no keychain prompts)
///
/// `workspace_root` is typically `default_workspace_root()` (i.e. `~/.mantis`).
pub fn default_keystore(workspace_root: &std::path::Path) -> Box<dyn KeyStore> {
    match std::env::var("MANTIS_KEYSTORE").as_deref() {
        Ok("keychain") => Box::new(OsKeyStore::new()),
        Ok("file") | Err(_) => Box::new(FileKeyStore::new(workspace_root.join("keystore"))),
        Ok(other) => {
            eprintln!("[mantis] warn: unknown MANTIS_KEYSTORE='{other}', using file backend");
            Box::new(FileKeyStore::new(workspace_root.join("keystore")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_round_trip() {
        let ks = InMemoryKeyStore::new();
        ks.put("svc", "acct", b"secret").unwrap();
        let out = ks.get("svc", "acct").unwrap();
        assert_eq!(out, b"secret");
        ks.delete("svc", "acct").unwrap();
        assert!(ks.get("svc", "acct").is_err());
    }

    #[test]
    fn in_memory_reports_available() {
        let ks = InMemoryKeyStore::new();
        assert!(ks.is_available());
        assert_eq!(ks.backend_name(), "in-memory");
    }

    #[test]
    fn in_memory_not_found_for_missing() {
        let ks = InMemoryKeyStore::new();
        let err = ks.get("svc", "acct").unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound { .. }));
    }
}
