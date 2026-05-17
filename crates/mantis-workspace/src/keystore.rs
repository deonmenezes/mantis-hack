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
