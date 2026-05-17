//! Publisher identity + trust.

use serde::{Deserialize, Serialize};

/// 32-byte Ed25519 public key, hex-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublisherKey(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherProfile {
    pub handle: String,
    pub display_name: String,
    pub public_keys: Vec<PublisherKey>,
    pub url: Option<String>,
    pub verified: bool,
}

impl PublisherProfile {
    pub fn new(handle: impl Into<String>) -> Self {
        Self {
            handle: handle.into(),
            display_name: String::new(),
            public_keys: vec![],
            url: None,
            verified: false,
        }
    }

    pub fn has_key(&self, hex: &str) -> bool {
        self.public_keys.iter().any(|k| k.0 == hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut p = PublisherProfile::new("alice");
        p.public_keys.push(PublisherKey("00".repeat(32)));
        p.public_keys.push(PublisherKey("ff".repeat(32)));
        let json = serde_json::to_string(&p).unwrap();
        let back: PublisherProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.public_keys.len(), 2);
        assert!(back.has_key(&"00".repeat(32)));
        assert!(!back.has_key("deadbeef"));
    }
}
