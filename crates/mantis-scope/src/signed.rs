//! Signed scope manifests.
//!
//! `SignedScope` wraps a manifest plus an Ed25519 signature over its
//! canonical bytes with domain-separation context `"scope"`. Verification
//! takes the authorizing operator's public key.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mantis_core::Signer;
use serde::{Deserialize, Serialize};

use crate::error::ScopeError;
use crate::manifest::ScopeManifest;

pub const SCOPE_SIGN_CONTEXT: &str = "scope";
pub const SIGN_DOMAIN_PREFIX: &[u8] = b"Mantis-v1:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedScope {
    pub manifest: ScopeManifest,
    #[serde(with = "crate::hex64")]
    pub signature: [u8; 64],
}

impl SignedScope {
    /// Create a signed scope by serializing `manifest` to canonical
    /// JSON and signing the domain-separated payload.
    pub fn create(manifest: ScopeManifest, signer: &dyn Signer) -> Result<Self, ScopeError> {
        let canonical = manifest.canonical_bytes()?;
        let signature = signer.sign(SCOPE_SIGN_CONTEXT, &canonical);
        Ok(Self {
            manifest,
            signature,
        })
    }

    /// Verify the signature against `verifier_public_key`. Returns the
    /// inner manifest on success.
    pub fn verify(self, verifier_public_key: &[u8; 32]) -> Result<ScopeManifest, ScopeError> {
        let vk = VerifyingKey::from_bytes(verifier_public_key)
            .map_err(|_| ScopeError::Envelope("verifier public key not on curve".into()))?;
        let canonical = self.manifest.canonical_bytes()?;
        let domain_separated = domain_separate(SCOPE_SIGN_CONTEXT, &canonical);
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&domain_separated, &sig)
            .map_err(|_| ScopeError::SignatureInvalid)?;
        Ok(self.manifest)
    }

    pub fn to_json(&self) -> Result<String, ScopeError> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub fn from_json(s: &str) -> Result<Self, ScopeError> {
        serde_json::from_str(s).map_err(Into::into)
    }
}

fn domain_separate(context: &str, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SIGN_DOMAIN_PREFIX.len() + context.len() + 1 + payload.len());
    buf.extend_from_slice(SIGN_DOMAIN_PREFIX);
    buf.extend_from_slice(context.as_bytes());
    buf.push(b':');
    buf.extend_from_slice(payload);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::BudgetEnvelope;
    use crate::host_pattern::HostPattern;
    use crate::manifest::{Protocol, ScopeRules, MANIFEST_SCHEMA_VERSION};
    use crate::port_range::PortMatcher;
    use mantis_core::{EngagementId, OperatorId};
    use ulid::Ulid;

    struct FakeSigner {
        secret: ed25519_dalek::SigningKey,
    }

    impl FakeSigner {
        fn generate() -> Self {
            let mut rng = rand_for_tests();
            Self {
                secret: ed25519_dalek::SigningKey::generate(&mut rng),
            }
        }

        fn public_key(&self) -> [u8; 32] {
            self.secret.verifying_key().to_bytes()
        }
    }

    impl Signer for FakeSigner {
        fn sign(&self, context: &str, payload: &[u8]) -> [u8; 64] {
            use ed25519_dalek::Signer as _;
            let domain_separated = domain_separate(context, payload);
            self.secret.sign(&domain_separated).to_bytes()
        }
        fn public_key_bytes(&self) -> [u8; 32] {
            self.public_key()
        }
    }

    fn rand_for_tests() -> impl rand::CryptoRng + rand::RngCore {
        rand::rngs::OsRng
    }

    fn sample_manifest() -> ScopeManifest {
        ScopeManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            engagement_id: EngagementId(Ulid::new()),
            authorized_by: OperatorId(Ulid::new()),
            expires_at_unix: 1_900_000_000,
            budget: BudgetEnvelope {
                max_requests: 1000,
                max_egress_bytes: 100_000_000,
                max_wall_clock_seconds: 3600,
                max_requests_per_second: 50,
            },
            include: ScopeRules {
                hosts: vec![HostPattern::new("api.example.com")],
                ports: vec![PortMatcher::single(443)],
                paths: vec!["/*".into()],
                protocols: vec![Protocol::Https],
            },
            exclude: ScopeRules::default(),
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let signer = FakeSigner::generate();
        let original = sample_manifest();
        let original_id = original.engagement_id;
        let signed = SignedScope::create(original, &signer).unwrap();
        let pk = signer.public_key();
        let manifest = signed.verify(&pk).unwrap();
        assert_eq!(manifest.engagement_id, original_id);
    }

    #[test]
    fn wrong_public_key_fails_verify() {
        let signer = FakeSigner::generate();
        let imposter = FakeSigner::generate();
        let signed = SignedScope::create(sample_manifest(), &signer).unwrap();
        let result = signed.verify(&imposter.public_key());
        assert!(matches!(result, Err(ScopeError::SignatureInvalid)));
    }

    #[test]
    fn tampered_manifest_fails_verify() {
        let signer = FakeSigner::generate();
        let mut signed = SignedScope::create(sample_manifest(), &signer).unwrap();
        signed.manifest.expires_at_unix = u64::MAX; // alter without re-signing
        let result = signed.verify(&signer.public_key());
        assert!(matches!(result, Err(ScopeError::SignatureInvalid)));
    }
}
