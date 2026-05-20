//! Build a signed scope manifest for an engagement.
//!
//! Mirrors `build_signed_scope_json` in `mantis-cli`. The daemon's
//! `Authorize` RPC accepts a JSON-serialized `SignedScope` (ADR-0003);
//! both the CLI and this MCP server construct it the same way: load
//! the operator's signing key from the OS keystore, derive
//! host/port matchers from the URL list, then sign with ed25519.
//!
//! Kept as a small standalone helper rather than imported from
//! `mantis-cli` to avoid promoting the CLI to a library dependency
//! of every other binary. If the two ever drift, lift this into a
//! shared `mantis-engagement` crate.

use anyhow::{anyhow, Context, Result};

use mantis_core::{EngagementId, Signer};
use mantis_scope::budget::BudgetEnvelope;
use mantis_scope::host_pattern::HostPattern;
use mantis_scope::manifest::{Protocol, ScopeManifest, ScopeRules};
use mantis_scope::port_range::PortMatcher;
use mantis_scope::signed::SignedScope;
use mantis_workspace::keystore::KeyStore;
use mantis_workspace::{
    default_keystore, default_workspace_root, operator_keystore_service, Keypair, Workspace,
};
use ulid::Ulid;

pub fn build_signed_scope_json(
    engagement_id: &str,
    urls: &[String],
    budget_seconds: u32,
) -> Result<String> {
    let root = default_workspace_root();
    let keystore = default_keystore(root.as_std_path());
    let workspace = Workspace::open(&root, &*keystore)
        .context("open workspace (run `mantis workspace init` first)")?;

    let operator = workspace
        .list_operators()
        .ok()
        .and_then(|ops| ops.into_iter().next())
        .ok_or_else(|| anyhow!("no operator yet — run `mantis operator create <name>` first"))?;

    let operator_secret = keystore
        .get(&operator_keystore_service(operator.id), "signing-key")
        .context("read operator signing key from keystore")?;
    let secret_arr: [u8; 32] = operator_secret
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("operator key wrong length"))?;
    let operator_keypair = Keypair::from_secret_bytes(&secret_arr);

    let hosts: std::collections::BTreeSet<String> =
        urls.iter().filter_map(|u| url_host(u)).collect();
    let host_patterns: Vec<HostPattern> = hosts.into_iter().map(HostPattern::new).collect();

    let ports: std::collections::BTreeSet<u16> = urls.iter().filter_map(|u| url_port(u)).collect();
    let port_matchers: Vec<PortMatcher> = if ports.is_empty() {
        vec![PortMatcher::single(80), PortMatcher::single(443)]
    } else {
        ports.into_iter().map(PortMatcher::single).collect()
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let manifest = ScopeManifest {
        schema_version: 1,
        engagement_id: EngagementId(
            Ulid::from_string(engagement_id).context("parse engagement id")?,
        ),
        authorized_by: operator.id,
        expires_at_unix: now + budget_seconds as u64 + 600,
        budget: BudgetEnvelope {
            max_requests: 5_000,
            max_egress_bytes: 50_000_000,
            max_wall_clock_seconds: budget_seconds as u64,
            max_requests_per_second: 50,
        },
        include: ScopeRules {
            hosts: host_patterns,
            ports: port_matchers,
            paths: vec!["/*".into()],
            protocols: vec![Protocol::Http, Protocol::Https],
        },
        exclude: ScopeRules::default(),
    };

    struct OpSigner<'a>(&'a Keypair);
    impl<'a> Signer for OpSigner<'a> {
        fn sign(&self, context: &str, payload: &[u8]) -> [u8; 64] {
            self.0.sign(context, payload).to_bytes()
        }
        fn public_key_bytes(&self) -> [u8; 32] {
            *self.0.public().as_bytes()
        }
    }
    let _ = workspace;
    let signed = SignedScope::create(manifest, &OpSigner(&operator_keypair))
        .context("sign scope manifest")?;
    Ok(serde_json::to_string(&signed)?)
}

pub fn url_port(u: &str) -> Option<u16> {
    let after_scheme = u.split_once("://")?.1;
    let authority = after_scheme.split('/').next()?;
    let (_, port) = authority.rsplit_once(':')?;
    port.parse::<u16>().ok()
}

pub fn url_host(u: &str) -> Option<String> {
    let after_scheme = u.split_once("://").map(|(_, rest)| rest).unwrap_or(u);
    let host = after_scheme
        .split('/')
        .next()?
        .split('?')
        .next()?
        .split('#')
        .next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.split(':').next().unwrap_or(host).to_string())
    }
}
