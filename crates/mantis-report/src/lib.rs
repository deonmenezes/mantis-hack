//! Engagement report generator.
//!
//! Implements the full six-format suite from PRD §5.9.1:
//! Markdown, PDF, HackerOne JSON, Bugcrowd JSON, SARIF, OpenVEX.

pub mod bugcrowd;
pub mod hackerone;
pub mod openvex;
pub mod pdf;
pub mod sarif;
pub mod severity;

use mantis_claim::{Claim, ClaimState};
use serde::{Deserialize, Serialize};
use std::fmt::Write;

pub use crate::severity::{severity_for, Severity};

// Helpers used by the alternate-format modules.
pub(crate) fn pretty_class(class: &str) -> String {
    class
        .split(&['-', '.'][..])
        .map(|word| {
            let mut c = word.chars();
            match c.next() {
                Some(first) => first.to_uppercase().chain(c).collect(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub engagement_id: String,
    pub engagement_name: String,
    pub operator_name: Option<String>,
    pub generated_at_unix: u64,
    pub workspace_fingerprint: Option<String>,
}

/// A standalone inclusion-proof bundle suitable for embedding in
/// the report's Merkle appendix. Produced by the daemon from
/// `mantis-event-store::EventStore::inclusion_proof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    /// Short identifier the appendix references; typically
    /// `primitive_id` or a short claim hash.
    pub claim_ref: String,
    /// 32-byte workspace public key, hex-encoded. The verifier needs
    /// this to check the signed tree head.
    pub workspace_public_key_hex: String,
    /// `mantis_event_store::InclusionProof` serialized as JSON.
    pub proof_json: String,
}

#[derive(Debug, Clone)]
pub struct Report<'a> {
    pub metadata: ReportMetadata,
    pub claims: &'a [Claim],
    pub proofs: &'a [ProofBundle],
}

impl<'a> Report<'a> {
    pub fn new(metadata: ReportMetadata, claims: &'a [Claim]) -> Self {
        Self {
            metadata,
            claims,
            proofs: &[],
        }
    }

    pub fn with_proofs(mut self, proofs: &'a [ProofBundle]) -> Self {
        self.proofs = proofs;
        self
    }

    /// Render the report as HackerOne-style disclosure JSON.
    pub fn to_hackerone_json(&self) -> String {
        crate::hackerone::render(self)
    }

    /// Render the report as Bugcrowd VRT-style JSON.
    pub fn to_bugcrowd_json(&self) -> String {
        crate::bugcrowd::render(self)
    }

    /// Render the report as SARIF v2.1.0.
    pub fn to_sarif(&self) -> String {
        crate::sarif::render(self)
    }

    /// Render the report as an OpenVEX v0.2.0 statement bundle.
    pub fn to_openvex(&self) -> String {
        crate::openvex::render(self)
    }

    /// Render the report as a self-contained PDF/1.4 byte stream.
    pub fn to_pdf(&self) -> Vec<u8> {
        crate::pdf::render(self)
    }

    /// Render the report as Markdown. Only `Verified` claims appear in
    /// the findings section; `Rejected` and `Retained` are summarized
    /// in the appendix for transparency but are not numbered findings.
    pub fn to_markdown(&self) -> String {
        let mut out = String::with_capacity(4096);
        self.write_header(&mut out);
        let (verified, rejected, retained) = self.partition();
        self.write_summary(&mut out, verified.len(), rejected.len(), retained.len());
        self.write_findings(&mut out, &verified);
        self.write_appendix(&mut out, &rejected, &retained);
        self.write_merkle_appendix(&mut out);
        out
    }

    fn partition(&self) -> (Vec<&Claim>, Vec<&Claim>, Vec<&Claim>) {
        let mut verified = vec![];
        let mut rejected = vec![];
        let mut retained = vec![];
        for c in self.claims {
            match c.state {
                ClaimState::Verified { .. } => verified.push(c),
                ClaimState::Rejected { .. } => rejected.push(c),
                ClaimState::Retained { .. } => retained.push(c),
                ClaimState::Pending => {} // not reported until verified
            }
        }
        // Sort verified by severity (descending).
        verified.sort_by(|a, b| {
            severity_for(&b.vuln_class)
                .rank()
                .cmp(&severity_for(&a.vuln_class).rank())
        });
        (verified, rejected, retained)
    }

    fn write_header(&self, out: &mut String) {
        let _ = writeln!(out, "# Mantis Engagement Report");
        let _ = writeln!(out);
        let _ = writeln!(out, "- **Engagement:** `{}`", self.metadata.engagement_id);
        let _ = writeln!(out, "- **Name:** {}", self.metadata.engagement_name);
        if let Some(op) = &self.metadata.operator_name {
            let _ = writeln!(out, "- **Operator:** {op}");
        }
        let _ = writeln!(
            out,
            "- **Generated at:** {} (unix seconds)",
            self.metadata.generated_at_unix
        );
        if let Some(fp) = &self.metadata.workspace_fingerprint {
            let _ = writeln!(out, "- **Workspace fingerprint:** `{fp}`");
        }
        let _ = writeln!(out);
    }

    fn write_summary(&self, out: &mut String, verified: usize, rejected: usize, retained: usize) {
        let _ = writeln!(out, "## Summary");
        let _ = writeln!(out);
        let _ = writeln!(out, "- **Verified findings:** {verified}");
        let _ = writeln!(out, "- **Rejected by verifier:** {rejected}");
        let _ = writeln!(out, "- **Retained (verifier inconclusive):** {retained}");
        let _ = writeln!(out);
    }

    fn write_findings(&self, out: &mut String, verified: &[&Claim]) {
        let _ = writeln!(out, "## Findings");
        let _ = writeln!(out);
        if verified.is_empty() {
            let _ = writeln!(out, "_No verified findings in this engagement._");
            let _ = writeln!(out);
            return;
        }
        for (idx, claim) in verified.iter().enumerate() {
            let n = idx + 1;
            let sev = severity_for(&claim.vuln_class);
            let _ = writeln!(
                out,
                "### Finding {n}: {} on {}",
                pretty_class(&claim.vuln_class),
                claim.surface.url()
            );
            let _ = writeln!(out);
            let _ = writeln!(out, "- **Vulnerability class:** `{}`", claim.vuln_class);
            let _ = writeln!(out, "- **Primitive:** `{}`", claim.primitive_id);
            let _ = writeln!(out, "- **Severity:** {sev}");
            if let ClaimState::Verified { verifier_id } = &claim.state {
                let _ = writeln!(out, "- **Verified by:** `{verifier_id}`");
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "**Evidence**");
            let _ = writeln!(out);
            for ev in &claim.evidence {
                let _ = writeln!(out, "- `{}`: {}", ev.kind, ev.detail);
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "**Reproducer (cURL)**");
            let _ = writeln!(out);
            let _ = writeln!(out, "```bash");
            let _ = writeln!(out, "{}", claim.reproducer.curl);
            let _ = writeln!(out, "```");
            let _ = writeln!(out);
            let _ = writeln!(out, "**Reproducer (raw HTTP)**");
            let _ = writeln!(out);
            let _ = writeln!(out, "```http");
            let _ = writeln!(out, "{}", claim.reproducer.raw_http);
            let _ = writeln!(out, "```");
            if let Some(py) = &claim.reproducer.python {
                let _ = writeln!(out);
                let _ = writeln!(out, "**Reproducer (Python)**");
                let _ = writeln!(out);
                let _ = writeln!(out, "```python");
                let _ = writeln!(out, "{py}");
                let _ = writeln!(out, "```");
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "---");
            let _ = writeln!(out);
        }
    }

    fn write_appendix(&self, out: &mut String, rejected: &[&Claim], retained: &[&Claim]) {
        if rejected.is_empty() && retained.is_empty() {
            return;
        }
        let _ = writeln!(out, "## Appendix: claims not reported");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "These claims were produced by primitives but did not survive independent verification. Recorded here for transparency; not reportable per [ADR-0012](./adr-0012-claim-verification.md)."
        );
        let _ = writeln!(out);
        if !rejected.is_empty() {
            let _ = writeln!(out, "### Rejected by verifier ({})", rejected.len());
            let _ = writeln!(out);
            for c in rejected {
                if let ClaimState::Rejected { reason } = &c.state {
                    let _ = writeln!(
                        out,
                        "- `{}` on `{}` — {reason}",
                        c.primitive_id,
                        c.surface.url()
                    );
                }
            }
            let _ = writeln!(out);
        }
        if !retained.is_empty() {
            let _ = writeln!(
                out,
                "### Retained (verifier inconclusive, {})",
                retained.len()
            );
            let _ = writeln!(out);
            for c in retained {
                if let ClaimState::Retained { reason } = &c.state {
                    let _ = writeln!(
                        out,
                        "- `{}` on `{}` — {reason}",
                        c.primitive_id,
                        c.surface.url()
                    );
                }
            }
            let _ = writeln!(out);
        }
    }
}

impl<'a> Report<'a> {
    fn write_merkle_appendix(&self, out: &mut String) {
        if self.proofs.is_empty() {
            return;
        }
        let _ = writeln!(out, "## Appendix: Merkle inclusion proofs");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Each proof below is an excerpt of the engagement event log, signed by the workspace key. Verify with the standalone `mantis-verify` binary:"
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "```");
        let _ = writeln!(out, "mantis-verify --proof <file.json> --public-key <hex>");
        let _ = writeln!(out, "```");
        let _ = writeln!(out);
        if let Some(first) = self.proofs.first() {
            let _ = writeln!(
                out,
                "- **Workspace public key (hex):** `{}`",
                first.workspace_public_key_hex
            );
            let _ = writeln!(out);
        }
        for (idx, bundle) in self.proofs.iter().enumerate() {
            let _ = writeln!(out, "### Proof {} — `{}`", idx + 1, bundle.claim_ref);
            let _ = writeln!(out);
            let _ = writeln!(out, "```json");
            // Re-pretty-print so the appendix is paste-friendly.
            let pretty = match serde_json::from_str::<serde_json::Value>(&bundle.proof_json) {
                Ok(v) => {
                    serde_json::to_string_pretty(&v).unwrap_or_else(|_| bundle.proof_json.clone())
                }
                Err(_) => bundle.proof_json.clone(),
            };
            let _ = writeln!(out, "{pretty}");
            let _ = writeln!(out, "```");
            let _ = writeln!(out);
        }
    }
}
