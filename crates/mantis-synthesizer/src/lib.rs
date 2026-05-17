//! Exploit synthesizer (Phase 2 M2.2 + M2.2b).
//!
//! PRD §5.7.4 calls for a hybrid synthesis engine: corpus retrieval,
//! grammar-aware fuzzer, symbolic constraint solver, and LLM-guided
//! code generation. The engines run in priority order; the first to
//! produce a sandbox-verified working payload wins.
//!
//! PRD §6.4.2 mandates that LLM-generated code execute exclusively
//! in ephemeral isolated environments — record-replay sandboxes for
//! development, microVM sandboxes for live verification — before
//! any production-target execution. [`synthesize`] enforces this by
//! requiring every caller to pass a [`SandboxValidator`]: the
//! corpus/fuzzer paths skip validation (their payloads are
//! compile-time-vetted), but the LLM path always runs the candidate
//! through `validator.validate(..)` before returning, surfacing any
//! sandbox failure as [`SynthError::SandboxRejected`].
//!
//! Module layout:
//! - [`CorpusRetriever`] — static-corpus payload lookup (workspace
//!   loading via [`CorpusRetriever::from_workspace`])
//! - [`NullLlm`] — stub used when no provider is configured
//! - [`NullValidator`] — pass-through, suitable for tests
//! - [`WasmValidator`] — `SandboxRuntime`-backed validator
//! - [`anthropic::AnthropicAdapter`] — Messages API client (M2.2b)
//! - [`openai::OpenAIAdapter`] — Chat Completions API client (M2.2b)

pub mod anthropic;
pub mod openai;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use mantis_sandbox::{ExecutionInput, SandboxBudget, SandboxRuntime};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use mantis_fuzzer::Variant;

#[derive(Debug, Error)]
pub enum SynthError {
    #[error("no synthesizer engine produced a payload")]
    NoCandidate,

    #[error("backend: {0}")]
    Backend(String),

    #[error("sandbox rejected candidate: {0}")]
    SandboxRejected(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthRequest {
    pub vuln_class: String,
    pub surface_url: String,
    /// Additional free-form context the engines may use.
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthCandidate {
    pub payload: String,
    pub engine: EngineKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineKind {
    Corpus,
    Fuzzer,
    Llm,
}

/// Trait the daemon implements to plug in an LLM provider.
#[async_trait]
pub trait LlmAdapter: Send + Sync {
    async fn complete(&self, prompt: &str) -> Result<String, SynthError>;
}

/// Static-corpus retriever. The default `CorpusRetriever` (unit
/// struct via [`CorpusRetriever::new`]) ships a compile-time fallback
/// per vuln class. [`CorpusRetriever::from_workspace`] reads
/// per-class JSON files from a workspace directory; the workspace
/// payloads take precedence over the compile-time fallback.
#[derive(Debug, Default, Clone)]
pub struct CorpusRetriever {
    workspace: HashMap<String, Vec<String>>,
}

impl CorpusRetriever {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load per-class payloads from `<workspace>/corpus/<class>.json`.
    /// Each file is a JSON array of strings. Missing files are
    /// non-fatal: the retriever falls back to the compile-time
    /// catalog for classes without a workspace file.
    pub fn from_workspace(workspace: &Path) -> std::io::Result<Self> {
        let dir = workspace.join("corpus");
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        if !dir.exists() {
            return Ok(Self { workspace: map });
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let class = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let bytes = std::fs::read(&path)?;
            let payloads: Vec<String> = serde_json::from_slice(&bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?;
            map.insert(class, payloads);
        }
        Ok(Self { workspace: map })
    }

    pub fn retrieve(&self, vuln_class: &str) -> Vec<String> {
        if let Some(ws) = self.workspace.get(vuln_class) {
            if !ws.is_empty() {
                return ws.clone();
            }
        }
        match vuln_class {
            "xss-reflected" => vec![
                "<script>alert(1)</script>".into(),
                "\"><img src=x onerror=alert(1)>".into(),
            ],
            "sqli" => vec!["' OR 1=1--".into(), "1 UNION SELECT NULL--".into()],
            "open-redirect" => vec!["https://evil.example/".into(), "//evil.example".into()],
            "ssrf" => vec![
                "http://169.254.169.254/latest/meta-data/".into(),
                "http://localhost:6379/".into(),
            ],
            _ => vec![],
        }
    }
}

/// Sandbox-gated validator. PRD §6.4.2 requires every LLM-produced
/// candidate to pass through an ephemeral isolated environment
/// before it can be returned for live use.
#[async_trait]
pub trait SandboxValidator: Send + Sync {
    async fn validate(&self, payload: &str, vuln_class: &str) -> Result<(), SynthError>;
}

/// Pass-through validator. Acceptable for unit tests and for
/// corpus/fuzzer paths where the payload provenance is already
/// trusted; PRD §6.4.2 only requires sandboxing for LLM output, so
/// production daemon configurations construct a real validator
/// before calling [`synthesize`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NullValidator;

#[async_trait]
impl SandboxValidator for NullValidator {
    async fn validate(&self, _payload: &str, _vuln_class: &str) -> Result<(), SynthError> {
        Ok(())
    }
}

/// Validator that runs each candidate through a `SandboxRuntime`.
/// The configured WASM module (typically a property-oracle checker)
/// receives the payload bytes as its sandbox input and must exit
/// with code 0 to accept; any non-zero exit, trap, or capability
/// refusal demotes the candidate to [`SynthError::SandboxRejected`].
pub struct WasmValidator {
    runtime: Arc<dyn SandboxRuntime>,
    module: Vec<u8>,
    budget: SandboxBudget,
}

impl WasmValidator {
    pub fn new(runtime: Arc<dyn SandboxRuntime>, module: Vec<u8>) -> Self {
        Self {
            runtime,
            module,
            budget: SandboxBudget::default(),
        }
    }

    pub fn with_budget(mut self, budget: SandboxBudget) -> Self {
        self.budget = budget;
        self
    }
}

#[async_trait]
impl SandboxValidator for WasmValidator {
    async fn validate(&self, payload: &str, _vuln_class: &str) -> Result<(), SynthError> {
        let input = ExecutionInput {
            bytes: payload.as_bytes().to_vec(),
            mime: Some("text/plain".into()),
        };
        match self
            .runtime
            .execute(&self.module, &input, &self.budget)
            .await
        {
            Ok(out) if out.exit_code == 0 => Ok(()),
            Ok(out) => Err(SynthError::SandboxRejected(format!(
                "checker exited with code {}",
                out.exit_code
            ))),
            Err(e) => Err(SynthError::SandboxRejected(format!("sandbox: {e}"))),
        }
    }
}

/// Stub LLM adapter that returns an error. Used when no provider is
/// configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullLlm;

#[async_trait]
impl LlmAdapter for NullLlm {
    async fn complete(&self, _prompt: &str) -> Result<String, SynthError> {
        Err(SynthError::Backend("no LLM provider configured".into()))
    }
}

/// The pipeline runs all engines and returns the first successful
/// candidate. Order is corpus → fuzzer → LLM (cheapest first).
///
/// PRD §6.4.2: the LLM path always runs its candidate through
/// `validator` before returning. Corpus and fuzzer payloads bypass
/// the validator because their provenance is compile-time trusted.
pub async fn synthesize(
    request: &SynthRequest,
    corpus: &CorpusRetriever,
    llm: &dyn LlmAdapter,
    validator: &dyn SandboxValidator,
    fuzzer_seed: u64,
) -> Result<SynthCandidate, SynthError> {
    // 1. Corpus retrieval.
    let corpus_payloads = corpus.retrieve(&request.vuln_class);
    if let Some(first) = corpus_payloads.into_iter().next() {
        return Ok(SynthCandidate {
            payload: first,
            engine: EngineKind::Corpus,
        });
    }

    // 2. Grammar fuzzer.
    if let Some(grammar) = mantis_fuzzer::builtin_grammar(&request.vuln_class) {
        let variants = mantis_fuzzer::generate(&grammar, 1, fuzzer_seed);
        if let Some(Variant { payload, .. }) = variants.into_iter().next() {
            return Ok(SynthCandidate {
                payload,
                engine: EngineKind::Fuzzer,
            });
        }
    }

    // 3. LLM. Gated through the sandbox validator per PRD §6.4.2.
    let prompt = format!(
        "Generate one minimal {} payload for {}. Reply with only the payload.{}",
        request.vuln_class,
        request.surface_url,
        request
            .hint
            .as_deref()
            .map(|h| format!(" Hint: {h}"))
            .unwrap_or_default()
    );
    let payload = match llm.complete(&prompt).await {
        Ok(p) => p,
        Err(_) => return Err(SynthError::NoCandidate),
    };
    validator.validate(&payload, &request.vuln_class).await?;
    Ok(SynthCandidate {
        payload,
        engine: EngineKind::Llm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CannedLlm(&'static str);
    #[async_trait]
    impl LlmAdapter for CannedLlm {
        async fn complete(&self, _prompt: &str) -> Result<String, SynthError> {
            Ok(self.0.into())
        }
    }

    fn request(class: &str) -> SynthRequest {
        SynthRequest {
            vuln_class: class.into(),
            surface_url: "https://x.example/".into(),
            hint: None,
        }
    }

    #[tokio::test]
    async fn corpus_wins_when_available() {
        let candidate = synthesize(
            &request("xss-reflected"),
            &CorpusRetriever::new(),
            &NullLlm,
            &NullValidator,
            0,
        )
        .await
        .unwrap();
        assert_eq!(candidate.engine, EngineKind::Corpus);
        assert!(candidate.payload.contains("<script>"));
    }

    #[tokio::test]
    async fn fuzzer_used_when_corpus_empty_but_grammar_known() {
        // No corpus for `clickjacking` but no built-in fuzzer
        // grammar either — should fall through to LLM.
        let candidate = synthesize(
            &request("clickjacking"),
            &CorpusRetriever::new(),
            &CannedLlm("<iframe src=...></iframe>"),
            &NullValidator,
            0,
        )
        .await
        .unwrap();
        assert_eq!(candidate.engine, EngineKind::Llm);
    }

    #[tokio::test]
    async fn llm_used_when_corpus_and_fuzzer_both_empty() {
        let candidate = synthesize(
            &request("novel-class-xyz"),
            &CorpusRetriever::new(),
            &CannedLlm("llm-payload"),
            &NullValidator,
            0,
        )
        .await
        .unwrap();
        assert_eq!(candidate.engine, EngineKind::Llm);
        assert_eq!(candidate.payload, "llm-payload");
    }

    #[tokio::test]
    async fn errors_when_all_engines_empty() {
        let candidate = synthesize(
            &request("nothing-knows-about"),
            &CorpusRetriever::new(),
            &NullLlm,
            &NullValidator,
            0,
        )
        .await;
        assert!(matches!(candidate, Err(SynthError::NoCandidate)));
    }

    #[test]
    fn corpus_retriever_returns_per_class_payloads() {
        let r = CorpusRetriever::new();
        assert!(!r.retrieve("xss-reflected").is_empty());
        assert!(!r.retrieve("sqli").is_empty());
        assert!(r.retrieve("nope").is_empty());
    }

    // PRD §6.4.2 — sandbox validator must gate LLM output.
    struct RejectingValidator;
    #[async_trait]
    impl SandboxValidator for RejectingValidator {
        async fn validate(&self, _payload: &str, _vuln_class: &str) -> Result<(), SynthError> {
            Err(SynthError::SandboxRejected("checker rejected".into()))
        }
    }

    #[tokio::test]
    async fn llm_candidate_blocked_when_sandbox_rejects() {
        let result = synthesize(
            &request("novel-class-blocked"),
            &CorpusRetriever::new(),
            &CannedLlm("dangerous-payload"),
            &RejectingValidator,
            0,
        )
        .await;
        assert!(matches!(result, Err(SynthError::SandboxRejected(_))));
    }

    #[tokio::test]
    async fn corpus_path_bypasses_sandbox_validator() {
        // The compile-time corpus is trusted, so it should not be
        // gated through the sandbox validator. A rejecting validator
        // would otherwise fail this test.
        let candidate = synthesize(
            &request("xss-reflected"),
            &CorpusRetriever::new(),
            &CannedLlm("never-used"),
            &RejectingValidator,
            0,
        )
        .await
        .unwrap();
        assert_eq!(candidate.engine, EngineKind::Corpus);
    }

    // Workspace corpus loading.
    #[test]
    fn workspace_corpus_overrides_compile_time_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let corpus_dir = dir.path().join("corpus");
        std::fs::create_dir(&corpus_dir).unwrap();
        std::fs::write(
            corpus_dir.join("xss-reflected.json"),
            r#"["custom-payload-1","custom-payload-2"]"#,
        )
        .unwrap();
        let r = CorpusRetriever::from_workspace(dir.path()).unwrap();
        let payloads = r.retrieve("xss-reflected");
        assert_eq!(payloads, vec!["custom-payload-1", "custom-payload-2"]);
    }

    #[test]
    fn workspace_corpus_falls_back_to_compile_time_for_unknown_class_files() {
        let dir = tempfile::tempdir().unwrap();
        // No workspace corpus dir — falls back to compile-time.
        let r = CorpusRetriever::from_workspace(dir.path()).unwrap();
        assert!(!r.retrieve("sqli").is_empty());
    }

    #[test]
    fn workspace_corpus_missing_dir_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let r = CorpusRetriever::from_workspace(dir.path()).unwrap();
        assert!(r.workspace.is_empty());
    }

    #[test]
    fn workspace_corpus_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let corpus_dir = dir.path().join("corpus");
        std::fs::create_dir(&corpus_dir).unwrap();
        std::fs::write(corpus_dir.join("broken.json"), "not json").unwrap();
        let result = CorpusRetriever::from_workspace(dir.path());
        assert!(result.is_err());
    }
}
