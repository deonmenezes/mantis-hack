//! Grammar-aware fuzzer (Phase 2 M2.3).
//!
//! Generates payload variants for vulnerability classes that
//! benefit from systematic mutation (XSS, SQLi, SSRF, etc.).
//! Each grammar declares a seed set and a set of mutation rules;
//! the engine produces N variants by sampling mutations against
//! seeds.
//!
//! Phase 2 M2.3 ships rule-based mutation grammars for the OWASP
//! Top 10 vuln classes Mantis already supports. Coverage-guided
//! fuzzing (track which payloads change response shape and bias
//! future samples toward them) lands in M2.3b.

use rand::rngs::SmallRng;
use rand::RngCore;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mutation {
    /// Prepend a string.
    Prefix(String),
    /// Append a string.
    Suffix(String),
    /// Substitute a substring with another.
    Replace { from: String, to: String },
    /// Wrap the input in `before...after`.
    Wrap { before: String, after: String },
    /// Base64-encode the input.
    Base64,
    /// URL-encode the input.
    UrlEncode,
}

impl Mutation {
    pub fn apply(&self, input: &str) -> String {
        match self {
            Mutation::Prefix(p) => format!("{p}{input}"),
            Mutation::Suffix(s) => format!("{input}{s}"),
            Mutation::Replace { from, to } => input.replace(from, to),
            Mutation::Wrap { before, after } => format!("{before}{input}{after}"),
            Mutation::Base64 => base64_encode(input.as_bytes()),
            Mutation::UrlEncode => url_encode(input),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grammar {
    pub vuln_class: String,
    pub seeds: Vec<String>,
    pub mutations: Vec<Mutation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variant {
    pub vuln_class: String,
    pub payload: String,
    pub provenance: VariantProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantProvenance {
    pub seed: String,
    pub mutations: Vec<Mutation>,
}

/// Generate `count` payload variants from this grammar using a
/// deterministic SmallRng seeded from `rng_seed`.
pub fn generate(grammar: &Grammar, count: usize, rng_seed: u64) -> Vec<Variant> {
    if grammar.seeds.is_empty() || count == 0 {
        return vec![];
    }
    let mut rng = SmallRng::seed_from_u64(rng_seed);
    let mut variants = Vec::with_capacity(count);
    for _ in 0..count {
        let seed_idx = (rng.next_u32() as usize) % grammar.seeds.len();
        let seed = grammar.seeds[seed_idx].clone();
        let mut payload = seed.clone();
        let mutations_to_apply = if grammar.mutations.is_empty() {
            0
        } else {
            1 + ((rng.next_u32() as usize) % grammar.mutations.len().min(3))
        };
        let mut applied = Vec::with_capacity(mutations_to_apply);
        for _ in 0..mutations_to_apply {
            let m_idx = (rng.next_u32() as usize) % grammar.mutations.len();
            let mutation = grammar.mutations[m_idx].clone();
            payload = mutation.apply(&payload);
            applied.push(mutation);
        }
        variants.push(Variant {
            vuln_class: grammar.vuln_class.clone(),
            payload,
            provenance: VariantProvenance {
                seed,
                mutations: applied,
            },
        });
    }
    variants
}

/// Built-in catalog: one grammar per vuln class Mantis supports.
pub fn builtin_grammar(vuln_class: &str) -> Option<Grammar> {
    match vuln_class {
        "xss-reflected" => Some(Grammar {
            vuln_class: "xss-reflected".into(),
            seeds: vec![
                "<script>alert(1)</script>".into(),
                "\"><svg onload=alert(1)>".into(),
                "javascript:alert(1)".into(),
                "<img src=x onerror=alert(1)>".into(),
            ],
            mutations: vec![
                Mutation::Prefix("xx".into()),
                Mutation::Suffix(">".into()),
                Mutation::Replace {
                    from: "alert".into(),
                    to: "prompt".into(),
                },
                Mutation::Wrap {
                    before: "\"".into(),
                    after: "\"".into(),
                },
                Mutation::UrlEncode,
            ],
        }),
        "sqli" => Some(Grammar {
            vuln_class: "sqli".into(),
            seeds: vec![
                "'".into(),
                "\"".into(),
                "' OR '1'='1".into(),
                "'; DROP TABLE users--".into(),
                "1 UNION SELECT NULL--".into(),
            ],
            mutations: vec![
                Mutation::Prefix(" ".into()),
                Mutation::Suffix("--".into()),
                Mutation::Replace {
                    from: " ".into(),
                    to: "/**/".into(),
                },
                Mutation::Wrap {
                    before: "(".into(),
                    after: ")".into(),
                },
                Mutation::UrlEncode,
            ],
        }),
        "ssrf" => Some(Grammar {
            vuln_class: "ssrf".into(),
            seeds: vec![
                "http://169.254.169.254/".into(),
                "http://localhost/".into(),
                "http://127.0.0.1:22/".into(),
                "file:///etc/passwd".into(),
                "gopher://127.0.0.1:6379/_INFO".into(),
            ],
            mutations: vec![
                Mutation::Replace {
                    from: "127.0.0.1".into(),
                    to: "127.1".into(),
                },
                Mutation::Replace {
                    from: "localhost".into(),
                    to: "localhost.localdomain".into(),
                },
                Mutation::UrlEncode,
            ],
        }),
        "open-redirect" => Some(Grammar {
            vuln_class: "open-redirect".into(),
            seeds: vec![
                "https://attacker.example/".into(),
                "//attacker.example/".into(),
                "\\\\attacker.example".into(),
                "https://example.com.attacker.example".into(),
            ],
            mutations: vec![
                Mutation::Prefix("/".into()),
                Mutation::UrlEncode,
                Mutation::Wrap {
                    before: "//".into(),
                    after: "".into(),
                },
            ],
        }),
        _ => None,
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len().div_ceil(3)) * 4);
    let chunks = bytes.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[((b0 & 0x03) << 4 | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((b1 & 0x0f) << 2 | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            out.push(c);
        } else {
            for b in c.to_string().bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_prefix_and_suffix() {
        assert_eq!(Mutation::Prefix("x".into()).apply("ab"), "xab");
        assert_eq!(Mutation::Suffix("y".into()).apply("ab"), "aby");
    }

    #[test]
    fn mutation_replace_and_wrap() {
        let r = Mutation::Replace {
            from: "a".into(),
            to: "z".into(),
        };
        assert_eq!(r.apply("banana"), "bznznz");
        let w = Mutation::Wrap {
            before: "(".into(),
            after: ")".into(),
        };
        assert_eq!(w.apply("x"), "(x)");
    }

    #[test]
    fn mutation_url_encode() {
        assert_eq!(Mutation::UrlEncode.apply("a b"), "a%20b");
        assert_eq!(Mutation::UrlEncode.apply("hello"), "hello");
    }

    #[test]
    fn mutation_base64() {
        assert_eq!(Mutation::Base64.apply("Man"), "TWFu");
        assert_eq!(Mutation::Base64.apply(""), "");
    }

    #[test]
    fn generate_produces_count_variants() {
        let grammar = builtin_grammar("xss-reflected").unwrap();
        let variants = generate(&grammar, 10, 0xc0ffee);
        assert_eq!(variants.len(), 10);
        for v in &variants {
            assert!(grammar.seeds.contains(&v.provenance.seed));
            assert!(!v.payload.is_empty());
            assert_eq!(v.vuln_class, "xss-reflected");
        }
    }

    #[test]
    fn generate_is_deterministic_with_same_seed() {
        let grammar = builtin_grammar("sqli").unwrap();
        let a = generate(&grammar, 5, 42);
        let b = generate(&grammar, 5, 42);
        for (av, bv) in a.iter().zip(b.iter()) {
            assert_eq!(av.payload, bv.payload);
        }
    }

    #[test]
    fn generate_differs_with_different_seed() {
        let grammar = builtin_grammar("sqli").unwrap();
        let a = generate(&grammar, 5, 42);
        let b = generate(&grammar, 5, 43);
        assert!(a
            .iter()
            .zip(b.iter())
            .any(|(av, bv)| av.payload != bv.payload));
    }

    #[test]
    fn generate_empty_grammar_yields_nothing() {
        let grammar = Grammar {
            vuln_class: "test".into(),
            seeds: vec![],
            mutations: vec![Mutation::Prefix("x".into())],
        };
        assert!(generate(&grammar, 5, 0).is_empty());
    }

    #[test]
    fn builtin_returns_some_for_known_classes() {
        for class in ["xss-reflected", "sqli", "ssrf", "open-redirect"] {
            assert!(
                builtin_grammar(class).is_some(),
                "{class} should be in catalog"
            );
        }
        assert!(builtin_grammar("unknown-class").is_none());
    }
}
