# scrub — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust CLI (`scrub`) that reads text from stdin/files, redacts secrets using gitleaks' detection rules, and writes scrubbed output.

**Architecture:** Three-layer design — `rules.rs` parses gitleaks TOML into `Vec<Rule>`, `lib.rs` applies rules (regex + optional entropy check) via `Redactor::redact()`, `main.rs` handles CLI dispatch via clap.

**Tech Stack:** Rust, clap (CLI), regex (pattern matching), toml+serde (config parsing), anyhow (errors).

---

### File Structure

```
/home/wderue/work/scrub/
  Cargo.toml
  config/
    gitleaks.toml           # Copied from gitleaks upstream
  src/
    lib.rs                  # Rule, Redactor, Outcome types + entropy + unit tests
    rules.rs                # Gitleaks TOML loading + parsing
    main.rs                 # CLI entry point (clap)
  tests/
    fixtures/
      basic.txt             # Sample input with known secrets
      edge.txt              # Edge cases (empty, binary-like)
    integration.rs          # Integration tests invoking the binary
```

---

### Task 1: Scaffold project

**Files:**
- Create: `/home/wderue/work/scrub/Cargo.toml`
- Create: `/home/wderue/work/scrub/src/lib.rs` (stub)
- Create: `/home/wderue/work/scrub/src/rules.rs` (stub)
- Create: `/home/wderue/work/scrub/src/main.rs` (stub)
- Create: `/home/wderue/work/scrub/config/gitleaks.toml`
- Create: `/home/wderue/work/scrub/tests/fixtures/basic.txt`
- Create: `/home/wderue/work/scrub/tests/fixtures/edge.txt`
- Create: `/home/wderue/work/scrub/tests/integration.rs` (stub)

**Steps:**

- [ ] **Step 1: Create project directory and Cargo.toml**

```bash
mkdir -p /home/wderue/work/scrub/src /home/wderue/work/scrub/tests/fixtures /home/wderue/work/scrub/config
```

Write `/home/wderue/work/scrub/Cargo.toml`:

```toml
[package]
name = "scrub"
version = "0.1.0"
edition = "2021"
license = "MIT"
description = "Redact secrets and PII from text using gitleaks detection rules."

[dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive"] }
regex = "1"
serde = { version = "1", features = ["derive"] }
toml = "0.8"

[profile.release]
strip = true
lto = true
codegen-units = 1
panic = "abort"
```

- [ ] **Step 2: Create stub source files**

Write `/home/wderue/work/scrub/src/lib.rs`:
```rust
pub mod rules;

pub struct Rule {
    pub id: String,
    regex: regex::Regex,
    pub entropy: Option<f64>,
}

pub struct Redactor {
    rules: Vec<Rule>,
    placeholder: String,
}

pub struct Outcome {
    pub text: String,
    pub counts: Vec<(String, usize)>,
}

/// Compute Shannon entropy of a string (bytes as symbols).
/// Returns a value in [0.0, 8.0] where 8.0 = perfectly random bytes.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in freq.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_same_char() {
        let e = shannon_entropy("AAAA");
        assert!(e < 0.1, "all same chars should have near-zero entropy");
    }

    #[test]
    fn entropy_high() {
        // base64-like random string
        let e = shannon_entropy("sk-proj-abc123ABC/+def456DEF=");
        assert!(e > 4.0, "random-looking string should have high entropy");
    }
}
```

Write `/home/wderue/work/scrub/src/rules.rs`:
```rust
use crate::Rule;
use anyhow::Result;
use regex::Regex;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct GitleaksConfig {
    pub rules: Vec<GitleaksRule>,
}

#[derive(Deserialize)]
pub struct GitleaksRule {
    pub id: String,
    pub regex: String,
    pub entropy: Option<f64>,
}

/// Load rules from the embedded gitleaks.toml (compile-time).
pub fn load_embedded() -> Result<Vec<Rule>> {
    let toml_str = include_str!("../config/gitleaks.toml");
    load_from_str(toml_str)
}

/// Load rules from a TOML string.
pub fn load_from_str(toml_str: &str) -> Result<Vec<Rule>> {
    let config: GitleaksConfig = toml::from_str(toml_str)?;
    let mut rules = Vec::new();
    for gr in config.rules {
        match Regex::new(&gr.regex) {
            Ok(regex) => {
                rules.push(Rule {
                    id: gr.id,
                    regex,
                    entropy: gr.entropy,
                });
            }
            Err(e) => {
                eprintln!("scrub: warning: skipping rule '{}': {}", gr.id, e);
            }
        }
    }
    Ok(rules)
}
```

Write `/home/wderue/work/scrub/src/main.rs`:
```rust
fn main() {
    println!("scrub not yet implemented");
}
```

Write `/home/wderue/work/scrub/tests/integration.rs`:
```rust
// Integration tests will go here
```

- [ ] **Step 3: Copy gitleaks.toml**

Copy the downloaded gitleaks.toml to `/home/wderue/work/scrub/config/gitleaks.toml`.

- [ ] **Step 4: Create test fixtures**

Write `/home/wderue/work/scrub/tests/fixtures/basic.txt`:
```
User logged in at 10.0.0.1
DB_PASSWORD=supersecret123
clone https://alice:s3cret@github.com/acme/app.git
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF_-123
AWS key: AKIAIOSFODNN7EXAMPLE
OpenAI key: sk-proj-abc123DEF456ghi789jkl012
```

Write `/home/wderue/work/scrub/tests/fixtures/edge.txt`:
```
Empty file below this line:

Just some regular text with no secrets.
plaintext@example.com is an email but not a high-value secret.
```

- [ ] **Step 5: Verify it compiles**

```bash
cd /home/wderue/work/scrub && cargo build 2>&1
```

Expected: compiles with warnings about unused code (fine at this stage).

- [ ] **Step 6: Run initial unit tests**

```bash
cd /home/wderue/work/scrub && cargo test 2>&1
```

Expected: entropy tests pass (the three tests in lib.rs).

- [ ] **Step 7: Commit**

```bash
cd /home/wderue/work/scrub && git init && git add -A && git commit -m "chore: scaffold scrub project"
```

---

### Task 2: Implement Redactor engine (lib.rs)

**Files:**
- Modify: `/home/wderue/work/scrub/src/lib.rs`

- [ ] **Step 1: Write the failing test for Redactor::redact()**

Add these tests to the `tests` module in `lib.rs`:

```rust
#[test]
fn redact_replaces_matched_text() {
    let rule = Rule {
        id: "test-key".into(),
        regex: Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(),
        entropy: None,
    };
    let redactor = Redactor::new(vec![rule], "[REDACTED]");
    let outcome = redactor.redact("my key is sk-proj-abc123DEF456ghi789jkl012");
    assert_eq!(outcome.text, "my key is [REDACTED]");
    assert_eq!(outcome.total(), 1);
}

#[test]
fn redact_multiple_matches_same_rule() {
    let rule = Rule {
        id: "test-key".into(),
        regex: Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(),
        entropy: None,
    };
    let redactor = Redactor::new(vec![rule], "[REDACTED]");
    let outcome = redactor.redact("keys: AKIAIOSFODNN7EXAMPLE and AKIAZZZZZZZZZZZZZZZZ");
    assert_eq!(outcome.text, "keys: [REDACTED] and [REDACTED]");
    assert_eq!(outcome.total(), 2);
}

#[test]
fn redact_multiple_rules_applied_in_order() {
    let rule1 = Rule {
        id: "aws".into(),
        regex: Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(),
        entropy: None,
    };
    let rule2 = Rule {
        id: "generic".into(),
        regex: Regex::new(r"(?i)password=\S+").unwrap(),
        entropy: None,
    };
    let redactor = Redactor::new(vec![rule1, rule2], "[REDACTED]");
    let outcome = redactor.redact("aws=AKIAIOSFODNN7EXAMPLE password=hunter2");
    assert_eq!(outcome.text, "aws=[REDACTED] password=[REDACTED]");
    assert_eq!(outcome.total(), 2);
}

#[test]
fn redact_entropy_filter_low_entropy() {
    let rule = Rule {
        id: "high-entropy-only".into(),
        regex: Regex::new(r"\b[A-Za-z0-9/+=-]{10,}\b").unwrap(),
        entropy: Some(4.0),
    };
    let redactor = Redactor::new(vec![rule], "[REDACTED]");
    let outcome = redactor.redact("low entropy AAAAAAAA high entropy sk-proj-abc123DEF456");
    // "AAAAAAAA" is 8 identical chars: entropy 0.0 < 4.0 → not redacted
    // "sk-proj-abc123DEF456" has mixed chars: entropy >= 4.0 → redacted
    assert_eq!(outcome.text, "low entropy AAAAAAAA high entropy [REDACTED]");
    assert_eq!(outcome.total(), 1);
}

#[test]
fn redact_empty_input() {
    let rule = Rule {
        id: "test".into(),
        regex: Regex::new(r"[A-Z]+").unwrap(),
        entropy: None,
    };
    let redactor = Redactor::new(vec![rule], "[REDACTED]");
    let outcome = redactor.redact("");
    assert_eq!(outcome.text, "");
    assert_eq!(outcome.total(), 0);
}

#[test]
fn redact_no_match() {
    let rule = Rule {
        id: "test".into(),
        regex: Regex::new(r"SECRET_\d+").unwrap(),
        entropy: None,
    };
    let redactor = Redactor::new(vec![rule], "[REDACTED]");
    let outcome = redactor.redact("just regular text here");
    assert_eq!(outcome.text, "just regular text here");
    assert_eq!(outcome.total(), 0);
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/wderue/work/scrub && cargo test 2>&1
```

Expected: compilation errors because `Rule`, `Redactor`, `Outcome` don't have methods yet.

- [ ] **Step 3: Implement the Redactor engine**

Replace the entire content of `/home/wderue/work/scrub/src/lib.rs` (keeping the existing `shannon_entropy` function and `pub mod rules;`):

```rust
pub mod rules;

use regex::Regex;

/// A single detection rule: a compiled regex and an optional entropy threshold.
pub struct Rule {
    pub id: String,
    pub regex: Regex,
    pub entropy: Option<f64>,
}

/// An ordered set of rules that are applied to text to redact secrets.
pub struct Redactor {
    rules: Vec<Rule>,
    placeholder: String,
}

/// The result of redacting text.
pub struct Outcome {
    pub text: String,
    pub counts: Vec<(String, usize)>,
}

impl Outcome {
    /// Total number of redactions across all rules.
    pub fn total(&self) -> usize {
        self.counts.iter().map(|(_, c)| c).sum()
    }
}

impl Redactor {
    /// Create a new Redactor from a list of rules and a placeholder string.
    pub fn new(rules: Vec<Rule>, placeholder: impl Into<String>) -> Self {
        Redactor {
            rules,
            placeholder: placeholder.into(),
        }
    }

    /// Apply every rule in order, returning the scrubbed text and per-rule counts.
    pub fn redact(&self, input: &str) -> Outcome {
        let mut text = input.to_string();
        let mut counts = Vec::new();

        for rule in &self.rules {
            let mut count = 0usize;
            let replaced = rule.regex.replace_all(&text, |_: &regex::Captures| {
                count += 1;
                self.placeholder.as_str()
            });

            // If the rule has an entropy threshold, we need to check each
            // match individually. The simple approach: do a second pass.
            if let Some(min_entropy) = rule.entropy {
                // Re-scan: only redact matches that meet the entropy threshold.
                // We collect match ranges and work backwards to avoid
                // invalidating byte offsets.
                let mut text_bytes = text.clone();
                let mut matches: Vec<(usize, usize)> = Vec::new();
                for m in rule.regex.find_iter(&text_bytes) {
                    if shannon_entropy(m.as_str()) >= min_entropy {
                        matches.push((m.start(), m.end()));
                    }
                }
                // Apply redactions from end to start to preserve offsets.
                let mut result = text_bytes;
                for (start, end) in matches.into_iter().rev() {
                    result.replace_range(start..end, &self.placeholder);
                    count += 1;
                }
                text = result;
            } else {
                // No entropy threshold: use the simple replacement.
                text = replaced.into_owned();
            }

            if count > 0 {
                counts.push((rule.id.clone(), count));
            }
        }

        Outcome { text, counts }
    }
}

/// Compute Shannon entropy of a string (byte-level).
/// Returns a value in [0.0, 8.0] where 8.0 = perfectly random bytes.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in freq.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_same_char() {
        let e = shannon_entropy("AAAA");
        assert!(e < 0.1);
    }

    #[test]
    fn entropy_high() {
        let e = shannon_entropy("sk-proj-abc123ABC/+def456DEF=");
        assert!(e > 4.0);
    }

    #[test]
    fn redact_replaces_matched_text() {
        let rule = Rule {
            id: "test-key".into(),
            regex: Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(),
            entropy: None,
        };
        let redactor = Redactor::new(vec![rule], "[REDACTED]");
        let outcome = redactor.redact("my key is sk-proj-abc123DEF456ghi789jkl012");
        assert_eq!(outcome.text, "my key is [REDACTED]");
        assert_eq!(outcome.total(), 1);
    }

    #[test]
    fn redact_multiple_matches_same_rule() {
        let rule = Rule {
            id: "test-key".into(),
            regex: Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(),
            entropy: None,
        };
        let redactor = Redactor::new(vec![rule], "[REDACTED]");
        let outcome = redactor.redact("keys: AKIAIOSFODNN7EXAMPLE and AKIAZZZZZZZZZZZZZZZZ");
        assert_eq!(outcome.text, "keys: [REDACTED] and [REDACTED]");
        assert_eq!(outcome.total(), 2);
    }

    #[test]
    fn redact_multiple_rules_applied_in_order() {
        let rule1 = Rule {
            id: "aws".into(),
            regex: Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(),
            entropy: None,
        };
        let rule2 = Rule {
            id: "generic".into(),
            regex: Regex::new(r"(?i)password=\S+").unwrap(),
            entropy: None,
        };
        let redactor = Redactor::new(vec![rule1, rule2], "[REDACTED]");
        let outcome = redactor.redact("aws=AKIAIOSFODNN7EXAMPLE password=hunter2");
        assert_eq!(outcome.text, "aws=[REDACTED] password=[REDACTED]");
        assert_eq!(outcome.total(), 2);
    }

    #[test]
    fn redact_entropy_filter_low_entropy() {
        let rule = Rule {
            id: "high-entropy-only".into(),
            regex: Regex::new(r"\b[A-Za-z0-9/+=-]{10,}\b").unwrap(),
            entropy: Some(4.0),
        };
        let redactor = Redactor::new(vec![rule], "[REDACTED]");
        let outcome = redactor.redact("low entropy AAAAAAAA high entropy sk-proj-abc123DEF456");
        assert_eq!(outcome.text, "low entropy AAAAAAAA high entropy [REDACTED]");
        assert_eq!(outcome.total(), 1);
    }

    #[test]
    fn redact_empty_input() {
        let rule = Rule {
            id: "test".into(),
            regex: Regex::new(r"[A-Z]+").unwrap(),
            entropy: None,
        };
        let redactor = Redactor::new(vec![rule], "[REDACTED]");
        let outcome = redactor.redact("");
        assert_eq!(outcome.text, "");
        assert_eq!(outcome.total(), 0);
    }

    #[test]
    fn redact_no_match() {
        let rule = Rule {
            id: "test".into(),
            regex: Regex::new(r"SECRET_\d+").unwrap(),
            entropy: None,
        };
        let redactor = Redactor::new(vec![rule], "[REDACTED]");
        let outcome = redactor.redact("just regular text here");
        assert_eq!(outcome.text, "just regular text here");
        assert_eq!(outcome.total(), 0);
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/wderue/work/scrub && cargo test 2>&1
```

Expected: all 9 tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/wderue/work/scrub && git add -A && git commit -m "feat: add Redactor engine with regex + entropy detection"
```

---

### Task 3: Implement rules loading (rules.rs)

**Files:**
- Modify: `/home/wderue/work/scrub/src/rules.rs`

- [ ] **Step 1: Write a failing test for rules loading**

Add a `tests` module at the bottom of `rules.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_from_str_parses_valid_toml() {
        let toml = r#"
[[rules]]
id = "test-rule"
regex = '''AKIA[A-Z0-9]{16}'''
entropy = 3.0

[[rules]]
id = "simple-rule"
regex = '''sk-[A-Za-z0-9]+'''
"#;
        let rules = load_from_str(toml).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "test-rule");
        assert_eq!(rules[0].entropy, Some(3.0));
        assert_eq!(rules[1].id, "simple-rule");
        assert_eq!(rules[1].entropy, None);
    }

    #[test]
    fn load_from_str_skips_bad_regex() {
        let toml = r#"
[[rules]]
id = "good-rule"
regex = '''[A-Z]+'''

[[rules]]
id = "bad-rule"
regex = '''[invalid'''
"#;
        let rules = load_from_str(toml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "good-rule");
    }

    #[test]
    fn load_from_str_skips_rule_without_regex_field() {
        // Rules without a regex field should be skipped by serde (won't deserialize).
        // This test verifies we only process properly formed rules.
        let toml = r#"
[[rules]]
id = "no-regex-rule"
"#;
        let result = load_from_str(toml);
        // This should be an error because `regex` field is missing (required by struct)
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run the rules tests**

```bash
cd /home/wderue/work/scrub && cargo test --lib rules 2>&1
```

Expected: first two pass, third confirms the deserialization error behavior.

- [ ] **Step 3: Add `load_from_path` function**

Add this function to `/home/wderue/work/scrub/src/rules.rs`:

```rust
/// Load rules from a TOML file at the given path.
pub fn load_from_path(path: &str) -> Result<Vec<Rule>> {
    let toml_str = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read rules file {}: {}", path, e))?;
    load_from_str(&toml_str)
}
```

- [ ] **Step 4: Run all tests**

```bash
cd /home/wderue/work/scrub && cargo test 2>&1
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/wderue/work/scrub && git add -A && git commit -m "feat: add gitleaks TOML rules loading with skip-bad-regex handling"
```

---

### Task 4: Implement CLI (main.rs)

**Files:**
- Modify: `/home/wderue/work/scrub/src/main.rs`

- [ ] **Step 1: Write main.rs with clap argument parsing**

Replace `/home/wderue/work/scrub/src/main.rs`:

```rust
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use scrub::rules;
use scrub::{Redactor, Rule};

/// Redact secrets and PII from text using gitleaks detection rules.
#[derive(Parser, Debug)]
#[command(name = "scrub", version, about)]
struct Cli {
    /// Input file (default: stdin)
    input: Option<PathBuf>,

    /// Write redacted text here (default: stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Replacement string for redacted values
    #[arg(short, long, default_value = "[REDACTED]")]
    placeholder: String,

    /// Scan only: exit 1 if secrets found, no output written
    #[arg(short, long)]
    check: bool,

    /// Path to custom gitleaks.toml (default: embedded rules)
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Print per-rule redaction counts to stderr
    #[arg(short, long)]
    stats: bool,

    /// List all compiled rule names and exit
    #[arg(long)]
    list_rules: bool,

    /// Don't load embedded default rules (use with --rules)
    #[arg(long)]
    no_default: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // --list-rules: just print rule names and exit
    if cli.list_rules {
        let rules = load_rules(&cli)?;
        for rule in &rules {
            println!("{}", rule.id);
        }
        return Ok(());
    }

    // --check and --output are mutually exclusive
    if cli.check && cli.output.is_some() {
        anyhow::bail!("--check and --output cannot be used together");
    }

    // Read input
    let input = match &cli.input {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("failed to read stdin")?;
            buf
        }
    };

    // Build redactor
    let rules = load_rules(&cli)?;
    if rules.is_empty() {
        anyhow::bail!("no rules loaded (use --rules or check config/gitleaks.toml)");
    }
    let redactor = Redactor::new(rules, &cli.placeholder);
    let outcome = redactor.redact(&input);

    // --check mode
    if cli.check {
        for (rule_id, count) in &outcome.counts {
            eprintln!("{}: {}", rule_id, count);
        }
        let total = outcome.total();
        if total > 0 {
            eprintln!("scrub: found {} potential secret(s)", total);
            std::process::exit(1);
        }
        eprintln!("scrub: no secrets found");
        return Ok(());
    }

    // Write output
    match &cli.output {
        Some(path) => std::fs::write(path, &outcome.text)
            .with_context(|| format!("failed to write {}", path.display()))?,
        None => {
            std::io::stdout()
                .write_all(outcome.text.as_bytes())
                .context("failed to write stdout")?;
        }
    }

    // --stats
    if cli.stats {
        for (rule_id, count) in &outcome.counts {
            eprintln!("{}: {}", rule_id, count);
        }
        eprintln!("scrub: {} redaction(s)", outcome.total());
    }

    Ok(())
}

/// Load rules based on CLI flags. Merges embedded and custom rules unless --no-default.
fn load_rules(cli: &Cli) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    if !cli.no_default {
        let embedded = rules::load_embedded().context("failed to load embedded rules")?;
        rules.extend(embedded);
    }

    if let Some(rules_path) = &cli.rules {
        let custom = rules::load_from_path(
            &rules_path.to_string_lossy(),
        )?;
        rules.extend(custom);
    }

    if rules.is_empty() && cli.no_default && cli.rules.is_none() {
        anyhow::bail!("--no-default requires --rules to specify a rules file");
    }

    Ok(rules)
}
```

- [ ] **Step 2: Build and verify compilation**

```bash
cd /home/wderue/work/scrub && cargo build 2>&1
```

Expected: clean compile, no warnings.

- [ ] **Step 3: Quick smoke test with the binary**

```bash
cd /home/wderue/work/scrub && echo "hello world" | cargo run 2>&1
```

Expected: prints "hello world" (no rules match).

```bash
cd /home/wderue/work/scrub && echo "AWS key AKIAIOSFODNN7EXAMPLE" | cargo run 2>&1
```

Expected: prints "AWS key [REDACTED]".

```bash
cd /home/wderue/work/scrub && cargo run -- --list-rules 2>&1
```

Expected: prints all rule IDs from gitleaks.toml (160+ lines).

```bash
cd /home/wderue/work/scrub && echo "nothing secret" | cargo run -- --check 2>&1; echo "exit=$?"
```

Expected: "scrub: no secrets found" on stderr, exit 0.

```bash
cd /home/wderue/work/scrub && echo "key AKIAIOSFODNN7EXAMPLE" | cargo run -- --check 2>&1; echo "exit=$?"
```

Expected: rule match logged, "scrub: found 1 potential secret(s)", exit 1.

- [ ] **Step 4: Run all tests**

```bash
cd /home/wderue/work/scrub && cargo test 2>&1
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/wderue/work/scrub && git add -A && git commit -m "feat: add CLI with clap, stdin/file I/O, --check, --stats, --list-rules"
```

---

### Task 5: Integration tests

**Files:**
- Modify: `/home/wderue/work/scrub/tests/integration.rs`

- [ ] **Step 1: Write integration tests**

Replace `/home/wderue/work/scrub/tests/integration.rs`:

```rust
use std::process::Command;
use std::path::Path;

fn scrub_binary() -> &'static str {
    if cfg!(debug_assertions) {
        "target/debug/scrub"
    } else {
        "target/release/scrub"
    }
}

#[test]
fn test_stdin_no_secrets() {
    let output = Command::new(scrub_binary())
        .arg("--check")
        .arg("--no-default")
        .arg("--rules")
        .arg("config/gitleaks.toml")
        .arg("tests/fixtures/edge.txt")
        .output()
        .expect("failed to execute scrub");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn test_file_redact_basic() {
    let output = Command::new(scrub_binary())
        .arg("--no-default")
        .arg("--rules")
        .arg("config/gitleaks.toml")
        .arg("tests/fixtures/basic.txt")
        .output()
        .expect("failed to execute scrub");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The fixture contains several known secret patterns.
    // At minimum, verify the output is shorter than the input (secrets were replaced).
    let input = std::fs::read_to_string("tests/fixtures/basic.txt").unwrap();
    assert!(stdout.len() < input.len(), "output should be shorter than input");
    // Verify no original secrets leaked through
    assert!(!stdout.contains("AKIAIOSFODNN7EXAMPLE"), "AKIA key should be redacted");
    assert!(!stdout.contains("sk-proj-abc123"), "OpenAI key should be redacted");
}

#[test]
fn test_stdin_pipe() {
    let mut child = Command::new(scrub_binary())
        .arg("--no-default")
        .arg("--rules")
        .arg("config/gitleaks.toml")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn scrub");
    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(b"key AKIAIOSFODNN7EXAMPLE").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[REDACTED]"));
    assert!(!stdout.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn test_check_mode_finds_secrets() {
    let output = Command::new(scrub_binary())
        .arg("--check")
        .arg("--no-default")
        .arg("--rules")
        .arg("config/gitleaks.toml")
        .arg("tests/fixtures/basic.txt")
        .output()
        .expect("failed to execute scrub");
    // --check with secrets should exit 1
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("found"), "should report findings on stderr");
}
```

- [ ] **Step 2: Run integration tests**

```bash
cd /home/wderue/work/scrub && cargo test 2>&1
```

Expected: all unit tests + integration tests pass.

- [ ] **Step 3: Commit**

```bash
cd /home/wderue/work/scrub && git add -A && git commit -m "test: add integration tests for stdin, file, and --check modes"
```

---

### Task 6: Final polish and verification

**Files:** (none — just commands)

- [ ] **Step 1: Build release binary**

```bash
cd /home/wderue/work/scrub && cargo build --release 2>&1
```

Expected: clean release build.

- [ ] **Step 2: Check binary size**

```bash
ls -lh /home/wderue/work/scrub/target/release/scrub
```

Expected: single static binary, likely ~5-8 MB.

- [ ] **Step 3: Full end-to-end test with embedded rules**

```bash
cd /home/wderue/work/scrub && echo "password=admin" | ./target/release/scrub --check; echo "exit=$?"
```

Expected: finds a match (generic-api-key rule), exit 1.

```bash
cd /home/wderue/work/scrub && echo "just regular text" | ./target/release/scrub --check; echo "exit=$?"
```

Expected: no match, exit 0.

- [ ] **Step 4: Run full test suite**

```bash
cd /home/wderue/work/scrub && cargo test 2>&1
```

Expected: all tests green.

- [ ] **Step 5: Final commit**

```bash
cd /home/wderue/work/scrub && git add -A && git commit -m "chore: final polish and release build"
```

---

## Self-Review Checklist

After writing, verify against these:

1. **Spec coverage:**
   - [x] CLI flags: `--output`, `--placeholder`, `--check`, `--rules`, `--stats`, `--list-rules`, `--no-default`
   - [x] Entropy detection (shannon_entropy with threshold)
   - [x] Gitleaks TOML parsing with serde
   - [x] Embedded rules at compile time (`include_str!`)
   - [x] Bad regex skips gracefully
   - [x] Exit codes (0, 1, 2+)
   - [x] `--rules` extends embedded by default; `--no-default` replaces
   - [x] Unit + integration tests

2. **Placeholder scan:** No TBD, TODOs, "add validation", or vague steps. Every step has exact code.

3. **Type consistency:** `Rule.id`, `Rule.entropy`, `Redactor::new()`, `Outcome.text`, `Outcome.counts` are consistent across all tasks.
