# Benchmark Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a benchmark suite to caviarder with throughput measurement, per-rule timing, and a confusion matrix against the Samsung/CredData dataset.

**Architecture:** Three benchmark components: two Criterion benchmarks (`throughput`, `per_rule`) measuring performance, and a standalone binary (`cav-bench-confusion`) computing precision/recall/F1 against ground-truth data. A shell script automates dataset download.

**Tech Stack:** Rust, criterion v4 with html_reports, csv crate for CredData parsing, the existing Redactor/Rule types from `caviarder::*`.

---

## File Structure

```
Cargo.toml                          # MODIFY: add criterion dev-dep + bench/bin targets
.gitignore                          # MODIFY: ignore bench-data/ _creddata/
scripts/setup-bench-data.sh         # CREATE: download and prepare CredData
benches/throughput.rs               # CREATE: criterion throughput benchmark
benches/per_rule.rs                 # CREATE: criterion per-rule benchmark
confusion/main.rs                   # CREATE: confusion matrix binary
```

---

### Task 1: Update Cargo.toml

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add criterion dev-dependency and bench/bin targets**

```toml
[dev-dependencies]
criterion = { version = "4", features = ["html_reports"] }
csv = "1"

[[bench]]
name = "throughput"
harness = false

[[bench]]
name = "per_rule"
harness = false

[[bin]]
name = "cav-bench-confusion"
path = "confusion/main.rs"
```

- [ ] **Step 2: Verify the changes parse correctly**

Run: `cargo check 2>&1 | tail -5`
Expected: `Finished ...` (warnings about unused code in the new files are fine — they don't exist yet)

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "chore: add criterion dev-dep and bench/confusion targets"
```

---

### Task 2: Update .gitignore

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Add dataset directories**

```gitignore
/target/

# Benchmark dataset
/bench-data/
/_creddata/
```

- [ ] **Step 2: Verify gitignore works**

Run: `git check-ignore bench-data/ _creddata/`
Expected: both paths listed

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore: ignore benchmark dataset directories"
```

---

### Task 3: Create dataset download script

**Files:**
- Create: `scripts/setup-bench-data.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BENCH_DATA="$PROJECT_DIR/bench-data"

if [ -d "$BENCH_DATA" ] && [ -f "$BENCH_DATA/META_README.md" ]; then
    echo "✓ CredData already downloaded in $BENCH_DATA"
    echo "  (delete it and re-run to refresh)"
    exit 0
fi

echo "==> Cloning Samsung/CredData..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
git clone --depth 1 https://github.com/Samsung/CredData.git "$TMP_DIR/creddata"

echo "==> Installing Python deps..."
cd "$TMP_DIR/creddata"
pip3 install -q -r requirements.txt 2>/dev/null || true

echo "==> Downloading dataset..."
python3 download_data.py

echo "==> Moving dataset to $BENCH_DATA..."
mkdir -p "$BENCH_DATA"
mv data "$BENCH_DATA/data"
mv meta "$BENCH_DATA/meta"
cp README.md "$BENCH_DATA/META_README.md"

echo ""
echo "✓ CredData ready in $BENCH_DATA"
echo "  Meta files:    $(find "$BENCH_DATA/meta" -name '*.csv' | wc -l)"
echo "  Data files:    $(find "$BENCH_DATA/data" -type f | wc -l)"
```

- [ ] **Step 2: Make executable and test**

Run: `chmod +x scripts/setup-bench-data.sh`

Run: `./scripts/setup-bench-data.sh`
Expected: downloads CredData into `bench-data/` or prints "✓ CredData already downloaded"

- [ ] **Step 3: Commit**

```bash
git add scripts/setup-bench-data.sh
git commit -m "feat: add script to download Samsung/CredData benchmark dataset"
```

---

### Task 4: Create throughput benchmark

**Files:**
- Create: `benches/throughput.rs`

- [ ] **Step 1: Write the benchmark**

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use caviarder::{Redactor, Rule};
use regex::Regex;
use std::time::Duration;

/// Generate a text buffer of `target_size` bytes containing a mix of clean lines
/// and embedded secrets at the given `density` (0.0 – 1.0).
fn generate_input(target_size: usize, density: f64) -> String {
    let clean_line = "    host = localhost\n    port = 8080\n    debug = false\n";
    let secret_line = "    password = sk-proj-ABC123def456GHI789jkl012MNO345pqr678\n";
    let mut buf = String::with_capacity(target_size);
    while buf.len() < target_size {
        if buf.len() as f64 % 1024.0 / 1024.0 < density {
            buf.push_str(secret_line);
        } else {
            buf.push_str(clean_line);
        }
    }
    buf
}

fn build_redactor() -> Redactor {
    let rule = Rule {
        id: "bench-key".into(),
        regex: Regex::new(r"sk-proj-[A-Za-z0-9]{20,}").unwrap(),
        entropy: None,
    };
    Redactor::new(vec![rule], "[CAVIARDER]")
}

fn bench_throughput(c: &mut Criterion) {
    let redactor = build_redactor();
    let input = generate_input(10 * 1024 * 1024, 0.05); // 10 MB, 5% secrets

    let mut group = c.benchmark_group("throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);
    group.throughput(criterion::Throughput::Bytes(input.len() as u64));
    group.bench_function("10_mb_5pct", |b| {
        b.iter(|| redactor.redact(black_box(&input)))
    });
    group.finish();
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --bench throughput 2>&1 | tail -5`
Expected: `Finished ...`

- [ ] **Step 3: Run a quick smoke test**

Run: `cargo bench --bench throughput -- --sample-size 2 --measurement-time 1 --warm-up-time 0 2>&1 | tail -10`
Expected: benchmark executes and reports throughput in MiB/s

- [ ] **Step 4: Commit**

```bash
git add benches/throughput.rs
git commit -m "feat: add Criterion throughput benchmark"
```

---

### Task 5: Create per-rule benchmark

**Files:**
- Create: `benches/per_rule.rs`

- [ ] **Step 1: Write the benchmark**

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use caviarder::{Redactor, Rule};
use regex::Regex;
use std::time::Duration;

/// Build a redactor with a single rule matching the given pattern,
/// and benchmark it against a matching input string.
fn bench_single_rule(c: &mut Criterion, rule_id: &str, pattern: &str, input: &str) {
    let rule = Rule {
        id: rule_id.into(),
        regex: Regex::new(pattern).unwrap(),
        entropy: None,
    };
    let redactor = Redactor::new(vec![rule], "[CAVIARDER]");

    let mut group = c.benchmark_group(format!("rule/{}", rule_id));
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);
    group.bench_function("single_match", |b| {
        b.iter(|| redactor.redact(black_box(input)))
    });
    group.finish();
}

fn bench_rules(c: &mut Criterion) {
    // AWS Access Key
    bench_single_rule(
        c,
        "aws-key",
        r"AKIA[A-Z0-9]{16}",
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    );

    // Generic API Key (key=... pattern)
    bench_single_rule(
        c,
        "generic-api-key",
        r"(?i)[\w.-]{0,50}?(?:key|secret|token)[\s'""]{0,3}(?:=|:)[\x60'""\s=]{0,5}([\w.=-]{10,150})",
        "api_key = sk-proj-abc123DEF456ghi789jkl012mnopqrXYZ",
    );

    // GitHub Token
    bench_single_rule(
        c,
        "github-token",
        r"\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255})\b",
        "token = ghp_abcdef1234567890abcdef1234567890abcdef12",
    );

    // Password field
    bench_single_rule(
        c,
        "password",
        r"(?i)password[\s'""]{0,3}(?:=|:)[\x60'""\s]{0,5}([^\s'""]{8,})",
        "password = MyS3cureP@ssw0rd!",
    );

    // Slack Token (benchmark uses pattern, input is NOT a real token)
    bench_single_rule(
        c,
        "slack-token",
        r"(xox[bp])-[0-9]{10,13}-[a-zA-Z0-9\-]{20,}",
        "slack_token = xoxb-SLACK-BENCH-TOKEN-NOT-REAL-00000",
    );

    // JWT / eyJ...
    bench_single_rule(
        c,
        "jwt",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "token = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doeR3Jkf4kHwFJdb9o3Ml6A6zVn5W8xYQ2SsKJmNpQo",
    );

    // RSA Private Key block (multi-line)
    bench_single_rule(
        c,
        "private-key",
        r"-----BEGIN\s?(RSA|EC|DSA|OPENSSH|PGP)?\s?PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..." ,
    );
}

criterion_group!(benches, bench_rules);
criterion_main!(benches);
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --bench per_rule 2>&1 | tail -5`
Expected: `Finished ...`

- [ ] **Step 3: Run a quick smoke test**

Run: `cargo bench --bench per_rule -- --sample-size 2 --measurement-time 1 --warm-up-time 0 2>&1 | tail -15`
Expected: benchmark executes and reports timing per rule

- [ ] **Step 4: Commit**

```bash
git add benches/per_rule.rs
git commit -m "feat: add per-rule Criterion benchmark"
```

---

### Task 6: Create confusion matrix binary

**Files:**
- Create: `confusion/main.rs`

- [ ] **Step 1: Write the binary**

```rust
use caviarder::rules;
use caviarder::{Redactor, Rule};
use std::fs;
use std::path::Path;

const BENCH_DATA: &str = "bench-data";
const META_DIR: &str = "bench-data/meta";

struct Entry {
    file_path: String,
    line_start: usize,
    ground_truth: String,
}

fn load_metadata() -> Vec<Entry> {
    let mut entries = Vec::new();
    let meta_dir = Path::new(META_DIR);

    if !meta_dir.is_dir() {
        eprintln!("ERROR: metadata directory not found at '{META_DIR}'");
        eprintln!("Run `./scripts/setup-bench-data.sh` first to download the dataset.");
        std::process::exit(0);
    }

    // Read all CSV files in the meta directory
    for dir_entry in fs::read_dir(meta_dir).expect("failed to read meta dir") {
        let dir_entry = dir_entry.expect("failed to read dir entry");
        let path = dir_entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("csv") {
            continue;
        }

        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_path(&path)
            .expect("failed to open metadata CSV");

        for result in reader.records() {
            let record = result.expect("invalid CSV record");
            // Columns: Id,FileID,Domain,RepoName,FilePath,LineStart,LineEnd,GroundTruth,...
            // FilePath (index 4) is relative like "data/<RepoID>/src/<FileID>.ext"
            entries.push(Entry {
                file_path: record.get(4).unwrap_or("").to_string(),
                line_start: record.get(5).unwrap_or("1").parse().unwrap_or(1),
                ground_truth: record.get(7).unwrap_or("F").to_string(),
            });
        }
    }

    entries
}

fn main() {
    let entries = load_metadata();
    eprintln!("Loaded {} metadata entries", entries.len());

    // Load all gitleaks rules (same as `cav` uses)
    let all_rules = match rules::load_embedded() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: failed to load embedded rules: {e}");
            std::process::exit(1);
        }
    };
    let custom_rules = rules::load_embedded_custom().unwrap_or_default();

    let mut full_rules: Vec<Rule> = all_rules;
    full_rules.extend(custom_rules);

    if full_rules.is_empty() {
        eprintln!("ERROR: no rules loaded");
        std::process::exit(1);
    }

    eprintln!("Loaded {} rules", full_rules.len());

    let redactor = Redactor::new(full_rules, "[CAVIARDER]");

    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut fn_ = 0usize;
    let mut tn = 0usize;
    let mut skipped = 0usize;

    for entry in &entries {
        let file_path = Path::new(BENCH_DATA).join("data").join(&entry.file_path);

        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        let line = match content.lines().nth(entry.line_start - 1) {
            Some(l) => l,
            None => {
                skipped += 1;
                continue;
            }
        };

        let outcome = redactor.redact(line);
        let was_redacted = outcome.text != line;

        let is_true = entry.ground_truth.trim() == "T";

        match (was_redacted, is_true) {
            (true, true) => tp += 1,
            (true, false) => fp += 1,
            (false, true) => fn_ += 1,
            (false, false) => tn += 1,
        }
    }

    let total = tp + fp + fn_ + tn;
    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };
    let recall = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    let accuracy = if total > 0 {
        (tp + tn) as f64 / total as f64
    } else {
        0.0
    };

    println!();
    println!("=== Confusion Matrix (CredData) ===");
    println!(" Instances:  {total}");
    println!(" True:       {} ({:.1}%)", tp + fn_, 100.0 * (tp + fn_) as f64 / total as f64);
    println!(" False:      {} ({:.1}%)", fp + tn, 100.0 * (fp + tn) as f64 / total as f64);
    println!(" Skipped:    {skipped}");
    println!();
    println!("                Predicted");
    println!("                redacted  clean");
    println!(" Actual True   {:>8} {:>6}", tp, fn_);
    println!("        False  {:>8} {:>6}", fp, tn);
    println!();
    println!(" Metrics:");
    println!("   Precision:  {:.1}%", precision * 100.0);
    println!("   Recall:     {:.1}%", recall * 100.0);
    println!("   F1:         {:.3}", f1);
    println!("   Accuracy:   {:.1}%", accuracy * 100.0);
    println!();
    println!(" Baseline (gitleaks on CredData):");
    println!("   Precision:  52.6%");
    println!("   Recall:     24.4%");
    println!("   F1:         0.334");
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --bin cav-bench-confusion 2>&1 | tail -5`
Expected: `Finished ...`

- [ ] **Step 3: Run a quick test (dataset required)**

Run: `cargo run --bin cav-bench-confusion 2>&1 | head -20`
Expected: loads metadata, processes entries, prints confusion matrix (or error if dataset not downloaded)

- [ ] **Step 4: Commit**

```bash
git add confusion/main.rs
git commit -m "feat: add confusion matrix binary against CredData"
```

---

### Task 7: Verify full build

**Files:**
- No new files

- [ ] **Step 1: Run full cargo check**

Run: `cargo check --all-targets 2>&1`
Expected: `Finished ...` with no errors

- [ ] **Step 2: Run existing tests**

Run: `cargo test 2>&1`
Expected: all 16+ tests pass

- [ ] **Step 3: Commit any final adjustments**

```bash
git add -A
git commit -m "chore: finalize benchmark suite setup" || true
git push
```

---

## Self-Review Checklist

- [ ] Spec coverage: throughput benchmark (Task 4), per-rule benchmark (Task 5), confusion matrix (Task 6), dataset script (Task 3), Cargo.toml (Task 1), .gitignore (Task 2)
- [ ] No placeholders: every step contains complete code
- [ ] Type consistency: all types used (Redactor, Rule, Regex) are from `caviarder` crate or `regex`/`criterion`/`csv` — already available
