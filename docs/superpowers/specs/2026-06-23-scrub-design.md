# scrub — Secret Redaction CLI

**Date**: 2026-06-23
**Status**: Approved design

## 1. Purpose

`scrub` is a fast, offline Rust CLI that reads text from stdin or a file, redacts
secrets (API keys, tokens, passwords, private keys, PII) using gitleaks'
detection rules, and writes the scrubbed output to stdout or a file.

It is a clean-sheet implementation based on the design patterns of
[printemps-tokyo/redact](https://github.com/printemps-tokyo/redact) (MIT)
but using gitleaks' rule engine for detection.

## 2. CLI Interface

```
scrub [OPTIONS] [FILE]

Arguments:
  [FILE]                    Input file (default: stdin)

Options:
  -o, --output <FILE>       Write redacted text here (default: stdout)
  -p, --placeholder <TEXT>  Replacement string (default: "[REDACTED]")
  -c, --check               Scan only: exit 1 if secrets found, no output
  -r, --rules <FILE>        Path to custom gitleaks.toml (default: embedded)
  -s, --stats               Print per-rule redaction counts to stderr
      --list-rules          List all compiled rule names and exit
      --no-default          Don't load embedded default rules (use with -r)

Note: `--rules` and `--no-default` interact as follows:
- Neither flag → embedded rules only
- `--rules FILE` only → embedded rules + custom rules merged
- `--rules FILE --no-default` → custom rules only (no embedded rules)
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Success (no secrets found, or output written successfully) |
| 1    | Secrets found (only in `--check` mode) |
| 2+   | Error (bad args, can't read file, regex compilation failure) |

## 3. Core Architecture

### Data flow

```
Input (stdin/file)
    │
    ▼
┌─────────────────────────────────────────┐
│  Redactor                               │
│  ┌──────────┐  ┌──────────┐            │
│  │ Rule #1  │→ │ Rule #2  │→ ...        │
│  │ regex +  │  │ regex +  │            │
│  │ entropy  │  │ entropy  │            │
│  └──────────┘  └──────────┘            │
│  Applied in order, one pass each        │
└─────────────────────────────────────────┘
    │
    ▼
Output (stdout/file) + optionally stats to stderr
```

### Key types

```rust
struct Rule {
    name: String,          // e.g. "openai-api-key"
    regex: Regex,          // compiled pattern
    entropy: Option<f64>,  // minimum Shannon entropy (optional)
}

struct Redactor {
    rules: Vec<Rule>,
    placeholder: String,
}

struct Outcome {
    text: String,           // scrubbed output
    counts: Vec<RuleCount>, // per-rule match counts
}
```

### Entropy detection

If a rule specifies `entropy > 0`, after a regex match the tool computes
Shannon entropy on the matched string. The match is only redacted if
entropy >= threshold. This prevents flagging low-entropy matches like
`"password=admin"` while catching random-generated keys.

## 4. Rules

### Source

Gitleaks' default rule set at `config/gitleaks.toml` (160+ rules covering
cloud API keys, tokens, private keys, connection strings, etc.) is copied
into the repository at `config/gitleaks.toml`.

### Embedding

The TOML file is embedded at compile time via `include_str!()` — zero
runtime file reads for the default case. A custom rules file can be loaded
at runtime with `--rules`.

### Parsing

The `toml` crate with `serde` deserializes only the fields we need:

```rust
#[derive(Deserialize)]
struct GitleaksConfig {
    rules: Vec<GitleaksRule>,
}

#[derive(Deserialize)]
struct GitleaksRule {
    id: String,
    regex: String,
    entropy: Option<f64>,
}
```

Rules without a `regex` field are skipped. Rules whose regex fails to
compile are skipped with a warning to stderr (one bad rule doesn't crash
the tool).

## 5. File layout

```
scrub/
  Cargo.toml
  config/
    gitleaks.toml          # Copied from gitleaks upstream
  src/
    main.rs                # CLI entry point (clap parse, dispatch)
    lib.rs                 # Redactor engine + rules loading + entropy
  tests/
    fixtures/
      basic.txt            # Sample inputs with known secrets
      edge.txt             # Edge cases (empty, binary, etc.)
    integration.rs         # #[test] functions invoking the binary
```

## 6. Dependencies

| Crate      | Purpose                  |
|------------|--------------------------|
| `clap`     | CLI argument parsing     |
| `regex`    | Rule pattern matching    |
| `toml`     | Gitleaks config parsing  |
| `serde`    | Deserialization for toml |
| `anyhow`   | Error handling           |

## 7. Error handling

- **Bad regex in gitleaks.toml**: skip that rule with a warning to stderr,
  continue loading the rest.
- **Unreadable input file**: print error to stderr, exit 2.
- **Unwritable output file**: print error to stderr, exit 2.
- **`--check` with `--output`**: error (mutually exclusive), exit 2.

## 8. Edge cases

- Empty input → empty output, exit 0.
- Binary input → regex engine handles gracefully (no matches), exit 0.
- No FILE argument and piped stdin → standard pipe behavior.
- `--no-default` without `--rules` → error (no rules to load), exit 2.

## 9. Testing

- **Unit tests**: On the `Redactor` core with known inputs/outputs in `lib.rs`.
- **Integration tests**: In `tests/` directory, invoke the binary on fixture
  files in `tests/fixtures/`.
- **Fixture content**: Sample text containing known secret patterns (AWS keys,
  OpenAI keys, JWT tokens, PEM private keys, credential URLs, bearer tokens).
