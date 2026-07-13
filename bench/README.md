# chennai-bench

Benchmark harness for measuring chennai analysis quality and token cost against
a curated ground-truth vulnerability corpus.

## Quick Start

```sh
# Build the harness (from workspace root).
cargo build -p chennai-bench

# Run chennai in "audit" mode against all corpus cases.
chennai-bench run --chennai ./target/release/chennai

# Score the results and emit a rollup.
chennai-bench score --results-dir ./bench/results
```

## Subcommands

### `run`

Runs chennai against each corpus case and writes raw JSON results.

```sh
chennai-bench run \
  --corpus ./bench/corpus \
  --chennai ./target/release/chennai \
  --mode audit \
  --mode orchestrate \
  --reps 3 \
  --results-dir ./bench/results \
  --provider anthropic \
  --model claude-sonnet-4-20250514
```

Each `--mode` maps to a distinct chennai invocation (the same objective is fed to all three for a
fair comparison):

| Mode | Invocation |
|------|-----------|
| `audit` | `chennai audit <case> --json --objective "<obj>"` — deterministic fixed pipeline |
| `orchestrate` | `chennai <case> --orchestrate --json --ask "<obj>"` — LLM-driven coordinator |
| `single` | `chennai <case> --json --ask "<obj>"` — flat single-agent |

All three emit the `chennai.audit.v1` schema on stdout; token/turn totals are read from
`profile.totals` in that JSON.

Flags:
- `--corpus DIR` — Corpus root (default: `./corpus`).
- `--chennai PATH` — Path to chennai binary (default: `chennai` on PATH).
- `--mode MODE` — Benchmark mode: `audit`, `orchestrate`, or `single`. Repeatable. Default: `audit`.
- `--reps N` — Repetitions per case × mode. Default: 1.
- `--results-dir DIR` — Output directory for raw JSON results. Default: `./results`.
- `--turn-budget`, `--token-budget`, `--provider`, `--model`, `--api-key`, `--base-url`, `--effort`, `--no-thinking` — Forwarded to the chennai binary.

### `score`

Aggregates raw results against ground truth and emits `rollup.json` + `rollup.md`.

```sh
chennai-bench score --results-dir ./bench/results
```

## Corpus Format

Each corpus case lives in `corpus/<case-name>/` and contains:

1. **`case.toml`** — Metadata and ground truth:
   ```toml
   name = "sqli-java"
   lang = "java"
   source = "vendored"
   description = "SQL injection via string concatenation in JDBC query."

   [[ground_truth]]
   id = "GT-001"
   cwe = "CWE-89"
   severity = "High"
   sink_file = "src/db/QueryExecutor.java"
   sink_line = 42
   line_window = 5
   must_be_reachable = true
   ```

2. **Source files** — The actual code to be analyzed (under `src/` or any structure).

3. **`build`** (optional) — A build recipe to generate the atom file before analysis.

### Ground Truth Fields

| Field | Description |
|-------|-------------|
| `id` | Unique identifier for this GT entry. |
| `cwe` | CWE identifier (e.g. `CWE-89`, `CWE-22`). Matched via CWE-family grouping. |
| `severity` | Severity level for documentation. |
| `sink_file` | Sink file path (relative to case root). Matched by basename. |
| `sink_line` | Sink line number. |
| `line_window` | Half-open window: finding must be within `[line - window, line + window]`. Default: 5. |
| `must_be_reachable` | If true, the finding must be confirmed/reachable to count as a TP. Default: true. |

## Metrics

| Metric | Definition |
|--------|-----------|
| **Recall** | TP / GT total — fraction of ground-truth vulnerabilities found. |
| **FP Rate** | FP / reported findings — fraction of reported findings that are false positives. |
| **Tokens/Confirmed** | Total tokens consumed / number of confirmed findings. |
| **Wall Clock** | Mean elapsed seconds per case. |
| **Turns** | Mean LLM turns per case. |

### Scoring Rules

1. A finding is a **True Positive (TP)** for a ground-truth entry iff:
   - CWE family matches (coarse mapping — see `cwe_family()` in `corpus.rs`).
   - Sink file matches (basename comparison).
   - Sink line is within `line_window` of the ground-truth sink line.
   - If `must_be_reachable`, the finding must be marked confirmed/reachable.
2. Each finding satisfies at most one GT entry (greedy nearest-line tie-break).
3. Unmatched reported findings → **False Positives (FP)**.
4. Unmatched ground truth → **False Negatives (FN)**.

## CWE Family Mapping

The scorer groups CWEs into coarse families to tolerate minor CWE numbering differences:

| Range | Family |
|-------|--------|
| CWE-78, CWE-79–119 | `injection` (OS command, SQL, LDAP, XSS, etc.) |
| CWE-22–23 | `path-traversal` |
| CWE-287–306, CWE-352–400 | `auth` |
| CWE-494–502 | `dos` |
| CWE-200–220 | `info-leak` |
| CWE-787–799 | `deserialization` |

All other CWEs match literally.

## Adding a New Case

1. Create a directory: `corpus/<case-name>/`.
2. Add source files under the directory.
3. Add a `case.toml` with ground-truth entries.
4. Run: `chennai-bench run --chennai ./target/release/chennai --mode audit --reps 1`
5. Run: `chennai-bench score`

## Hold-out Discipline

The `fixtures-holdout/` directory contains cases reserved for formal evaluation.
**Do not** use these cases for development, tuning, or threshold adjustment.
See `fixtures-holdout/README.md` for the contamination guard policy.

## Project Structure

```
bench/
├── Cargo.toml
├── README.md              # This file
├── BASELINE.md            # Placeholder for funded run results
├── src/
│   ├── main.rs            # CLI: run / score subcommands
│   ├── corpus.rs          # Corpus case loading and CWE-family mapping
│   ├── scoring.rs         # Deterministic TP/FP/FN scoring
│   └── report.rs          # Rollup generation (JSON + Markdown)
├── corpus/                # Curated benchmark cases with ground truth
│   ├── sqli-java/
│   ├── path-traversal-go/
│   ├── xss-python/
│   ├── cmdi-node/
│   └── clean-rust/
├── results/               # Raw run results (JSON)
└── fixtures-holdout/      # Held-out cases (not for development)
```
