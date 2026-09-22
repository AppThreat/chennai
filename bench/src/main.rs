//! `chennai-bench`: benchmark harness for measuring chennai analysis quality
//! and token cost against a curated ground-truth corpus.
//!
//! Usage:
//!   chennai-bench run   [--corpus DIR] [--chennai PATH] [--mode MODE] [--reps N] [--results-dir DIR]
//!   chennai-bench score [--results-dir DIR] [--output-dir DIR]

mod corpus;
mod report;
mod scoring;

use clap::{Parser, Subcommand};
use corpus::CorpusCase;
use report::Rollup;
use scoring::{parse_findings_from_v1, parse_totals_from_v1, score_run, ScoreResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Benchmark harness for chennai.
#[derive(Parser, Debug)]
#[command(
    name = "chennai-bench",
    about = "Benchmark harness for chennai analysis quality"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Run chennai against each corpus case and collect raw results.
    Run {
        /// Corpus root directory (default: ./corpus).
        #[arg(long, default_value = "./corpus")]
        corpus: PathBuf,
        /// Path to chennai binary (default: chennai on PATH).
        #[arg(long, default_value = "chennai")]
        chennai: PathBuf,
        /// Mode(s) to benchmark (audit, orchestrate, single). Repeatable.
        #[arg(long, value_parser = ["audit", "orchestrate", "single"], default_values = ["audit"])]
        mode: Vec<String>,
        /// Number of repetitions per case × mode.
        #[arg(long, default_value_t = 1)]
        reps: usize,
        /// Directory to write raw results JSON (default: ./results).
        #[arg(long, default_value = "./results")]
        results_dir: PathBuf,
        /// Global turn budget override.
        #[arg(long)]
        turn_budget: Option<u64>,
        /// Global token budget override.
        #[arg(long)]
        token_budget: Option<u64>,
        /// LLM provider.
        #[arg(long)]
        provider: Option<String>,
        /// LLM model.
        #[arg(long)]
        model: Option<String>,
        /// API key (or set CHENNAI_API_KEY env).
        #[arg(long)]
        api_key: Option<String>,
        /// Base URL for the LLM API.
        #[arg(long)]
        base_url: Option<String>,
        /// Output effort level.
        #[arg(long)]
        effort: Option<String>,
        /// Omit thinking blocks.
        #[arg(long, default_value_t = false)]
        no_thinking: bool,
    },
    /// Score collected results against ground truth and emit rollup.
    Score {
        /// Directory containing raw result JSON files (default: ./results).
        #[arg(long, default_value = "./results")]
        results_dir: PathBuf,
        /// Directory to write rollup.json and rollup.md (default: same as results_dir).
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
}

/// A single raw run result, stored as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawRun {
    /// Case name.
    pub case: String,
    /// Mode (audit, orchestrate, single).
    pub mode: String,
    /// Repetition index (1-based).
    pub rep: usize,
    /// The raw chennai JSON output (if parsing succeeded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chennai_output: Option<serde_json::Value>,
    /// Wall-clock seconds for the run.
    pub wall_secs: f64,
    /// Error message if the run failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    match args.command {
        Command::Run {
            corpus,
            chennai,
            mode,
            reps,
            results_dir,
            turn_budget,
            token_budget,
            provider,
            model,
            api_key,
            base_url,
            effort,
            no_thinking,
        } => cmd_run(
            &corpus,
            &chennai,
            &mode,
            reps,
            &results_dir,
            turn_budget,
            token_budget,
            provider.as_deref(),
            model.as_deref(),
            api_key.as_deref(),
            base_url.as_deref(),
            effort.as_deref(),
            no_thinking,
        ),
        Command::Score {
            results_dir,
            output_dir,
        } => cmd_score(&results_dir, output_dir.as_deref()),
    }
}

/// Run chennai against each corpus case and collect raw results.
#[allow(clippy::too_many_arguments)]
fn cmd_run(
    corpus_root: &Path,
    chennai_bin: &Path,
    modes: &[String],
    reps: usize,
    results_dir: &Path,
    turn_budget: Option<u64>,
    token_budget: Option<u64>,
    provider: Option<&str>,
    model: Option<&str>,
    api_key: Option<&str>,
    base_url: Option<&str>,
    effort: Option<&str>,
    no_thinking: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Loading corpus from {}...", corpus_root.display());
    let cases = CorpusCase::discover_all(corpus_root);
    if cases.is_empty() {
        return Err("no corpus cases found".into());
    }
    eprintln!("Found {} corpus cases.", cases.len());

    let _ = std::fs::create_dir_all(results_dir);

    for case in &cases {
        eprintln!("\n=== Case: {} ({}) ===", case.name, case.lang);

        // Corpus cases are vendored under corpus/<case>/ with a source directory.
        // chennai resolves/generates the atom from this path for every mode.
        let case_source = corpus_root.join(&case.name);

        // If there's a build step, run it first (e.g. to fetch/prepare sources).
        if let Some(ref build) = case.build {
            eprintln!("[run] Running build: {build}");
            let build_status = std::process::Command::new("sh")
                .arg("-c")
                .arg(build)
                .current_dir(&case_source)
                .status()?;
            if !build_status.success() {
                eprintln!("[run] WARNING: build step failed for case '{}'", case.name);
                continue;
            }
        }

        // The objective is fed identically to all three modes for fairness. The
        // single/orchestrate modes require a non-empty --ask to trigger a headless
        // run, so we always supply a default when the case has none.
        let objective = case
            .objective
            .clone()
            .unwrap_or_else(|| "Perform a full security audit of this codebase.".to_string());

        for mode in modes {
            for rep in 1..=reps {
                eprintln!("[run] {} × {} × rep {} ...", case.name, mode, rep);

                // Reports go into a per-case/mode/rep dir so parallel modes don't clobber.
                let reports_dir = results_dir
                    .join("reports")
                    .join(&case.name)
                    .join(format!("{mode}_rep{rep}"));
                let _ = std::fs::create_dir_all(&reports_dir);

                // Each mode maps to a distinct chennai invocation. This is the whole
                // point of the harness — comparing orchestration shapes — so the mode
                // MUST select the invocation, not be ignored.
                let mut cmd = std::process::Command::new(chennai_bin);
                match mode.as_str() {
                    "audit" => {
                        // Deterministic fixed-pipeline subcommand (path is positional).
                        cmd.arg("audit")
                            .arg(&case_source)
                            .arg("--json")
                            .arg("--objective")
                            .arg(&objective);
                    }
                    "orchestrate" => {
                        // LLM-driven orchestrator over the flat headless path.
                        cmd.arg(&case_source)
                            .arg("--orchestrate")
                            .arg("--json")
                            .arg("--ask")
                            .arg(&objective);
                    }
                    "single" => {
                        // Flat single-agent headless path.
                        cmd.arg(&case_source)
                            .arg("--json")
                            .arg("--ask")
                            .arg(&objective);
                    }
                    other => {
                        eprintln!("[run] WARNING: unknown mode '{other}', skipping");
                        continue;
                    }
                }

                cmd.arg("--reports-dir").arg(&reports_dir);

                if let Some(turns) = turn_budget {
                    cmd.arg("--turn-budget").arg(turns.to_string());
                }
                if let Some(tokens) = token_budget {
                    cmd.arg("--token-budget").arg(tokens.to_string());
                }
                if let Some(p) = provider {
                    cmd.arg("--provider").arg(p);
                }
                if let Some(m) = model {
                    cmd.arg("--model").arg(m);
                }
                if let Some(key) = api_key {
                    cmd.arg("--api-key").arg(key);
                }
                if let Some(url) = base_url {
                    cmd.arg("--base-url").arg(url);
                }
                if let Some(e) = effort {
                    cmd.arg("--effort").arg(e);
                }
                if no_thinking {
                    cmd.arg("--no-thinking");
                }

                // Capture stdout (JSON), let stderr pass through.
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::inherit());

                let start = Instant::now();
                let result = cmd.output();
                let wall_secs = start.elapsed().as_secs_f64();

                let raw = match result {
                    Ok(output) => {
                        let chennai_output = if output.status.success() {
                            let stdout_str = String::from_utf8_lossy(&output.stdout);
                            serde_json::from_str(&stdout_str).ok()
                        } else {
                            None
                        };
                        RawRun {
                            case: case.name.clone(),
                            mode: mode.clone(),
                            rep,
                            chennai_output,
                            wall_secs,
                            error: if output.status.success() {
                                None
                            } else {
                                Some(format!("exit code {}", output.status.code().unwrap_or(-1)))
                            },
                        }
                    }
                    Err(e) => RawRun {
                        case: case.name.clone(),
                        mode: mode.clone(),
                        rep,
                        chennai_output: None,
                        wall_secs,
                        error: Some(e.to_string()),
                    },
                };

                // Write raw result.
                let filename = format!("{}_{}_rep{}.json", case.name, mode, rep);
                let path = results_dir.join(&filename);
                let json_str = serde_json::to_string_pretty(&raw)?;
                std::fs::write(&path, json_str)?;
            }
        }
    }

    eprintln!("\nAll runs complete. Results in {}", results_dir.display());
    Ok(())
}

/// Score collected results against ground truth and emit rollup.
fn cmd_score(
    results_dir: &Path,
    output_dir: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = output_dir.unwrap_or(results_dir);

    // Load corpus for ground truth.
    // The corpus directory is typically a sibling of results_dir (../corpus).
    let corpus_root = results_dir
        .parent()
        .map(|p| p.join("corpus"))
        .unwrap_or_else(|| PathBuf::from("./corpus"));
    eprintln!("Loading corpus from {}...", corpus_root.display());
    let cases: std::collections::HashMap<String, CorpusCase> =
        CorpusCase::discover_all(&corpus_root)
            .into_iter()
            .map(|c| (c.name.clone(), c))
            .collect();
    if cases.is_empty() {
        return Err("no corpus cases found".into());
    }

    // Load all raw results.
    eprintln!("Loading results from {}...", results_dir.display());
    let mut scores: Vec<ScoreResult> = Vec::new();
    let mut raw_count = 0;

    for entry in std::fs::read_dir(results_dir)?.flatten() {
        let path = entry.path();
        if !path.extension().map(|e| e == "json").unwrap_or(false) {
            continue;
        }
        // Skip rollup files.
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with("rollup") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let raw: RawRun = match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(_) => continue,
        };
        raw_count += 1;

        // Skip failed runs.
        if let Some(ref err) = raw.error {
            eprintln!("[score] Skipping {} (error: {})", raw.case, err);
            continue;
        }

        let case = match cases.get(&raw.case) {
            Some(c) => c,
            None => {
                eprintln!("[score] No ground truth for case '{}'", raw.case);
                continue;
            }
        };

        let json_val = match &raw.chennai_output {
            Some(v) => v,
            None => {
                eprintln!("[score] No chennai output for {} × {}", raw.case, raw.mode);
                continue;
            }
        };

        let findings = parse_findings_from_v1(json_val);
        let (tokens, turns, confirmed, _elapsed) = parse_totals_from_v1(json_val);

        let score = score_run(
            case,
            &raw.mode,
            &findings,
            tokens,
            turns,
            confirmed,
            raw.wall_secs,
        );
        scores.push(score);
    }

    if scores.is_empty() {
        return Err(format!(
            "no scoreable results found (loaded {} raw files, 0 had valid chennai output and matching ground truth)",
            raw_count
        ).into());
    }

    eprintln!("Scored {} results.", scores.len());

    let rollup = Rollup::from_scores(&scores);

    let _ = std::fs::create_dir_all(out_dir);

    // Write rollup.json.
    let json_path = out_dir.join("rollup.json");
    let json_str = rollup.to_json()?;
    std::fs::write(&json_path, &json_str)?;
    eprintln!("Wrote {}", json_path.display());

    // Write rollup.md.
    let md_path = out_dir.join("rollup.md");
    let md = rollup.to_markdown();
    std::fs::write(&md_path, &md)?;
    eprintln!("Wrote {}", md_path.display());

    // Print summary to stdout.
    println!("{}", md);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Args, Command};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn clap_args_parse_run() {
        let args = Args::parse_from(["chennai-bench", "run", "--corpus", "/tmp/corpus"]);
        match args.command {
            Command::Run { corpus, .. } => assert_eq!(corpus, PathBuf::from("/tmp/corpus")),
            _ => panic!("expected Run subcommand"),
        }
    }

    #[test]
    fn clap_args_parse_score() {
        let args = Args::parse_from(["chennai-bench", "score", "--results-dir", "/tmp/results"]);
        match args.command {
            Command::Score { results_dir, .. } => {
                assert_eq!(results_dir, PathBuf::from("/tmp/results"))
            }
            _ => panic!("expected Score subcommand"),
        }
    }

    #[test]
    fn clap_args_run_defaults() {
        let args = Args::parse_from(["chennai-bench", "run"]);
        match args.command {
            Command::Run { mode, reps, .. } => {
                assert_eq!(mode, vec!["audit".to_string()]);
                assert_eq!(reps, 1);
            }
            _ => panic!("expected Run subcommand"),
        }
    }
}
