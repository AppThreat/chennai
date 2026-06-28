use std::path::{Path, PathBuf};
use std::process::Command;

pub const GOLEM_REPORT_FILENAME: &str = "golem-report.json";
pub const GOLEM_DATAFLOW_FILENAME: &str = "golem-dataflow.graphml";

/// Locate the `golem` binary. Checks, in order:
/// 1. `GOLEM_CMD` environment variable
/// 2. `golem` on PATH
pub fn find_golem() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("GOLEM_CMD") {
        let pb = PathBuf::from(&path);
        if pb.is_file() {
            return Ok(pb);
        }
    }

    if let Some(path) = which("golem") {
        return Ok(path);
    }

    Err("golem CLI not found. Set GOLEM_CMD or install cdxgen-plugins-bin which bundles golem.".to_string())
}

/// Path to the golem JSON report inside `source_dir`.
pub fn golem_report_path(source_dir: &Path) -> PathBuf {
    source_dir.join(GOLEM_REPORT_FILENAME)
}

#[allow(dead_code)]
pub fn golem_dataflow_path(source_dir: &Path) -> PathBuf {
    source_dir.join(GOLEM_DATAFLOW_FILENAME)
}

/// Run golem analysis on `source_dir`, writing outputs into `out_dir`.
///
/// Invokes `golem analyze --dir <src> --dataflow all --callgraph static --format json
/// --out <report> --dataflow-graph-out <df-graphml>`. `--dataflow all` produces the
/// fullest data-flow output (summaries, nodes, edges, and slices when present); the
/// call graph is embedded in the JSON report (golem has no separate call-graph sidecar flag).
pub fn run_golem(source_dir: &Path, out_dir: &Path) -> Result<PathBuf, String> {
    let golem_bin = find_golem()?;

    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("failed to create output dir {}: {e}", out_dir.display()))?;
    let out_path = out_dir.join(GOLEM_REPORT_FILENAME);

    let df_path = out_dir.join(GOLEM_DATAFLOW_FILENAME);

    let status = Command::new(&golem_bin)
        .args([
            "analyze",
            "--dir",
            &source_dir.to_string_lossy(),
            "--dataflow",
            "all",
            "--callgraph",
            "static",
            "--format",
            "json",
            "--out",
            &out_path.to_string_lossy(),
            "--dataflow-graph-out",
            &df_path.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to execute golem: {e}"))?;

    if !status.success() {
        return Err(format!("golem exited with {status}"));
    }

    if out_path.is_file() {
        Ok(out_path)
    } else {
        Err(format!("golem completed but output file {} was not created", out_path.display()))
    }
}

fn which(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_golem_error_message() {
        let result = find_golem();
        if let Err(msg) = result {
            assert!(msg.contains("golem"))
        }
    }

    #[test]
    fn test_golem_report_path() {
        let dir = Path::new("/tmp/test-project");
        assert_eq!(golem_report_path(dir), dir.join("golem-report.json"));
        assert_eq!(golem_dataflow_path(dir), dir.join("golem-dataflow.graphml"));
    }
}
