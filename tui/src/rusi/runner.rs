use std::path::{Path, PathBuf};
use std::process::Command;

pub const RUSI_REPORT_FILENAME: &str = "rusi-report.json";
pub const RUSI_CALLGRAPH_FILENAME: &str = "callgraph.graphml";
pub const RUSI_DATAFLOW_FILENAME: &str = "dataflow.graphml";

pub fn find_rusi() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("RUSI_CMD") {
        let pb = PathBuf::from(&path);
        if pb.is_file() {
            return Ok(pb);
        }
    }

    if let Some(path) = which("rusi") {
        return Ok(path);
    }

    Err("rusi CLI not found. Set RUSI_CMD or install cdxgen-plugins-bin which bundles rusi.".to_string())
}

pub fn rusi_report_path(source_dir: &Path) -> PathBuf {
    source_dir.join(RUSI_REPORT_FILENAME)
}

#[allow(dead_code)]
pub fn rusi_callgraph_path(source_dir: &Path) -> PathBuf {
    source_dir.join(RUSI_CALLGRAPH_FILENAME)
}

#[allow(dead_code)]
pub fn rusi_dataflow_path(source_dir: &Path) -> PathBuf {
    source_dir.join(RUSI_DATAFLOW_FILENAME)
}

/// Run rusi against `source_dir`, writing the report and graph sidecars into `out_dir`.
pub fn run_rusi(source_dir: &Path, out_dir: &Path) -> Result<PathBuf, String> {
    let rusi_bin = find_rusi()?;

    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("failed to create output dir {}: {e}", out_dir.display()))?;
    let out_path = out_dir.join(RUSI_REPORT_FILENAME);

    let cg_path = out_dir.join(RUSI_CALLGRAPH_FILENAME);
    let df_path = out_dir.join(RUSI_DATAFLOW_FILENAME);

    let status = Command::new(&rusi_bin)
        .args([
            "analyze",
            "--dir",
            &source_dir.to_string_lossy(),
            "--backend",
            "stable",
            "--callgraph",
            "static",
            "--dataflow",
            "security",
            "--out",
            &out_path.to_string_lossy(),
            "--callgraph-out",
            &cg_path.to_string_lossy(),
            "--callgraph-export-format",
            "graphml",
            "--dataflow-out",
            &df_path.to_string_lossy(),
            "--dataflow-export-format",
            "graphml",
        ])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to execute rusi: {e}"))?;

    if !status.success() {
        return Err(format!("rusi exited with {status}"));
    }

    if out_path.is_file() {
        Ok(out_path)
    } else {
        Err(format!("rusi completed but output file {} was not created", out_path.display()))
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
