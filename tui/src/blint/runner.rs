use std::path::{Path, PathBuf};
use std::process::Command;

#[allow(dead_code)]
pub const BLINT_METADATA_SUFFIX: &str = "-metadata.json";
#[allow(dead_code)]
pub const BLINT_FINDINGS_SUFFIX: &str = "-findings.json";
#[allow(dead_code)]
pub const BLINT_REVIEWS_SUFFIX: &str = "-reviews.json";
#[allow(dead_code)]
pub const BLINT_FUZZABLES_SUFFIX: &str = "-fuzzables.json";
#[allow(dead_code)]
pub const BLINT_SBOM_FILENAME: &str = "sbom.cdx.json";
#[allow(dead_code)]
pub const BLINT_CALLGRAPH_FILENAME: &str = "callgraph.graphml";

/// Locate the `blint` binary. Checks, in order:
/// 1. `BLINT_CMD` environment variable
/// 2. `blint` on PATH (pip/uv install)
#[allow(dead_code)]
pub fn find_blint() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("BLINT_CMD") {
        let pb = PathBuf::from(&path);
        if pb.is_file() {
            return Ok(pb);
        }
    }

    if let Some(path) = which("blint") {
        return Ok(path);
    }

    Err("blint CLI not found. Install with: uv tool install blint  or  pip install blint[extended]".to_string())
}

/// Run blint analysis on a binary/APK/IPA file.
///
/// Executes two commands:
/// 1. `blint -i <artifact> -o <output_dir>` — metadata, findings, reviews, fuzzables
/// 2. `blint sbom -i <artifact> -o <sbom_path> --deep --disassemble --export-callgraph-graphml` — SBOM + callgraph
///
/// `deep` analysis (disassembly, callgraph) is optional and can be skipped by setting
/// `deep` to `false` for faster scans.
#[allow(dead_code)]
pub fn run_blint(artifact_path: &Path, output_dir: &Path, deep: bool) -> Result<(PathBuf, Option<PathBuf>), String> {
    let blint_bin = find_blint()?;

    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create output dir {}: {e}", output_dir.display()))?;

    // 1. Basic scan: metadata + findings + reviews + fuzzables
    let status = Command::new(&blint_bin)
        .args([
            "-i",
            &artifact_path.to_string_lossy(),
            "-o",
            &output_dir.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to execute blint scan: {e}"))?;

    if !status.success() {
        return Err(format!("blint scan exited with {status}"));
    }

    // Find the metadata file (named <artifact_basename>-metadata.json)
    let stem = artifact_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "artifact".to_string());
    let metadata_path = output_dir.join(format!("{stem}{BLINT_METADATA_SUFFIX}"));

    let sbom_path = if deep {
        // 2. Deep SBOM scan with callgraph
        let sbom_out = output_dir.join(BLINT_SBOM_FILENAME);
        let cg_out = output_dir.join(BLINT_CALLGRAPH_FILENAME);
        let status = Command::new(&blint_bin)
            .args([
                "sbom",
                "-i",
                &artifact_path.to_string_lossy(),
                "-o",
                &sbom_out.to_string_lossy(),
                "--deep",
                "--disassemble",
                "--export-callgraph-graphml",
                "--callgraph-out",
                &cg_out.to_string_lossy(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()
            .map_err(|e| format!("failed to execute blint sbom: {e}"))?;

        if status.success() && sbom_out.is_file() {
            Some(sbom_out)
        } else {
            None
        }
    } else {
        None
    };

    Ok((metadata_path, sbom_path))
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
    fn test_find_blint_error_message() {
        let result = find_blint();
        // The error message should reference blint regardless of whether the tool is installed.
        if let Err(msg) = result {
            assert!(msg.contains("blint"))
        }
    }

    #[test]
    fn test_blint_report_filename_convention() {
        let stem = "myapp".to_string();
        assert_eq!(
            Path::new("/out").join(format!("{stem}{BLINT_METADATA_SUFFIX}")),
            Path::new("/out/myapp-metadata.json")
        );
    }
}
