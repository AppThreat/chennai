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
/// Executes one or two commands (flags verified against blint's CLI):
/// 1. Metadata/findings/reviews scan — `blint -i <artifact> -o <output_dir>`. When `deep`
///    is set, `--disassemble --export-callgraph-graphml` are appended (both are top-level
///    options that take effect only with `--disassemble`) so a GraphML callgraph is exported.
/// 2. When `deep`, an SBOM is generated — `blint sbom -i <artifact> -o <sbom_file> --deep`
///    (`--deep` auto-enables disassembly; the sbom subcommand has no callgraph flags).
///
/// `deep` analysis (disassembly, callgraph, SBOM) is slow and optional; set `deep` to
/// `false` for a fast metadata-only scan.
#[allow(dead_code)]
pub fn run_blint(artifact_path: &Path, output_dir: &Path, deep: bool) -> Result<(PathBuf, Option<PathBuf>), String> {
    let blint_bin = find_blint()?;

    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create output dir {}: {e}", output_dir.display()))?;

    // 1. Metadata scan (+ optional disassembly & GraphML callgraph export when deep).
    let artifact = artifact_path.to_string_lossy().to_string();
    let out = output_dir.to_string_lossy().to_string();
    let mut scan_args: Vec<&str> = vec!["-i", &artifact, "-o", &out];
    if deep {
        scan_args.push("--disassemble");
        scan_args.push("--export-callgraph-graphml");
    }
    let status = Command::new(&blint_bin)
        .args(&scan_args)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to execute blint scan: {e}"))?;

    if !status.success() {
        return Err(format!("blint scan exited with {status}"));
    }

    // blint names the metadata file after the full input file name *including* its
    // extension (e.g. `app.apk` → `app.apk-metadata.json`), so use `file_name`, not `file_stem`.
    let base = artifact_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "artifact".to_string());
    let metadata_path = output_dir.join(format!("{base}{BLINT_METADATA_SUFFIX}"));

    // 2. Deep SBOM generation (best-effort — a missing SBOM must not fail the scan).
    let sbom_path = if deep {
        let sbom_out = output_dir.join(BLINT_SBOM_FILENAME);
        let sbom_out_str = sbom_out.to_string_lossy().to_string();
        let ok = Command::new(&blint_bin)
            .args(["sbom", "-i", &artifact, "-o", &sbom_out_str, "--deep"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok && sbom_out.is_file() { Some(sbom_out) } else { None }
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
        // blint keeps the full file name (with extension) when naming reports.
        let base = "myapp.apk".to_string();
        assert_eq!(
            Path::new("/out").join(format!("{base}{BLINT_METADATA_SUFFIX}")),
            Path::new("/out/myapp.apk-metadata.json")
        );
    }
}
