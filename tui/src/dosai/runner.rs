use std::path::{Path, PathBuf};
use std::process::Command;

pub const DOSAI_DATAFLOWS_FILENAME: &str = "dosai-dataflows.json";
pub const DOSAI_METHODS_FILENAME: &str = "dosai-methods.json";
pub const DOSAI_CRYPTO_FILENAME: &str = "dosai-crypto.json";

/// Locate the `dosai` binary. Checks, in order:
/// 1. `DOSAI_CMD` environment variable
/// 2. `dosai` on PATH
pub fn find_dosai() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("DOSAI_CMD") {
        let pb = PathBuf::from(&path);
        if pb.is_file() {
            return Ok(pb);
        }
    }

    if let Some(path) = which("dosai") {
        return Ok(path);
    }

    Err("dosai CLI not found. Set DOSAI_CMD or install the full dosai release from https://github.com/owasp-dep-scan/dosai/releases".to_string())
}

/// Path to the dosai dataflows JSON report inside `source_dir`.
#[allow(dead_code)]
pub fn dosai_dataflows_path(source_dir: &Path) -> PathBuf {
    source_dir.join(DOSAI_DATAFLOWS_FILENAME)
}

/// Path to the dosai methods JSON report inside `source_dir`.
#[allow(dead_code)]
pub fn dosai_methods_path(source_dir: &Path) -> PathBuf {
    source_dir.join(DOSAI_METHODS_FILENAME)
}

/// Path to the dosai crypto JSON report inside `source_dir`.
#[allow(dead_code)]
pub fn dosai_crypto_path(source_dir: &Path) -> PathBuf {
    source_dir.join(DOSAI_CRYPTO_FILENAME)
}

/// Run dosai analysis on `source_dir`.
///
/// The `dataflows` subcommand is **required** — it produces the primary report.
/// The `methods` and `crypto` subcommands are **best-effort**: `dosai methods` can
/// abort when it cannot load an input's assemblies (e.g. a missing ASP.NET shared
/// framework), and that must not prevent the data-flow analysis from being used.
///
/// Invokes:
/// - `dosai dataflows --path <src> --pattern-packs all --o <dataflows.json>` (required)
/// - `dosai methods --path <src> --o <methods.json>` (best-effort)
/// - `dosai crypto --path <src> --format dosai --o <crypto.json>` (best-effort)
///
/// Returns the list of output file paths that were successfully generated, with the
/// dataflows report guaranteed to be first.
pub fn run_dosai(source_dir: &Path, out_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let dosai_bin = find_dosai()?;

    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("failed to create output dir {}: {e}", out_dir.display()))?;

    let df_path = out_dir.join(DOSAI_DATAFLOWS_FILENAME);
    let methods_path = out_dir.join(DOSAI_METHODS_FILENAME);
    let crypto_path = out_dir.join(DOSAI_CRYPTO_FILENAME);

    let mut outputs = Vec::new();

    // 1. Dataflows (required).
    let status = Command::new(&dosai_bin)
        .args([
            "dataflows",
            "--path",
            &source_dir.to_string_lossy(),
            "--pattern-packs",
            "all",
            "--o",
            &df_path.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to execute dosai dataflows: {e}"))?;

    if !status.success() {
        return Err(format!("dosai dataflows exited with {status}"));
    }
    if !df_path.is_file() {
        return Err(format!(
            "dosai dataflows completed but output file {} was not created",
            df_path.display()
        ));
    }
    outputs.push(df_path);

    // 2. Methods (best-effort — failure is tolerated and logged).
    run_optional(&dosai_bin, &["methods", "--path", &source_dir.to_string_lossy(), "--o", &methods_path.to_string_lossy()], &methods_path, "methods", &mut outputs);

    // 3. Crypto (best-effort).
    run_optional(&dosai_bin, &["crypto", "--path", &source_dir.to_string_lossy(), "--format", "dosai", "--o", &crypto_path.to_string_lossy()], &crypto_path, "crypto", &mut outputs);

    Ok(outputs)
}

/// Run a best-effort dosai subcommand: if it exits non-zero or writes no file, log a
/// warning and continue. Successful outputs are appended to `outputs`.
fn run_optional(bin: &Path, args: &[&str], out_path: &Path, label: &str, outputs: &mut Vec<PathBuf>) {
    match Command::new(bin)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() && out_path.is_file() => {
            outputs.push(out_path.to_path_buf());
        }
        Ok(status) => {
            eprintln!("dosai {label} did not produce usable output (exit {status}); continuing with dataflows only.");
        }
        Err(e) => {
            eprintln!("dosai {label} could not be executed ({e}); continuing with dataflows only.");
        }
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
    fn test_find_dosai_error_message() {
        let result = find_dosai();
        if let Err(msg) = result {
            assert!(msg.contains("dosai"))
        }
    }

    #[test]
    fn test_dosai_report_paths() {
        let dir = Path::new("/tmp/test-project");
        assert_eq!(dosai_dataflows_path(dir), dir.join("dosai-dataflows.json"));
        assert_eq!(dosai_methods_path(dir), dir.join("dosai-methods.json"));
        assert_eq!(dosai_crypto_path(dir), dir.join("dosai-crypto.json"));
    }
}
