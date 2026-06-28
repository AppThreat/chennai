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
/// Executes up to three subcommands:
/// - `dosai dataflows --path <src> --pattern-packs all --o <dataflows.json>`
/// - `dosai methods --path <src> --o <methods.json>`
/// - `dosai crypto --path <src> --format dosai --o <crypto.json>`
///
/// Returns a list of output file paths that were successfully generated.
pub fn run_dosai(source_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let dosai_bin = find_dosai()?;

    if let Some(parent) = source_dir.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create output dir {}: {e}", parent.display()))?;
    }

    let df_path = source_dir.join(DOSAI_DATAFLOWS_FILENAME);
    let methods_path = source_dir.join(DOSAI_METHODS_FILENAME);
    let crypto_path = source_dir.join(DOSAI_CRYPTO_FILENAME);

    let mut outputs = Vec::new();

    // 1. Dataflows
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
    if df_path.is_file() {
        outputs.push(df_path);
    }

    // 2. Methods
    let status = Command::new(&dosai_bin)
        .args([
            "methods",
            "--path",
            &source_dir.to_string_lossy(),
            "--o",
            &methods_path.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to execute dosai methods: {e}"))?;

    if !status.success() {
        return Err(format!("dosai methods exited with {status}"));
    }
    if methods_path.is_file() {
        outputs.push(methods_path);
    }

    // 3. Crypto (optional — best-effort)
    let crypto_ok = Command::new(&dosai_bin)
        .args([
            "crypto",
            "--path",
            &source_dir.to_string_lossy(),
            "--format",
            "dosai",
            "--o",
            &crypto_path.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if let Ok(status) = crypto_ok
        && status.success()
        && crypto_path.is_file()
    {
        outputs.push(crypto_path);
    }

    Ok(outputs)
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
