use crate::shared::LoadedReport;
use std::path::Path;

/// All parsed blint output files for a single binary artifact.
#[derive(Clone)]
#[allow(dead_code)]
pub struct BlintReports {
    /// The primary metadata JSON (header, functions, symbols, imports/exports, etc.).
    pub metadata: LoadedReport,
    /// Optional security findings JSON.
    pub findings: Option<LoadedReport>,
    /// Optional capability reviews JSON.
    pub reviews: Option<LoadedReport>,
    /// Optional fuzzable-entry-points JSON.
    pub fuzzables: Option<LoadedReport>,
    /// Optional CycloneDX SBOM from `blint sbom`.
    pub sbom: Option<LoadedReport>,
    /// Path to the callgraph GraphML export, if generated.
    pub callgraph_path: Option<String>,
    /// The detected artifact type (apk, ipa, elf, pe, macho, wasm, etc.).
    pub artifact_type: String,
}

impl BlintReports {
    /// Load all available blint reports for a given artifact file.
    ///
    /// blint names its output files after the **full input file name including its
    /// extension** — e.g. an input `app.apk` produces `app.apk-metadata.json`,
    /// `app.apk-findings.json`, etc. `artifact_basename` must therefore be the file
    /// name with extension (not the stem). The SBOM and callgraph are written to
    /// fixed names (`sbom.cdx.json`, `callgraph.graphml`).
    pub fn load(artifact_basename: &str, output_dir: &Path) -> Result<Self, String> {
        let stem = artifact_basename;

        let metadata_path = output_dir.join(format!("{stem}-metadata.json"));
        let metadata = LoadedReport::from_file(&metadata_path)
            .map_err(|e| format!("failed to load blint metadata: {e}"))?;

        let findings_path = output_dir.join(format!("{stem}-findings.json"));
        let findings = if findings_path.is_file() {
            LoadedReport::from_file(&findings_path).ok()
        } else {
            None
        };

        let reviews_path = output_dir.join(format!("{stem}-reviews.json"));
        let reviews = if reviews_path.is_file() {
            LoadedReport::from_file(&reviews_path).ok()
        } else {
            None
        };

        let fuzzables_path = output_dir.join(format!("{stem}-fuzzables.json"));
        let fuzzables = if fuzzables_path.is_file() {
            LoadedReport::from_file(&fuzzables_path).ok()
        } else {
            None
        };

        let sbom_path = output_dir.join("sbom.cdx.json");
        let sbom = if sbom_path.is_file() {
            LoadedReport::from_file(&sbom_path).ok()
        } else {
            None
        };

        // blint exports the callgraph as `<stem>.graphml` (the stem varies by binary),
        // so accept the fixed name if present, otherwise the first `*.graphml` in the dir.
        let callgraph_path = first_graphml(output_dir).map(|p| p.to_string_lossy().to_string());

        let artifact_type = detect_artifact_type(stem, &metadata.report);

        Ok(BlintReports {
            metadata,
            findings,
            reviews,
            fuzzables,
            sbom,
            callgraph_path,
            artifact_type,
        })
    }
}

/// Return a GraphML callgraph export from `dir`: the fixed `callgraph.graphml` if present,
/// otherwise the first file with a `.graphml` extension (blint names it `<stem>.graphml`).
fn first_graphml(dir: &Path) -> Option<std::path::PathBuf> {
    let fixed = dir.join("callgraph.graphml");
    if fixed.is_file() {
        return Some(fixed);
    }
    std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).find(|p| {
        p.extension().and_then(|e| e.to_str()) == Some("graphml")
    })
}

/// Detect the binary artifact type, preferring blint's own metadata fields
/// (`exe_type` / `binary_type`) and falling back to the file-name extension.
fn detect_artifact_type(basename: &str, metadata: &serde_json::Value) -> String {
    if let Some(exe) = metadata["exe_type"].as_str() {
        match exe {
            "dexbinary" => return "apk".to_string(),
            other if !other.is_empty() => return other.to_string(),
            _ => {}
        }
    }
    if let Some(bt) = metadata["binary_type"].as_str()
        && !bt.is_empty()
    {
        return bt.to_string();
    }
    let lower = basename.to_lowercase();
    for (suffix, kind) in [
        (".apkm", "apk"), (".apk", "apk"), (".aab", "apk"),
        (".ipa", "ipa"), (".wasm", "wasm"),
        (".dll", "pe"), (".exe", "pe"),
        (".so", "elf"), (".dylib", "macho"),
    ] {
        if lower.ends_with(suffix) {
            return kind.to_string();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blint_loader_uses_full_filename_with_extension() {
        // blint names outputs after the full file name including the extension.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.apk-metadata.json"),
            r#"{"exe_type":"dexbinary","functions":[]}"#,
        )
        .unwrap();
        let reports = BlintReports::load("app.apk", dir.path()).unwrap();
        assert_eq!(reports.metadata.report["exe_type"].as_str(), Some("dexbinary"));
        assert_eq!(reports.artifact_type, "apk");
        assert!(reports.findings.is_none());
    }

    #[test]
    fn test_blint_loader_all_files() {
        let dir = tempfile::tempdir().unwrap();
        let base = "myapp.exe";
        std::fs::write(dir.path().join(format!("{base}-metadata.json")), r#"{"binary_type":"PE32"}"#).unwrap();
        std::fs::write(dir.path().join(format!("{base}-findings.json")), r#"{"findings":[]}"#).unwrap();
        std::fs::write(dir.path().join(format!("{base}-reviews.json")), r#"{"reviews":[]}"#).unwrap();
        std::fs::write(dir.path().join(format!("{base}-fuzzables.json")), r#"[]"#).unwrap();
        std::fs::write(dir.path().join("sbom.cdx.json"), r#"{"bomFormat":"CycloneDX"}"#).unwrap();
        std::fs::write(dir.path().join("callgraph.graphml"), r#"<?xml?>"#).unwrap();

        let reports = BlintReports::load(base, dir.path()).unwrap();
        assert!(reports.findings.is_some());
        assert!(reports.reviews.is_some());
        assert!(reports.fuzzables.is_some());
        assert!(reports.sbom.is_some());
        assert!(reports.callgraph_path.is_some());
        assert_eq!(reports.artifact_type, "PE32");
    }

    #[test]
    fn test_blint_loader_missing_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let result = BlintReports::load("test.apk", dir.path());
        assert!(result.is_err());
    }
}
