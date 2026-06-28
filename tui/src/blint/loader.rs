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
    /// Expects output files named `<artifact_stem>-metadata.json` etc. in `output_dir`.
    pub fn load(artifact_basename: &str, output_dir: &Path) -> Result<Self, String> {
        let stem = artifact_basename.trim_end_matches(".apk")
            .trim_end_matches(".ipa")
            .trim_end_matches(".aab")
            .trim_end_matches(".apkm")
            .trim_end_matches(".exe")
            .trim_end_matches(".dll")
            .trim_end_matches(".so")
            .trim_end_matches(".dylib")
            .trim_end_matches(".wasm");

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

        let callgraph_path = output_dir.join("callgraph.graphml");
        let callgraph_path = if callgraph_path.is_file() {
            Some(callgraph_path.to_string_lossy().to_string())
        } else {
            None
        };

        let artifact_type = detect_artifact_type(stem);

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

/// Detect the binary artifact type from the filename or metadata.
fn detect_artifact_type(_stem: &str) -> String {
    // In a real scenario, we'd check magic bytes or the metadata JSON header,
    // but for now we derive from the filename suffix at the caller level.
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blint_loader_metadata_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("test-metadata.json"),
            r#"{"binary_type":"ELF","machine_type":"x86_64","imports":[]}"#,
        )
        .unwrap();
        let reports = BlintReports::load("test.apk", dir.path()).unwrap();
        assert_eq!(reports.metadata.report["binary_type"].as_str(), Some("ELF"));
        assert!(reports.findings.is_none());
        assert!(reports.reviews.is_none());
    }

    #[test]
    fn test_blint_loader_all_files() {
        let dir = tempfile::tempdir().unwrap();
        let base = "myapp";
        std::fs::write(dir.path().join(format!("{base}-metadata.json")), r#"{"binary_type":"ELF"}"#).unwrap();
        std::fs::write(dir.path().join(format!("{base}-findings.json")), r#"{"findings":[]}"#).unwrap();
        std::fs::write(dir.path().join(format!("{base}-reviews.json")), r#"{"capabilities":[]}"#).unwrap();
        std::fs::write(dir.path().join(format!("{base}-fuzzables.json")), r#"[]"#).unwrap();
        std::fs::write(dir.path().join("sbom.cdx.json"), r#"{"bomFormat":"CycloneDX"}"#).unwrap();
        std::fs::write(dir.path().join("callgraph.graphml"), r#"<?xml?>"#).unwrap();

        let reports = BlintReports::load("myapp.exe", dir.path()).unwrap();
        assert!(reports.findings.is_some());
        assert!(reports.reviews.is_some());
        assert!(reports.fuzzables.is_some());
        assert!(reports.sbom.is_some());
        assert!(reports.callgraph_path.is_some());
    }

    #[test]
    fn test_blint_loader_missing_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let result = BlintReports::load("test.apk", dir.path());
        assert!(result.is_err());
    }
}
