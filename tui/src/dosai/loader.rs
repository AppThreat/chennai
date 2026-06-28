pub use crate::shared::LoadedReport;
use std::path::Path;

/// A loaded dosai analysis report pair (dataflows + optionally methods, crypto).
pub struct DosaiReports {
    /// The primary dataflows JSON report.
    pub dataflows: crate::shared::LoadedReport,
    /// Optional methods JSON report.
    pub methods: Option<crate::shared::LoadedReport>,
    /// Optional crypto JSON report.
    pub crypto: Option<crate::shared::LoadedReport>,
}

impl DosaiReports {
    /// Load all available dosai reports from a source directory.
    ///
    /// Expects files named `dosai-dataflows.json`, `dosai-methods.json`,
    /// and `dosai-crypto.json` inside `source_dir`. Only `dataflows` is
    /// required; `methods` and `crypto` are optional.
    pub fn load(source_dir: &Path) -> Result<Self, String> {
        let df_path = source_dir.join("dosai-dataflows.json");
        let dataflows = crate::shared::LoadedReport::from_file(&df_path).map_err(|e| {
            format!("failed to load dosai dataflows report: {e}")
        })?;

        let methods_path = source_dir.join("dosai-methods.json");
        let methods = if methods_path.is_file() {
            crate::shared::LoadedReport::from_file(&methods_path).ok()
        } else {
            None
        };

        let crypto_path = source_dir.join("dosai-crypto.json");
        let crypto = if crypto_path.is_file() {
            crate::shared::LoadedReport::from_file(&crypto_path).ok()
        } else {
            None
        };

        Ok(DosaiReports { dataflows, methods, crypto })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dosai_loader_dataflows_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("dosai-dataflows.json"),
            r#"{"Metadata":{"Tool":"Dosai"},"Statistics":{"NodeCount":5}}"#,
        )
        .unwrap();
        let reports = DosaiReports::load(dir.path()).unwrap();
        assert_eq!(reports.dataflows.report["Metadata"]["Tool"].as_str(), Some("Dosai"));
        assert!(reports.methods.is_none());
        assert!(reports.crypto.is_none());
    }

    #[test]
    fn test_dosai_loader_all_reports() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("dosai-dataflows.json"), r#"{"Statistics":{"NodeCount":5}}"#).unwrap();
        std::fs::write(dir.path().join("dosai-methods.json"), r#"{"Methods":[{"Name":"Main"}]}"#).unwrap();
        std::fs::write(dir.path().join("dosai-crypto.json"), r#"{"findings":[]}"#).unwrap();
        let reports = DosaiReports::load(dir.path()).unwrap();
        assert!(reports.methods.is_some());
        assert!(reports.crypto.is_some());
    }

    #[test]
    fn test_dosai_loader_missing_dataflows() {
        let dir = tempfile::tempdir().unwrap();
        let result = DosaiReports::load(dir.path());
        assert!(result.is_err());
    }
}
