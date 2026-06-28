/// A loaded golem analysis report, backed by the shared [`LoadedReport`].
///
/// This re-exports [`crate::shared::LoadedReport`] so call sites
/// (`golem::loader::LoadedReport::from_file(…)`) work unchanged.
pub use crate::shared::LoadedReport;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_golem_loader_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("golem-report.json");
        std::fs::write(
            &path,
            r#"{"tool":{"name":"golem","version":"2.5.1"},"stats":{"packageCount":2}}"#,
        )
        .unwrap();
        let report = LoadedReport::from_file(&path).unwrap();
        assert_eq!(report.report["tool"]["name"].as_str(), Some("golem"));
        assert_eq!(report.report["stats"]["packageCount"].as_i64(), Some(2));
    }

    #[test]
    fn test_golem_loader_bad_path() {
        assert!(LoadedReport::from_file(Path::new("/nonexistent/golem.json")).is_err());
    }
}
