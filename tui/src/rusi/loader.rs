use serde_json::Value;
use std::path::Path;

pub struct LoadedReport {
    pub report: Value,
    #[allow(dead_code)]
    pub report_path: String,
}

impl LoadedReport {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read rusi report '{}': {e}", path.display()))?;
        let report: Value = serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse rusi report '{}': {e}", path.display()))?;
        Ok(LoadedReport {
            report,
            report_path: path.to_string_lossy().to_string(),
        })
    }
}
