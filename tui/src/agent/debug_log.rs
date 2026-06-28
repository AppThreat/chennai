use serde_json::Value;

/// Logs custom tool calls to timestamped JSON files under
/// `<source_root>/.chen/chennai-debug-logs/`. Only tools matching the
/// tracked prefixes (`atom_`, `bom_`, `rusi_`, `golem_`, `dosai_`, `blint_`)
/// are recorded — shell/git tools are excluded.
#[derive(Clone)]
pub struct DebugLogger {
    log_dir: std::path::PathBuf,
}

impl DebugLogger {
    /// Create a new logger rooted at `source_root/.chen/chennai-debug-logs/`.
    /// The directory is created if it doesn't exist. Returns `None` if the
    /// directory cannot be created.
    pub fn new(source_root: Option<&str>) -> Option<Self> {
        let base = source_root
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let log_dir = base.join(".chen").join("chennai-debug-logs");
        std::fs::create_dir_all(&log_dir).ok()?;
        eprintln!("Tool debug logs: {}", log_dir.display());
        Some(DebugLogger { log_dir })
    }

    /// Record a tool call and its result to a timestamped JSON file.
    /// The file is named `<tool>-<YYYYmmdd-HHMMSSfff>.json`.
    pub fn log(&self, tool_name: &str, input: &Value, output: &str, is_error: bool) {
        let ts = chrono::Local::now().format("%Y%m%d-%H%M%S%3f");
        let filename = format!("{}-{}.json", tool_name, ts);
        let path = self.log_dir.join(filename);
        let entry = serde_json::json!({
            "tool": tool_name,
            "input": input,
            "output": output,
            "is_error": is_error,
            "timestamp": ts.to_string(),
        });
        if let Ok(json) = serde_json::to_string_pretty(&entry) {
            let _ = std::fs::write(&path, json);
        }
    }

    /// Returns `true` when the tool name should be logged.
    pub fn is_tracked(name: &str) -> bool {
        name.starts_with("atom_")
            || name == "bom_query"
            || name.starts_with("rusi_")
            || name.starts_with("golem_")
            || name.starts_with("dosai_")
            || name.starts_with("blint_")
    }
}
