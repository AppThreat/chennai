use serde_json::Value;

/// Logs custom tool calls to timestamped JSON files under
/// `<source_root>/.chen/chennai-debug-logs/`. The structured-analysis tools
/// (`atom_`, `bom_`, `rusi_`, `golem_`, `dosai_`, `blint_`, `project_memory`)
/// are recorded, as are the fallback `ripgrep` / `read_file` / `git_*` tools —
/// capturing the latter is what lets us audit whether the model is reaching for
/// text search instead of the structured tools when debugging tool selection.
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
            || name == "project_memory"
            || name.starts_with("rusi_")
            || name.starts_with("golem_")
            || name.starts_with("dosai_")
            || name.starts_with("blint_")
            // Fallback text/file/git tools: tracked so a debug session shows the FULL tool mix
            // (structured-analysis vs. text-search), which is essential for auditing tool selection.
            || name == "ripgrep"
            || name == "read_file"
            || name.starts_with("git_")
    }
}
