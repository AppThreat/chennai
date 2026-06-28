use serde_json::Value;
use std::path::Path;

/// A generic loaded JSON report from any analysis tool backend.
#[derive(Clone)]
#[allow(dead_code)]
pub struct LoadedReport {
    pub report: Value,
    pub report_path: String,
}

impl LoadedReport {
    /// Load and parse a JSON report from a file path.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read report '{}': {e}", path.display()))?;
        let report: Value = serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse report '{}': {e}", path.display()))?;
        Ok(LoadedReport {
            report,
            report_path: path.to_string_lossy().to_string(),
        })
    }
}

/// Extract a string field from a JSON object, returning `default` if missing.
pub fn field_str<'a>(obj: &'a Value, key: &str) -> &'a str {
    obj.get(key).and_then(Value::as_str).unwrap_or("?")
}

/// Extract an i64 field from a JSON object, returning 0 if missing.
pub fn field_i64(obj: &Value, key: &str) -> i64 {
    obj.get(key).and_then(Value::as_i64).unwrap_or(0)
}

/// Check whether `text` contains `pattern` (case-insensitive).
/// When `pattern` is `None`, every text matches.
pub fn pattern_match(text: &str, pattern: Option<&str>) -> bool {
    match pattern {
        Some(pat) => text.to_lowercase().contains(&pat.to_lowercase()),
        None => true,
    }
}

/// Format a `filename:line` position string from optional components.
#[allow(dead_code)]
pub fn format_position(filename: &str, line: i64) -> String {
    format!("{filename}:{line}")
}

/// Build a tool definition JSON value with name, description, and input schema.
pub fn make_tool(name: &str, description: &str, input_schema: Value) -> Value {
    serde_json::json!({
        "name": name,
        "description": description,
        "input_schema": input_schema,
    })
}

/// Truncate content to `max_bytes`, appending a truncation marker.
#[allow(dead_code)]
pub fn truncate_content(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    const MARKER_BUDGET: usize = 96;
    let cut = floor_char_boundary(text, max_bytes.saturating_sub(MARKER_BUDGET));
    format!(
        "{}\n--- OUTPUT TRUNCATED at {} KiB (original: {} KiB). Use offset/limit to paginate. ---",
        &text[..cut],
        max_bytes / 1024,
        text.len() / 1024,
    )
}

#[allow(dead_code)]
fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    let mut idx = max;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Renders a header line like `"# Entities (42 total)"` or `"# Entities (42 matched, showing first 10)"`.
pub struct ListHeader {
    pub title: &'static str,
    pub total: usize,
    pub matched: usize,
    pub shown: usize,
}

impl std::fmt::Display for ListHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    if self.matched == self.total {
        write!(f, "# {} ({} total)", self.title, self.total)
    } else {
        write!(
            f,
            "# {} ({} matched, showing first {})",
            self.title, self.total, self.shown
        )
    }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loaded_report_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");
        std::fs::write(&path, r#"{"key": "value"}"#).unwrap();
        let report = LoadedReport::from_file(&path).unwrap();
        assert_eq!(report.report["key"].as_str(), Some("value"));
    }

    #[test]
    fn test_loaded_report_bad_path() {
        let err = LoadedReport::from_file(Path::new("/nonexistent/file.json"));
        assert!(err.is_err());
    }

    #[test]
    fn test_loaded_report_bad_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        let err = LoadedReport::from_file(&path);
        assert!(err.is_err());
    }

    #[test]
    fn test_field_str() {
        let v = serde_json::json!({"name": "test"});
        assert_eq!(field_str(&v, "name"), "test");
        assert_eq!(field_str(&v, "missing"), "?");
    }

    #[test]
    fn test_field_i64() {
        let v = serde_json::json!({"count": 42});
        assert_eq!(field_i64(&v, "count"), 42);
        assert_eq!(field_i64(&v, "missing"), 0);
    }

    #[test]
    fn test_pattern_match() {
        assert!(pattern_match("hello world", Some("world")));
        assert!(!pattern_match("hello world", Some("foo")));
        assert!(pattern_match("hello", None));
        assert!(pattern_match("Hello World", Some("world")));
    }

    #[test]
    fn test_format_position() {
        assert_eq!(format_position("src/main.rs", 42), "src/main.rs:42");
    }

    #[test]
    fn test_make_tool() {
        let tool = make_tool("test_tool", "A test tool", serde_json::json!({"type": "object", "properties": {}}));
        assert_eq!(tool["name"].as_str(), Some("test_tool"));
        assert_eq!(tool["description"].as_str(), Some("A test tool"));
    }

    #[test]
    fn test_truncate_content_is_utf8_safe() {
        let s = "café_".repeat(20_000);
        let out = truncate_content(&s, 1000);
        assert!(out.len() <= 1000 + 128);
        assert!(out.contains("TRUNCATED"));
        assert!(out.starts_with("café"));
    }

    #[test]
    fn test_truncate_content_short() {
        let s = "short text";
        assert_eq!(truncate_content(s, 100), s);
    }

    #[test]
    fn test_list_header_no_filter() {
        let h = ListHeader { title: "Packages", total: 5, matched: 5, shown: 5 };
        assert_eq!(h.to_string(), "# Packages (5 total)");
    }

    #[test]
    fn test_list_header_filtered() {
        let h = ListHeader { title: "Declarations", total: 100, matched: 10, shown: 10 };
        assert_eq!(h.to_string(), "# Declarations (100 matched, showing first 10)");
    }
}
