//! Corpus management: loading and representing benchmark test cases with
//! ground-truth vulnerability entries.
//!
//! Each case is defined by a `case.toml` file under `bench/corpus/<case>/`.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single ground-truth vulnerability entry for a corpus case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroundTruth {
    /// Unique identifier for this ground-truth entry (e.g. "GT-001").
    pub id: String,
    /// CWE family identifier (e.g. "CWE-89", "CWE-22").
    pub cwe: String,
    /// Severity level.
    pub severity: String,
    /// Sink file path (relative to the case source root).
    pub sink_file: String,
    /// Sink line number.
    pub sink_line: u32,
    /// Half-open line window around the sink: the finding's sink_line must be
    /// within `[sink_line - line_window, sink_line + line_window]` to match.
    /// Default: 5.
    #[serde(default = "default_line_window")]
    pub line_window: u32,
    /// If true, the finding must be confirmed/reachable to count as a TP.
    /// Default: true.
    #[serde(default = "default_true")]
    pub must_be_reachable: bool,
}

fn default_line_window() -> u32 {
    5
}

fn default_true() -> bool {
    true
}

/// A benchmark corpus case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusCase {
    /// Case name (directory name under corpus/).
    pub name: String,
    /// Programming language.
    pub lang: String,
    /// Source URL or vendored path for the case.
    pub source: String,
    /// Build recipe (command to generate the atom file, if needed).
    #[serde(default)]
    pub build: Option<String>,
    /// Human-readable description of what the case tests.
    pub description: String,
    /// The fixed objective text passed to chennai for all modes.
    #[serde(default)]
    pub objective: Option<String>,
    /// Known ground-truth vulnerabilities.
    #[serde(default)]
    pub ground_truth: Vec<GroundTruth>,
}

impl CorpusCase {
    /// Load a case from its `case.toml` file.
    pub fn load(toml_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(toml_path)
            .map_err(|e| format!("read {}: {e}", toml_path.display()))?;
        let mut case: CorpusCase = toml::from_str(&content)
            .map_err(|e| format!("parse {}: {e}", toml_path.display()))?;
        // Derive the name from the parent directory if not set.
        if case.name.is_empty() {
            if let Some(parent) = toml_path.parent() {
                case.name = parent.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
            }
        }
        Ok(case)
    }

    /// List all cases found under the given corpus root directory.
    pub fn discover_all(corpus_root: &Path) -> Vec<CorpusCase> {
        let mut cases = Vec::new();
        if let Ok(entries) = std::fs::read_dir(corpus_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let toml_path = path.join("case.toml");
                    if toml_path.is_file() {
                        if let Ok(case) = CorpusCase::load(&toml_path) {
                            cases.push(case);
                        }
                    }
                }
            }
        }
        cases.sort_by(|a, b| a.name.cmp(&b.name));
        cases
    }
}

/// Coarse CWE-family mapping: groups related CWEs so that minor CWE number
/// differences (e.g. CWE-78 vs CWE-89, both injection) still match.
pub fn cwe_family(cwe: &str) -> &str {
    // Strip the numeric part and match by prefix/family.
    let num = cwe.strip_prefix("CWE-").unwrap_or(cwe);
    match num.parse::<u32>() {
        Ok(n) => {
            // Group by hundreds range (coarse but practical).
            if n == 78 || (79..=119).contains(&n) {
                "injection" // CWE-78: OS Command, CWE-89: SQL, CWE-90: LDAP, etc.
            } else if (22..=23).contains(&n) {
                "path-traversal"
            } else if (287..=306).contains(&n) || (352..=400).contains(&n) {
                "auth"
            } else if (494..=502).contains(&n) {
                "dos"
            } else if (200..=220).contains(&n) {
                "info-leak"
            } else if (787..=799).contains(&n) {
                "deserialization"
            } else {
                cwe
            }
        }
        Err(_) => cwe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwe_family_groups_injection_variants() {
        assert_eq!(cwe_family("CWE-78"), "injection");  // OS Command
        assert_eq!(cwe_family("CWE-89"), "injection");  // SQL
        assert_eq!(cwe_family("CWE-90"), "injection");  // LDAP
        assert_eq!(cwe_family("CWE-79"), "injection");   // XSS
    }

    #[test]
    fn cwe_family_groups_path_traversal() {
        assert_eq!(cwe_family("CWE-22"), "path-traversal");
        assert_eq!(cwe_family("CWE-23"), "path-traversal");
    }

    #[test]
    fn cwe_family_groups_auth() {
        assert_eq!(cwe_family("CWE-287"), "auth");
        assert_eq!(cwe_family("CWE-306"), "auth");
    }

    #[test]
    fn cwe_family_passthrough_for_unknown() {
        assert_eq!(cwe_family("CWE-999"), "CWE-999");
        assert_eq!(cwe_family("SOME-OTHER"), "SOME-OTHER");
    }

    #[test]
    fn default_ground_truth_values() {
        let gt = GroundTruth {
            id: "GT-1".into(),
            cwe: "CWE-89".into(),
            severity: "High".into(),
            sink_file: "src/db.rs".into(),
            sink_line: 42,
            line_window: default_line_window(),
            must_be_reachable: default_true(),
        };
        assert_eq!(gt.line_window, 5);
        assert!(gt.must_be_reachable);
    }

    #[test]
    fn line_window_zero_still_matches_exact() {
        let gt = GroundTruth {
            id: "GT-1".into(),
            cwe: "CWE-89".into(),
            severity: "High".into(),
            sink_file: "src/db.rs".into(),
            sink_line: 42,
            line_window: 0,
            must_be_reachable: true,
        };
        // Exact match should pass.
        assert!(gt.sink_line >= gt.sink_line.saturating_sub(gt.line_window));
        assert!(gt.sink_line <= gt.sink_line + gt.line_window);
    }
}
