//! Structured security finding types, report rendering, and token usage ledger.
//!
//! [`Finding`] represents a single proven (or disproven) security weakness with
//! source/sink locations, a deterministic engine proof, and confidence. [`FindingSet`]
//! accumulates, deduplicates, and ranks findings and can render them as Markdown or JSON.
//! [`TokenLedger`] aggregates per-run token usage for the one-line cost summary.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Confirmed,
    Plausible,
    Low,
}

// ---------------------------------------------------------------------------
// Location & Proof
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: Option<u32>,
    pub tag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// The chen DSL expression that proves (or attempts to prove) reachability.
    pub expr: String,
    /// Number of flow paths the engine returned.
    pub path_count: usize,
    /// Whether the proof resolved to at least one real path.
    pub verified: bool,
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub cwe: Option<String>,
    pub confidence: Confidence,
    pub source: Location,
    pub sink: Location,
    pub proof: Proof,
    /// Whether the source→sink path is reachable — mirrors `proof.verified`, surfaced
    /// at the top level so benchmark tooling can filter without descending into `proof`.
    pub reachable: bool,
    /// Sanitizer/validation routines the agent checked and found absent (or present).
    #[serde(default)]
    pub sanitizers_checked: Vec<String>,
    /// The analysis tool(s) that produced the evidence, e.g. "atom_flows, atom_callsites".
    #[serde(default)]
    pub grounded_by: Option<String>,
    pub remediation: Option<String>,
}

// ---------------------------------------------------------------------------
// FindingSet
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FindingSet {
    pub findings: Vec<Finding>,
    /// Cache of proof-expression → reachable (true) / not-reachable (false),
    /// so repeated submissions of the same expr avoid re-executing the engine.
    pub proof_cache: HashMap<String, bool>,
}

impl FindingSet {
    pub fn new() -> Self {
        FindingSet {
            findings: Vec::new(),
            proof_cache: HashMap::new(),
        }
    }

    /// Add a finding, then deduplicate and re-rank.
    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
        self.dedupe();
        self.rank();
    }

    /// Collapse findings with the same `(source.tag, sink.file, sink.line)` tuple.
    /// When duplicates exist, the one with the highest severity·confidence is kept.
    pub fn dedupe(&mut self) {
        let mut seen: HashMap<(Option<String>, String, Option<u32>), Finding> = HashMap::new();
        for f in self.findings.drain(..) {
            let key = (f.source.tag.clone(), f.sink.file.clone(), f.sink.line);
            match seen.get_mut(&key) {
                Some(existing) => {
                    // Keep the higher-ranked finding (severity first, then confidence).
                    if f.severity < existing.severity
                        || (f.severity == existing.severity && f.confidence < existing.confidence)
                    {
                        *existing = f;
                    }
                }
                None => {
                    seen.insert(key, f);
                }
            }
        }
        self.findings = seen.into_values().collect();
    }

    /// Sort by severity (Critical first), then by confidence (Confirmed first).
    pub fn rank(&mut self) {
        self.findings.sort_by(|a, b| {
            a.severity.cmp(&b.severity).then(a.confidence.cmp(&b.confidence))
        });
    }

    /// Return the number of findings with `Confirmed` confidence.
    pub fn confirmed_count(&self) -> usize {
        self.findings.iter().filter(|f| f.confidence == Confidence::Confirmed).count()
    }

    /// Render all findings as a Markdown string.
    pub fn render_markdown(&self) -> String {
        if self.findings.is_empty() {
            return "# Security Findings\n\n_No findings submitted._\n".to_string();
        }
        let mut out = String::from("# Security Findings\n\n");
        for f in &self.findings {
            let sev = format!("{:?}", f.severity);
            let conf = format!("{:?}", f.confidence);
            let cwe = f.cwe.as_deref().map(|c| format!(" | **CWE:** {}", c)).unwrap_or_default();
            let src_line = f.source.line.map(|l| format!(":{}", l)).unwrap_or_default();
            let snk_line = f.sink.line.map(|l| format!(":{}", l)).unwrap_or_default();
            let proven = if f.proof.verified { "✅ verified" } else { "❌ not verified" };
            let remediation = f.remediation.as_deref()
                .map(|r| format!("\n- **Remediation:** {}", r))
                .unwrap_or_default();
            let grounded = f.grounded_by.as_deref()
                .filter(|s| !s.is_empty())
                .map(|g| format!("\n- **Grounded by:** {}", g))
                .unwrap_or_default();
            let sanitizers = if f.sanitizers_checked.is_empty() {
                String::new()
            } else {
                format!("\n- **Sanitizers checked:** {}", f.sanitizers_checked.join(", "))
            };

            out.push_str(&format!(
                "## {} — {}\n\
                 **Severity:** {} | **Confidence:** {} | **ID:** {}{}\n\
                 - **Source:** `{}`{}\n\
                 - **Sink:** `{}`{}\n\
                 - **Proof:** `{}` — {} path(s), {}{}{}{}\n\n",
                f.id, f.title, sev, conf, f.id, cwe,
                f.source.file, src_line,
                f.sink.file, snk_line,
                f.proof.expr, f.proof.path_count, proven,
                sanitizers, grounded, remediation,
            ));
        }
        out
    }

    /// Render all findings as a JSON value.
    pub fn render_json(&self) -> serde_json::Value {
        serde_json::json!({
            "findings": self.findings,
            "total": self.findings.len(),
            "confirmed": self.confirmed_count(),
        })
    }
}

impl Default for FindingSet {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TokenLedger
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct TokenLedger {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    #[allow(dead_code)]
    pub per_tool: HashMap<String, u64>,
}

impl TokenLedger {
    pub fn record_usage(&mut self, input_tokens: u32, output_tokens: u32, cache_read_tokens: Option<u32>) {
        self.input += input_tokens as u64;
        self.output += output_tokens as u64;
        if let Some(cr) = cache_read_tokens {
            self.cache_read += cr as u64;
        }
    }

    /// One-line summary like `tokens: 1234 in / 567 out / 89 cache`.
    pub fn summary(&self) -> String {
        format!("tokens: {} in / {} out / {} cache", self.input, self.output, self.cache_read)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Count flow paths in an engine `flows` response. The FlowHandler reports the full
/// pre-pagination count under `"total"` (the accurate number of proof paths); the
/// `"flows"` array is only the current page window, so it undercounts when the result
/// is paginated. Prefer `total`, then fall back to the array lengths for other shapes.
pub fn count_flow_paths(data: &serde_json::Value) -> usize {
    if let Some(total) = data.get("total").and_then(|v| v.as_u64()) {
        return total as usize;
    }
    data.get("flows")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .or_else(|| {
            data.get("rows")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
        })
        .unwrap_or(0)
}

/// Parse a [`Severity`] from a case-insensitive string.
pub fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

/// Parse a [`Confidence`] from a case-insensitive string.
pub fn parse_confidence(s: &str) -> Confidence {
    match s.to_ascii_lowercase().as_str() {
        "confirmed" => Confidence::Confirmed,
        "plausible" => Confidence::Plausible,
        "low" => Confidence::Low,
        _ => Confidence::Low,
    }
}

/// Parse a [`Location`] from an optional JSON sub-object.
pub fn parse_location(val: Option<&serde_json::Value>) -> Result<Location, String> {
    let obj = val.ok_or("missing location")?;
    let file = obj.get("file").and_then(|v| v.as_str()).ok_or("location requires 'file'")?;
    Ok(Location {
        file: file.to_string(),
        line: obj.get("line").and_then(|v| v.as_u64()).map(|v| v as u32),
        tag: obj.get("tag").and_then(|v| v.as_str()).map(String::from),
    })
}

/// Generate a deterministic finding ID from title and source/sink fingerprints.
pub fn finding_id(title: &str, source: &Location, sink: &Location) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    title.hash(&mut hasher);
    source.file.hash(&mut hasher);
    source.line.hash(&mut hasher);
    sink.file.hash(&mut hasher);
    sink.line.hash(&mut hasher);
    format!("F-{:016x}", hasher.finish())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding(id: &str, severity: Severity, confidence: Confidence, tag: &str, sink_file: &str, sink_line: Option<u32>) -> Finding {
        Finding {
            id: id.into(),
            title: "Test Finding".into(),
            severity,
            cwe: Some("CWE-22".into()),
            confidence,
            source: Location { file: "src/input.rs".into(), line: Some(1), tag: Some(tag.into()) },
            sink: Location { file: sink_file.into(), line: sink_line, tag: None },
            proof: Proof { expr: "sink.reachableByFlows(source)".into(), path_count: 3, verified: true },
            reachable: true,
            sanitizers_checked: vec!["escapeHtml".into()],
            grounded_by: Some("atom_reaches".into()),
            remediation: Some("Use safe API".into()),
        }
    }

    // -----------------------------------------------------------------------
    // (De)serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn finding_serde_roundtrip() {
        let f = sample_finding("F-test", Severity::High, Confidence::Confirmed, "cli-source", "src/exec.rs", Some(42));
        let json = serde_json::to_value(&f).unwrap();
        let deser: Finding = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(deser.id, f.id);
        assert_eq!(deser.title, f.title);
        assert_eq!(deser.severity, Severity::High);
        assert_eq!(deser.confidence, Confidence::Confirmed);
        assert_eq!(deser.source.file, "src/input.rs");
        assert_eq!(deser.sink.line, Some(42));
        assert_eq!(deser.proof.path_count, 3);
        let re_json = serde_json::to_value(&deser).unwrap();
        assert_eq!(json, re_json);
    }

    #[test]
    fn finding_set_roundtrip() {
        let f = sample_finding("F1", Severity::Critical, Confidence::Confirmed, "cli", "sink.rs", Some(1));
        let mut set = FindingSet::new();
        set.add(f);
        let json = set.render_json();
        assert_eq!(json["total"].as_i64().unwrap(), 1);
        assert_eq!(json["confirmed"].as_i64().unwrap(), 1);
    }

    // -----------------------------------------------------------------------
    // Dedupe
    // -----------------------------------------------------------------------

    #[test]
    fn dedupe_collapses_same_source_tag_sink_file_sink_line() {
        let mut set = FindingSet::new();
        set.add(sample_finding("A", Severity::High, Confidence::Plausible, "cli", "sink.rs", Some(10)));
        set.add(sample_finding("B", Severity::Critical, Confidence::Confirmed, "cli", "sink.rs", Some(10)));
        set.dedupe();
        assert_eq!(set.findings.len(), 1);
        // The higher-ranked one (Critical+Confirmed) should have won.
        assert_eq!(set.findings[0].id, "B");
    }

    #[test]
    fn dedupe_preserves_different_sink_files() {
        let mut set = FindingSet::new();
        set.add(sample_finding("A", Severity::High, Confidence::Confirmed, "cli", "sink-a.rs", Some(10)));
        set.add(sample_finding("B", Severity::High, Confidence::Confirmed, "cli", "sink-b.rs", Some(10)));
        set.dedupe();
        assert_eq!(set.findings.len(), 2);
    }

    #[test]
    fn dedupe_preserves_different_source_tags() {
        let mut set = FindingSet::new();
        set.add(sample_finding("A", Severity::High, Confidence::Confirmed, "cli", "sink.rs", Some(10)));
        set.add(sample_finding("B", Severity::High, Confidence::Confirmed, "framework-input", "sink.rs", Some(10)));
        set.dedupe();
        assert_eq!(set.findings.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Rank ordering
    // -----------------------------------------------------------------------

    #[test]
    fn rank_orders_critical_before_high() {
        let mut set = FindingSet::new();
        set.findings.push(sample_finding("L", Severity::High, Confidence::Confirmed, "t1", "s.rs", Some(1)));
        set.findings.push(sample_finding("H", Severity::Critical, Confidence::Confirmed, "t2", "s.rs", Some(2)));
        set.rank();
        assert_eq!(set.findings[0].id, "H");
        assert_eq!(set.findings[1].id, "L");
    }

    #[test]
    fn rank_orders_confirmed_before_plausible_within_same_severity() {
        let mut set = FindingSet::new();
        set.findings.push(sample_finding("P", Severity::High, Confidence::Plausible, "t1", "s.rs", Some(1)));
        set.findings.push(sample_finding("C", Severity::High, Confidence::Confirmed, "t2", "s.rs", Some(2)));
        set.rank();
        assert_eq!(set.findings[0].id, "C");
        assert_eq!(set.findings[1].id, "P");
    }

    // -----------------------------------------------------------------------
    // TokenLedger
    // -----------------------------------------------------------------------

    #[test]
    fn ledger_aggregates_multiple_usage_events() {
        let mut ledger = TokenLedger::default();
        ledger.record_usage(100, 50, Some(10));
        ledger.record_usage(200, 100, None);
        assert_eq!(ledger.input, 300);
        assert_eq!(ledger.output, 150);
        assert_eq!(ledger.cache_read, 10);
        assert!(ledger.summary().contains("300"));
        assert!(ledger.summary().contains("150"));
        assert!(ledger.summary().contains("10"));
    }

    #[test]
    fn empty_ledger_summary() {
        let ledger = TokenLedger::default();
        assert_eq!(ledger.summary(), "tokens: 0 in / 0 out / 0 cache");
    }

    // -----------------------------------------------------------------------
    // Parsing helpers
    // -----------------------------------------------------------------------

    #[test]
    fn parse_severity_is_case_insensitive() {
        assert_eq!(parse_severity("CRITICAL"), Severity::Critical);
        assert_eq!(parse_severity("High"), Severity::High);
        assert_eq!(parse_severity("medium"), Severity::Medium);
        assert_eq!(parse_severity("LOW"), Severity::Low);
        assert_eq!(parse_severity("Info"), Severity::Info);
        assert_eq!(parse_severity("unknown"), Severity::Medium);
    }

    #[test]
    fn parse_confidence_is_case_insensitive() {
        assert_eq!(parse_confidence("CONFIRMED"), Confidence::Confirmed);
        assert_eq!(parse_confidence("Plausible"), Confidence::Plausible);
        assert_eq!(parse_confidence("low"), Confidence::Low);
        assert_eq!(parse_confidence("unknown"), Confidence::Low);
    }

    #[test]
    fn finding_id_is_deterministic() {
        let loc1 = Location { file: "a.rs".into(), line: Some(1), tag: None };
        let loc2 = Location { file: "b.rs".into(), line: Some(2), tag: None };
        let id1 = finding_id("test", &loc1, &loc2);
        let id2 = finding_id("test", &loc1, &loc2);
        assert_eq!(id1, id2);
    }

    #[test]
    fn count_flow_paths_counts_flows_or_rows() {
        let data1 = serde_json::json!({"flows": [{"id": 1}, {"id": 2}]});
        assert_eq!(count_flow_paths(&data1), 2);
        let data2 = serde_json::json!({"rows": [{"id": 1}]});
        assert_eq!(count_flow_paths(&data2), 1);
        let data3 = serde_json::json!({"error": "bad"});
        assert_eq!(count_flow_paths(&data3), 0);
    }

    #[test]
    fn count_flow_paths_prefers_total_over_windowed_page() {
        // The FlowHandler reports the full count in `total` while `flows` is only the
        // paged window (here capped at limit=5); the accurate proof count is `total`.
        let data = serde_json::json!({"total": 37, "flows": [{"id":1},{"id":2},{"id":3},{"id":4},{"id":5}]});
        assert_eq!(count_flow_paths(&data), 37);
    }

    #[test]
    fn render_markdown_includes_finding_details() {
        let mut set = FindingSet::new();
        set.add(sample_finding("F-001", Severity::Critical, Confidence::Confirmed, "cli", "exec.rs", Some(42)));
        let md = set.render_markdown();
        assert!(md.contains("F-001"));
        assert!(md.contains("Critical"));
        assert!(md.contains("Confirmed"));
        assert!(md.contains("exec.rs"));
        assert!(md.contains("✅ verified"));
        assert!(md.contains("Use safe API"));
    }

    #[test]
    fn render_markdown_empty() {
        let set = FindingSet::new();
        let md = set.render_markdown();
        assert!(md.contains("No findings"));
    }
}
