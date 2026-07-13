//! Structured security finding types, report rendering, and token usage ledger.
//!
//! [`Finding`] represents a single proven (or disproven) security weakness with
//! source/sink locations, a deterministic engine proof, and confidence. [`FindingSet`]
//! accumulates, deduplicates, and ranks findings and can render them as Markdown or JSON.
//! [`TokenLedger`] aggregates per-run token usage for the one-line cost summary.
//!
//! [`LedgerSnapshot`] captures a point-in-time copy of the ledger so that
//! [`LedgerDelta`] can compute token/time differences between two snapshots.
//! [`RunProfile`] accumulates per-segment timing and token data for orchestrated runs,
//! giving visibility into each sub-agent's cost and wall-clock duration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

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
    /// Number of provider turns (each `record_usage` call increments this).
    pub turns: u64,
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
        self.turns += 1;
    }

    /// One-line summary like `tokens: 1234 in / 567 out / 89 cache`.
    pub fn summary(&self) -> String {
        format!("tokens: {} in / {} out / {} cache", self.input, self.output, self.cache_read)
    }

    /// Capture a point-in-time snapshot of the current ledger state. Used to
    /// compute token deltas between two moments (e.g. before/after a sub-agent run).
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            input: self.input,
            output: self.output,
            cache_read: self.cache_read,
            turns: self.turns,
        }
    }

    /// Compute the token and turn difference between an earlier snapshot and the
    /// current ledger state.
    pub fn delta_since(&self, earlier: &LedgerSnapshot) -> LedgerDelta {
        LedgerDelta {
            input: self.input.saturating_sub(earlier.input),
            output: self.output.saturating_sub(earlier.output),
            cache_read: self.cache_read.saturating_sub(earlier.cache_read),
            turns: self.turns.saturating_sub(earlier.turns),
        }
    }

    /// Total tokens (input + output + cache read).
    #[allow(dead_code)]
    pub fn total_tokens(&self) -> u64 {
        self.input + self.output + self.cache_read
    }
}

// ---------------------------------------------------------------------------
// LedgerSnapshot & LedgerDelta
// ---------------------------------------------------------------------------

/// A point-in-time copy of [`TokenLedger`] counters. Cheap to create and compare,
/// used to attribute token usage to specific segments of a run.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerSnapshot {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    /// Number of `record_usage` calls recorded as of this snapshot.
    pub turns: u64,
}

/// The difference between two [`LedgerSnapshot`]s — how many tokens and turns
/// were consumed during a segment of a run (e.g. one sub-agent invocation).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerDelta {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub turns: u64,
}

impl LedgerDelta {
    /// Total tokens in this delta (input + output + cache read).
    pub fn total_tokens(&self) -> u64 {
        self.input + self.output + self.cache_read
    }

    /// Format a compact human-readable token count (e.g. "18.2k" for 18,200).
    pub fn format_tokens(total: u64) -> String {
        if total >= 1_000_000 {
            format!("{:.1}M", total as f64 / 1_000_000.0)
        } else if total >= 1_000 {
            format!("{:.1}k", total as f64 / 1_000.0)
        } else {
            total.to_string()
        }
    }

    /// Format as compact token summary like "18.2k tok".
    pub fn token_summary(&self) -> String {
        format!("{} tok", Self::format_tokens(self.total_tokens()))
    }

    /// Format as compact turn count like "12 turns".
    pub fn turn_summary(&self) -> String {
        format!("{} turns", self.turns)
    }
}

// ---------------------------------------------------------------------------
// RunProfile — per-segment cost accumulator for orchestrated runs
// ---------------------------------------------------------------------------

/// A single timed segment within an orchestrated run: one sub-agent invocation,
/// or the orchestrator's own turns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSegment {
    /// Human-readable label (e.g. "orchestrator", "recon", "sink-hunter #2").
    pub label: String,
    /// Tokens consumed by this segment.
    pub tokens: LedgerDelta,
    /// Wall-clock time elapsed during this segment.
    pub elapsed: Duration,
    /// Turn count for this segment.
    pub turns: u64,
    /// Number of new findings added during this segment.
    pub findings_delta: usize,
    /// Whether the segment completed normally (vs. truncated by turn budget).
    pub completed: bool,
}

/// Accumulates per-segment timing, token, and finding data for an orchestrated run.
/// Empty for flat (non-orchestrated) runs — populated only when the orchestrator is active.
/// Shared across the orchestrator and sub-agents via `Arc<Mutex<RunProfile>>`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunProfile {
    pub segments: Vec<ProfileSegment>,
    /// Cumulative advisory budget warnings generated during the run.
    pub budget_warnings: Vec<String>,
}

impl RunProfile {
    /// Create a new empty profile.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed segment (e.g. after a sub-agent finishes).
    pub fn push_segment(&mut self, segment: ProfileSegment) {
        self.segments.push(segment);
    }

    /// Record a budget warning message for the end-of-run summary.
    pub fn push_budget_warning(&mut self, message: String) {
        self.budget_warnings.push(message);
    }

    /// Total tokens across all segments.
    pub fn total_tokens(&self) -> u64 {
        self.segments.iter().map(|s| s.tokens.total_tokens()).sum()
    }

    /// Total turns across all segments.
    pub fn total_turns(&self) -> u64 {
        self.segments.iter().map(|s| s.turns).sum()
    }

    /// Total wall-clock time across all segments.
    pub fn total_elapsed(&self) -> Duration {
        self.segments.iter().fold(Duration::ZERO, |acc, s| acc + s.elapsed)
    }

    /// Total findings across all segments.
    pub fn total_findings(&self) -> usize {
        self.segments.iter().map(|s| s.findings_delta).sum()
    }

    /// Render a compact per-segment table for the end-of-run summary.
    /// Returns an empty string if there are no segments and no budget warnings.
    pub fn render_report(&self) -> String {
        if self.segments.is_empty() && self.budget_warnings.is_empty() {
            return String::new();
        }
        let mut out = String::from("\n─── Run Profile ───\n");
        out.push_str(&format!(
            "{:<20} {:>10} {:>8} {:>8}  {:>9}  {}\n",
            "Role", "Tokens", "Turns", "Findings", "Duration", "Done?"
        ));
        out.push_str(&format!(
            "{:<20} {:>10} {:>8} {:>8}  {:>9}  {}\n",
            "────", "──────", "────", "───────", "─────────", "─────"
        ));
        for seg in &self.segments {
            let dur = format_duration(seg.elapsed);
            let status = if seg.completed { "✓" } else { "✗" };
            out.push_str(&format!(
                "{:<20} {:>10} {:>8} {:>8}  {:>9}  {}\n",
                seg.label,
                seg.tokens.token_summary(),
                seg.turns,
                seg.findings_delta,
                dur,
                status,
            ));
        }
        out.push_str(&format!(
            "{:<20} {:>10} {:>8} {:>8}  {:>9}\n",
            "────", "──────", "────", "───────", "─────────"
        ));
        out.push_str(&format!(
            "{:<20} {:>10} {:>8} {:>8}  {:>9}\n",
            "TOTAL",
            LedgerDelta::format_tokens(self.total_tokens()) + " tok",
            self.total_turns(),
            self.total_findings(),
            format_duration(self.total_elapsed()),
        ));
        if !self.budget_warnings.is_empty() {
            out.push_str("\nBudget advisories:\n");
            for w in &self.budget_warnings {
                out.push_str(&format!("  ⚠ {w}\n"));
            }
        }
        out
    }

    /// Render as a JSON value for persistence.
    pub fn to_json(&self) -> serde_json::Value {
        let segments: Vec<serde_json::Value> = self.segments.iter().map(|s| {
            serde_json::json!({
                "label": s.label,
                "tokens": {
                    "input": s.tokens.input,
                    "output": s.tokens.output,
                    "cache_read": s.tokens.cache_read,
                    "total": s.tokens.total_tokens(),
                },
                "turns": s.turns,
                "findings_delta": s.findings_delta,
                "elapsed_secs": s.elapsed.as_secs_f64(),
                "completed": s.completed,
            })
        }).collect();
        serde_json::json!({
            "segments": segments,
            "totals": {
                "tokens": self.total_tokens(),
                "turns": self.total_turns(),
                "findings": self.total_findings(),
                "elapsed_secs": self.total_elapsed().as_secs_f64(),
            },
            "budget_warnings": self.budget_warnings,
        })
    }

    /// Persist to `<source_root>/.chen/agent-state/profile.json`.
    pub fn save(&self, source_root: Option<&str>) -> Result<(), String> {
        let base = source_root.ok_or("no source root configured")?;
        let dir = std::path::Path::new(base)
            .join(".chen")
            .join("agent-state");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create agent-state dir: {e}"))?;
        let json = serde_json::to_string_pretty(&self.to_json())
            .map_err(|e| format!("serialize profile: {e}"))?;
        std::fs::write(dir.join("profile.json"), json)
            .map_err(|e| format!("write profile: {e}"))?;
        Ok(())
    }
}

/// Format a [`Duration`] as a compact human-readable string (e.g. "1m40s", "45s").
pub fn format_duration(dur: Duration) -> String {
    let total_secs = dur.as_secs();
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    if mins > 0 {
        format!("{}m{}s", mins, secs)
    } else {
        format!("{}s", secs)
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

    // -----------------------------------------------------------------------
    // LedgerSnapshot / LedgerDelta
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_captures_ledger_state() {
        let mut ledger = TokenLedger::default();
        ledger.record_usage(100, 50, Some(10));
        ledger.record_usage(200, 100, None);
        let snap = ledger.snapshot();
        assert_eq!(snap.input, 300);
        assert_eq!(snap.output, 150);
        assert_eq!(snap.cache_read, 10);
        assert_eq!(snap.turns, 2);
    }

    #[test]
    fn delta_since_computes_difference() {
        let mut ledger = TokenLedger::default();
        ledger.record_usage(100, 50, Some(10));
        let before = ledger.snapshot();
        ledger.record_usage(200, 100, Some(20));
        let delta = ledger.delta_since(&before);
        assert_eq!(delta.input, 200);
        assert_eq!(delta.output, 100);
        assert_eq!(delta.cache_read, 20);
        assert_eq!(delta.turns, 1);
    }

    #[test]
    fn delta_since_with_no_activity_is_zero() {
        let ledger = TokenLedger::default();
        let snap = ledger.snapshot();
        let delta = ledger.delta_since(&snap);
        assert_eq!(delta.input, 0);
        assert_eq!(delta.output, 0);
        assert_eq!(delta.cache_read, 0);
        assert_eq!(delta.turns, 0);
    }

    #[test]
    fn delta_saturates_on_underflow() {
        // If a snapshot somehow has higher values than the current ledger, delta saturates at 0.
        let later = LedgerSnapshot { input: 50, output: 30, cache_read: 10, turns: 1 };
        let earlier = LedgerSnapshot { input: 200, output: 100, cache_read: 50, turns: 5 };
        let ledger = TokenLedger { input: later.input, output: later.output, cache_read: later.cache_read, turns: later.turns, per_tool: HashMap::new() };
        let delta = ledger.delta_since(&earlier);
        assert_eq!(delta.input, 0);
        assert_eq!(delta.output, 0);
        assert_eq!(delta.cache_read, 0);
        assert_eq!(delta.turns, 0);
    }

    #[test]
    fn total_tokens_aggregates_all() {
        let delta = LedgerDelta { input: 100, output: 50, cache_read: 25, turns: 3 };
        assert_eq!(delta.total_tokens(), 175);
    }

    // -----------------------------------------------------------------------
    // LedgerDelta formatting
    // -----------------------------------------------------------------------

    #[test]
    fn format_tokens_compact() {
        assert_eq!(LedgerDelta::format_tokens(500), "500");
        assert_eq!(LedgerDelta::format_tokens(1_200), "1.2k");
        assert_eq!(LedgerDelta::format_tokens(18_200), "18.2k");
        assert_eq!(LedgerDelta::format_tokens(1_500_000), "1.5M");
    }

    // -----------------------------------------------------------------------
    // RunProfile
    // -----------------------------------------------------------------------

    #[test]
    fn profile_accumulates_segments() {
        let mut profile = RunProfile::new();
        profile.push_segment(ProfileSegment {
            label: "recon".into(),
            tokens: LedgerDelta { input: 1000, output: 500, cache_read: 200, turns: 3 },
            elapsed: Duration::from_secs(60),
            turns: 3,
            findings_delta: 2,
            completed: true,
        });
        profile.push_segment(ProfileSegment {
            label: "sink-hunter".into(),
            tokens: LedgerDelta { input: 2000, output: 800, cache_read: 300, turns: 5 },
            elapsed: Duration::from_secs(100),
            turns: 5,
            findings_delta: 4,
            completed: false,
        });
        assert_eq!(profile.segments.len(), 2);
        assert_eq!(profile.total_tokens(), 4800);
        assert_eq!(profile.total_turns(), 8);
        assert_eq!(profile.total_findings(), 6);
        assert_eq!(profile.total_elapsed(), Duration::from_secs(160));
    }

    #[test]
    fn profile_empty_has_zero_totals() {
        let profile = RunProfile::new();
        assert_eq!(profile.total_tokens(), 0);
        assert_eq!(profile.total_turns(), 0);
        assert_eq!(profile.total_findings(), 0);
        assert_eq!(profile.total_elapsed(), Duration::ZERO);
    }

    #[test]
    fn profile_render_report_includes_all_segments() {
        let mut profile = RunProfile::new();
        profile.push_segment(ProfileSegment {
            label: "recon".into(),
            tokens: LedgerDelta { input: 1000, output: 500, cache_read: 200, turns: 3 },
            elapsed: Duration::from_secs(100),
            turns: 3,
            findings_delta: 2,
            completed: true,
        });
        let report = profile.render_report();
        assert!(report.contains("Run Profile"));
        assert!(report.contains("recon"));
        assert!(report.contains("TOTAL"));
        assert!(report.contains("✓"));
    }

    #[test]
    fn profile_budget_warnings_rendered() {
        let mut profile = RunProfile::new();
        profile.push_budget_warning("Turn budget exceeded: 82/80".into());
        let report = profile.render_report();
        assert!(report.contains("Budget advisories"));
        assert!(report.contains("Turn budget exceeded"));
    }

    #[test]
    fn profile_json_roundtrip() {
        let mut profile = RunProfile::new();
        profile.push_segment(ProfileSegment {
            label: "recon".into(),
            tokens: LedgerDelta { input: 1000, output: 500, cache_read: 200, turns: 3 },
            elapsed: Duration::from_secs(60),
            turns: 3,
            findings_delta: 1,
            completed: true,
        });
        let json = profile.to_json();
        assert_eq!(json["segments"].as_array().unwrap().len(), 1);
        assert_eq!(json["totals"]["tokens"].as_u64().unwrap(), 1700);
        assert_eq!(json["totals"]["turns"].as_u64().unwrap(), 3);

        // Verify serialization/deserialization roundtrip.
        let json_str = serde_json::to_string_pretty(&json).unwrap();
        let deser: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(json, deser);
    }

    #[test]
    fn profile_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = RunProfile::new();
        profile.push_segment(ProfileSegment {
            label: "recon".into(),
            tokens: LedgerDelta { input: 500, output: 200, cache_read: 100, turns: 2 },
            elapsed: Duration::from_secs(30),
            turns: 2,
            findings_delta: 1,
            completed: true,
        });
        profile.save(Some(dir.path().to_str().unwrap())).unwrap();

        let path = dir.path().join(".chen").join("agent-state").join("profile.json");
        let content = std::fs::read_to_string(path).unwrap();
        let loaded: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded["segments"][0]["label"].as_str().unwrap(), "recon");
        assert_eq!(loaded["totals"]["tokens"].as_u64().unwrap(), 800);
    }

    // -----------------------------------------------------------------------
    // format_duration
    // -----------------------------------------------------------------------

    #[test]
    fn format_duration_compact() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(5)), "5s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(format_duration(Duration::from_secs(600)), "10m0s");
    }

    // -----------------------------------------------------------------------
    // TokenLedger turns counter
    // -----------------------------------------------------------------------

    #[test]
    fn ledger_turns_counter_increments_per_record() {
        let mut ledger = TokenLedger::default();
        assert_eq!(ledger.turns, 0);
        ledger.record_usage(100, 50, Some(10));
        assert_eq!(ledger.turns, 1);
        ledger.record_usage(200, 100, None);
        assert_eq!(ledger.turns, 2);
    }

    #[test]
    fn ledger_total_tokens() {
        let mut ledger = TokenLedger::default();
        ledger.record_usage(100, 50, Some(10));
        assert_eq!(ledger.total_tokens(), 160);
    }
}
