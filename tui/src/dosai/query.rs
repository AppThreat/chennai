//! Query formatters for the dosai (.NET) JSON schema.
//!
//! dosai emits up to three independent files, two of which this layer reads:
//! - `dosai-dataflows.json` — the primary report: data-flow `Nodes`/`Edges`/`Slices`,
//!   `WeaknessCandidates`, `DangerousApiReachability`, `PackageReachability`, and
//!   `EntryPoints` (which already carry HTTP route + authorization metadata).
//! - `dosai-methods.json` — method inventory, `MethodCalls`, `CallGraph`, `ApiEndpoints`.
//!
//! # Schema reference (verified against dosai 3.0.5 output + source models)
//! dosai serializes with **PascalCase** keys. Source positions are flat
//! `FileName` + `LineNumber` fields (no nested `range`/`position`). The methods
//! report is optional: `dosai methods` can fail to load assemblies on some inputs,
//! so every methods-backed query degrades gracefully to a clear message.

use crate::shared::{field_i64, field_str, pattern_match, ListHeader};
use serde_json::Value;
use std::collections::HashMap;

/// Build an index of data-flow node `Id` → node object, for resolving the `SourceId`,
/// `SinkId`, and `NodeIds` references that dosai uses instead of inline names.
fn node_index(dataflows: &Value) -> HashMap<&str, &Value> {
    let mut idx = HashMap::new();
    if let Some(nodes) = dataflows["Nodes"].as_array() {
        for n in nodes {
            if let Some(id) = n["Id"].as_str() {
                idx.insert(id, n);
            }
        }
    }
    idx
}

/// Render a node reference as `Name (file:line)`, resolving through `idx` when possible.
fn node_label(id: &str, idx: &HashMap<&str, &Value>) -> String {
    match idx.get(id) {
        Some(node) => {
            let name = node["Name"].as_str().or_else(|| node["Symbol"].as_str()).unwrap_or(id);
            let (file, line) = dosai_loc(node);
            format!("{name} ({file}:{line})")
        }
        None => id.to_string(),
    }
}

/// Extract a `(filename, line)` position from a dosai entity (flat `FileName`/`LineNumber`).
fn dosai_loc(obj: &Value) -> (String, i64) {
    let file = obj
        .get("FileName")
        .and_then(Value::as_str)
        .or_else(|| obj.get("Path").and_then(Value::as_str))
        .unwrap_or("?");
    (file.to_string(), field_i64(obj, "LineNumber"))
}

/// Render a merged summary from the dataflows report and the optional methods report.
pub fn extract_summary(dataflows: &Value, methods: &Option<Value>) -> String {
    let meta = &dataflows["Metadata"];
    let schema = meta["SchemaVersion"].as_str().unwrap_or("?");
    let version = meta["AnalyzerVersion"].as_str().unwrap_or("?");
    let stats = &dataflows["Statistics"];

    let nodes = field_i64(stats, "NodeCount");
    let edges = field_i64(stats, "EdgeCount");
    let sources = field_i64(stats, "SourceCount");
    let sinks = field_i64(stats, "SinkCount");
    let slices = field_i64(stats, "SliceCount");
    let files = field_i64(stats, "FilesAnalyzed");

    let weaknesses = dataflows["WeaknessCandidates"].as_array().map(|a| a.len()).unwrap_or(0);
    let dangerous = dataflows["DangerousApiReachability"].as_array().map(|a| a.len()).unwrap_or(0);
    let entry_points = dataflows["EntryPoints"].as_array().map(|a| a.len()).unwrap_or(0);

    let mut out = format!(
        "Analysis tool: dosai (schema {schema}, analyzer {version})\n\
         Data-flow: {nodes} nodes, {edges} edges, {sources} sources, {sinks} sinks, {slices} slices\n\
         Files analyzed: {files} | Entry points: {entry_points}\n\
         Weakness candidates: {weaknesses} | Dangerous-API reachability: {dangerous}"
    );

    if let Some(m) = methods {
        let ms = m["Methods"].as_array().map(|a| a.len()).unwrap_or(0);
        let calls = m["MethodCalls"].as_array().map(|a| a.len()).unwrap_or(0);
        let endpoints = m["ApiEndpoints"].as_array().map(|a| a.len()).unwrap_or(0);
        out.push_str(&format!(
            "\nMethods report: {ms} methods, {calls} call sites, {endpoints} API endpoints"
        ));
    } else {
        out.push_str("\nMethods report: not loaded (dataflows-only analysis).");
    }

    out
}

pub fn query_methods(methods: &Option<Value>, pattern: Option<&str>, limit: usize) -> String {
    let ms = match methods.as_ref().and_then(|m| m["Methods"].as_array()) {
        Some(arr) => arr,
        None => return "No method data available (dosai methods report not loaded).".to_string(),
    };

    let mut matched: Vec<&Value> = ms.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|m| {
            field_str(m, "Name").to_lowercase().contains(&pat_lower)
                || field_str(m, "ClassName").to_lowercase().contains(&pat_lower)
                || field_str(m, "SourceSignature").to_lowercase().contains(&pat_lower)
        });
    }

    let show: Vec<&Value> = matched.iter().take(limit).copied().collect();
    let mut lines: Vec<String> = vec![ListHeader {
        title: "Methods",
        total: ms.len(),
        matched: matched.len(),
        shown: show.len(),
    }
    .to_string()];

    for m in show {
        let name = field_str(m, "Name");
        let class = field_str(m, "ClassName");
        let ns = field_str(m, "Namespace");
        let sig = m["SourceSignature"].as_str().or_else(|| m["AssemblySignature"].as_str()).unwrap_or("");
        let (file, line) = dosai_loc(m);

        lines.push(format!("  {ns}.{class}.{name}"));
        if !sig.is_empty() {
            let preview: String = sig.chars().take(120).collect();
            lines.push(format!("         {preview}"));
        }
        lines.push(format!("         {file}:{line}"));
    }

    lines.join("\n")
}

pub fn query_method_calls(methods: &Option<Value>, pattern: Option<&str>, limit: usize) -> String {
    let calls = match methods.as_ref().and_then(|m| m["MethodCalls"].as_array()) {
        Some(arr) => arr,
        None => return "No method call data available (dosai methods report not loaded).".to_string(),
    };

    let mut matched: Vec<&Value> = calls.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|c| {
            field_str(c, "ClassName").to_lowercase().contains(&pat_lower)
                || field_str(c, "CalledMethod").to_lowercase().contains(&pat_lower)
        });
    }

    let show: Vec<&Value> = matched.iter().take(limit).copied().collect();
    let mut lines: Vec<String> = vec![ListHeader {
        title: "Method Calls",
        total: calls.len(),
        matched: matched.len(),
        shown: show.len(),
    }
    .to_string()];

    for c in show {
        let caller = field_str(c, "ClassName");
        let callee = field_str(c, "CalledMethod");
        let (file, line) = dosai_loc(c);
        lines.push(format!("  {caller} → {callee} at {file}:{line}"));
    }

    lines.join("\n")
}

pub fn query_dataflow_nodes(dataflows: &Value, pattern: Option<&str>, limit: usize) -> String {
    let nodes = match dataflows["Nodes"].as_array() {
        Some(arr) => arr,
        None => return "No data-flow node data available.".to_string(),
    };

    let mut matched: Vec<&Value> = nodes.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|n| {
            field_str(n, "Name").to_lowercase().contains(&pat_lower)
                || field_str(n, "Category").to_lowercase().contains(&pat_lower)
                || field_str(n, "Symbol").to_lowercase().contains(&pat_lower)
        });
    }

    let show: Vec<&Value> = matched.iter().take(limit).copied().collect();
    let mut lines: Vec<String> = vec![ListHeader {
        title: "Data-Flow Nodes",
        total: nodes.len(),
        matched: matched.len(),
        shown: show.len(),
    }
    .to_string()];

    for n in show {
        let name = field_str(n, "Name");
        let kind = field_str(n, "Kind");
        let category = field_str(n, "Category");
        let (file, line) = dosai_loc(n);
        let is_source = n["IsSource"].as_bool().unwrap_or(false);
        let is_sink = n["IsSink"].as_bool().unwrap_or(false);
        let tag = if is_source { " [source]" } else if is_sink { " [sink]" } else { "" };
        lines.push(format!("  [{kind}]{tag} {name} ({category}) at {file}:{line}"));
    }

    lines.join("\n")
}

/// Render data-flow slices, ranked by confidence. dosai slices link a source node id to
/// a sink node id with a taint summary and category labels.
pub fn query_slices(dataflows: &Value, pattern: Option<&str>, limit: usize) -> String {
    let slices = match dataflows["Slices"].as_array() {
        Some(arr) => arr,
        None => return "No data-flow slice data available.".to_string(),
    };

    let mut matched: Vec<&Value> = slices
        .iter()
        .filter(|s| {
            pattern_match(field_str(s, "SourceCategory"), pattern)
                || pattern_match(field_str(s, "SinkCategory"), pattern)
                || pattern_match(field_str(s, "Summary"), pattern)
        })
        .collect();

    matched.sort_by_key(|s| std::cmp::Reverse(confidence_rank(field_str(s, "Confidence"))));
    let show: Vec<&Value> = matched.iter().take(limit).copied().collect();

    let idx = node_index(dataflows);
    let mut lines: Vec<String> = vec![ListHeader {
        title: "Data-Flow Slices",
        total: slices.len(),
        matched: matched.len(),
        shown: show.len(),
    }
    .to_string()];

    for s in show {
        let id = field_str(s, "Id");
        let src_cat = field_str(s, "SourceCategory");
        let sink_cat = field_str(s, "SinkCategory");
        let confidence = field_str(s, "Confidence");
        let summary = field_str(s, "Summary");
        let hops = s["NodeIds"].as_array().map(|a| a.len()).unwrap_or(0);
        // Resolve the source/sink node ids to human-readable name + location.
        let src = node_label(field_str(s, "SourceId"), &idx);
        let sink = node_label(field_str(s, "SinkId"), &idx);
        let taint = s["TaintKinds"]
            .as_array()
            .map(|t| t.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();

        lines.push(format!(
            "  [{id}][conf={confidence}] {src_cat} → {sink_cat} ({hops} nodes)"
        ));
        lines.push(format!("         {src} → {sink}"));
        if summary != "?" {
            lines.push(format!("         {summary}"));
        }
        if !taint.is_empty() {
            lines.push(format!("         taint: {taint}"));
        }
    }
    lines.push("Use dosai_trace with a slice id (e.g. dfs1) to expand the full node path.".to_string());

    lines.join("\n")
}

/// Expand one or more data-flow slices into their full ordered node path, resolving each
/// `NodeIds` entry to a name + file:line. `pattern` matches a slice `Id` (e.g. `dfs1`) or
/// a source/sink category; when empty, the highest-confidence slices are shown.
pub fn query_trace(dataflows: &Value, pattern: Option<&str>, limit: usize) -> String {
    let slices = match dataflows["Slices"].as_array() {
        Some(arr) => arr,
        None => return "No data-flow slice data available.".to_string(),
    };

    let mut matched: Vec<&Value> = slices
        .iter()
        .filter(|s| {
            pattern_match(field_str(s, "Id"), pattern)
                || pattern_match(field_str(s, "SourceCategory"), pattern)
                || pattern_match(field_str(s, "SinkCategory"), pattern)
        })
        .collect();
    matched.sort_by_key(|s| std::cmp::Reverse(confidence_rank(field_str(s, "Confidence"))));

    if matched.is_empty() {
        return format!("No data-flow slice matching '{}' found.", pattern.unwrap_or(""));
    }

    let idx = node_index(dataflows);
    let mut lines: Vec<String> = Vec::new();
    for s in matched.into_iter().take(limit) {
        let id = field_str(s, "Id");
        let confidence = field_str(s, "Confidence");
        lines.push(format!("# Slice {id} (confidence {confidence})"));
        match s["NodeIds"].as_array() {
            Some(node_ids) if !node_ids.is_empty() => {
                for (step, nid) in node_ids.iter().filter_map(Value::as_str).enumerate() {
                    lines.push(format!("  {}. {}", step + 1, node_label(nid, &idx)));
                }
            }
            _ => lines.push("  (no node path recorded)".to_string()),
        }
    }

    lines.join("\n")
}

/// List API endpoints with route, verb, handler, and authorization status.
///
/// Prefers the dataflows report's `EntryPoints` (always available and carrying HTTP
/// metadata) and falls back to the methods report's `ApiEndpoints`.
pub fn query_endpoints(dataflows: &Value, methods: &Option<Value>, pattern: Option<&str>) -> String {
    // Prefer dataflows EntryPoints that look like HTTP routes.
    if let Some(eps) = dataflows["EntryPoints"].as_array() {
        let http: Vec<&Value> = eps
            .iter()
            .filter(|e| e.get("Route").and_then(Value::as_str).is_some() || field_str(e, "Kind").contains("Http"))
            .filter(|e| pattern_match(field_str(e, "Route"), pattern) || pattern_match(field_str(e, "Kind"), pattern))
            .collect();
        if !http.is_empty() {
            let mut lines: Vec<String> = vec![format!("# API Endpoints ({} from dataflows entry points)", http.len())];
            for e in http {
                let verb = field_str(e, "HttpMethod");
                let route = field_str(e, "Route");
                let anon = e["AllowAnonymous"].as_bool().unwrap_or(false);
                let policies = e["AuthorizationPolicies"].as_array().map(|a| a.len()).unwrap_or(0);
                let auth = if anon { " [anonymous]" } else if policies > 0 { " [auth]" } else { "" };
                let (file, line) = dosai_loc(e);
                lines.push(format!("  {verb} {route}{auth} at {file}:{line}"));
            }
            return lines.join("\n");
        }
    }

    // Fall back to the methods report's ApiEndpoints.
    let endpoints = match methods.as_ref().and_then(|m| m["ApiEndpoints"].as_array()) {
        Some(arr) => arr,
        None => return "No API endpoint data available.".to_string(),
    };

    let matched: Vec<&Value> = endpoints
        .iter()
        .filter(|ep| pattern_match(field_str(ep, "Route"), pattern) || pattern_match(field_str(ep, "MethodName"), pattern))
        .collect();

    let mut lines: Vec<String> = vec![format!("# API Endpoints ({} total)", matched.len())];
    for ep in matched {
        let verb = field_str(ep, "HttpMethod");
        let route = field_str(ep, "Route");
        let handler = field_str(ep, "MethodName");
        let anon = ep["AllowAnonymous"].as_bool().unwrap_or(false);
        let required = ep["AuthorizationRequired"].as_bool().unwrap_or(false);
        let auth = if anon { " [anonymous]" } else if required { " [auth]" } else { "" };
        lines.push(format!("  {verb} {route} → {handler}{auth}"));
    }

    lines.join("\n")
}

pub fn query_weakness_candidates(dataflows: &Value, limit: usize) -> String {
    let candidates = match dataflows["WeaknessCandidates"].as_array() {
        Some(arr) => arr,
        None => return "No weakness candidate data available.".to_string(),
    };

    let mut sorted: Vec<&Value> = candidates.iter().collect();
    sorted.sort_by_key(|c| std::cmp::Reverse(confidence_rank(field_str(c, "Confidence"))));
    let show: Vec<&Value> = sorted.iter().take(limit).copied().collect();

    let mut lines: Vec<String> = vec![format!(
        "# Weakness Candidates ({} total, showing first {})",
        candidates.len(),
        show.len()
    )];

    for c in show {
        let cwe = field_str(c, "Cwe");
        let kind = field_str(c, "Kind");
        let confidence = field_str(c, "Confidence");
        let summary = field_str(c, "Summary");
        let src_loc = field_str(c, "SourceLocation");
        let sink_loc = field_str(c, "SinkLocation");

        lines.push(format!("  [{confidence}] {cwe} — {kind}"));
        if summary != "?" {
            lines.push(format!("         {summary}"));
        }
        lines.push(format!("         source: {src_loc} → sink: {sink_loc}"));
    }

    lines.join("\n")
}

pub fn query_dangerous_apis(dataflows: &Value, pattern: Option<&str>, limit: usize) -> String {
    let apis = match dataflows["DangerousApiReachability"].as_array() {
        Some(arr) => arr,
        None => return "No dangerous API reachability data available.".to_string(),
    };

    let mut matched: Vec<&Value> = apis.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|a| {
            field_str(a, "Symbol").to_lowercase().contains(&pat_lower)
                || field_str(a, "Category").to_lowercase().contains(&pat_lower)
        });
    }

    let show: Vec<&Value> = matched.iter().take(limit).copied().collect();
    let mut lines: Vec<String> = vec![ListHeader {
        title: "Dangerous API Reachability",
        total: apis.len(),
        matched: matched.len(),
        shown: show.len(),
    }
    .to_string()];

    for a in show {
        let symbol = field_str(a, "Symbol");
        let category = field_str(a, "Category");
        let confidence = field_str(a, "Confidence");
        let reachable = !a["SliceIds"].as_array().map(|s| s.is_empty()).unwrap_or(true);
        let reach_str = if reachable { "REACHABLE" } else { "present (no flow)" };
        lines.push(format!("  [{category}][{confidence}][{reach_str}] {symbol}"));
    }

    lines.join("\n")
}

pub fn query_security_signals(dataflows: &Value, pattern: Option<&str>, limit: usize) -> String {
    let mut lines: Vec<String> = Vec::new();
    let weakness = query_weakness_candidates(dataflows, limit);
    if !weakness.contains("No weakness candidate") {
        lines.push(weakness);
    }
    let dangerous = query_dangerous_apis(dataflows, pattern, limit);
    if !dangerous.contains("No dangerous API") {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(dangerous);
    }
    if lines.is_empty() {
        return "No security signal data available.".to_string();
    }
    lines.join("\n")
}

pub fn detail_method(methods: &Option<Value>, name: &str) -> String {
    let ms = match methods.as_ref().and_then(|m| m["Methods"].as_array()) {
        Some(arr) => arr,
        None => return "No method data available (dosai methods report not loaded).".to_string(),
    };

    let name_lower = name.to_lowercase();
    let matches: Vec<&Value> = ms
        .iter()
        .filter(|m| {
            field_str(m, "Name").to_lowercase() == name_lower
                || field_str(m, "SourceSignature").to_lowercase().contains(&name_lower)
                || field_str(m, "ClassName").to_lowercase().contains(&name_lower)
        })
        .collect();

    if matches.is_empty() {
        return format!("No method matching '{name}' found.");
    }

    let mut lines: Vec<String> = Vec::new();
    for m in matches.iter().take(10) {
        let name = field_str(m, "Name");
        let class = field_str(m, "ClassName");
        let ns = field_str(m, "Namespace");
        let sig = field_str(m, "SourceSignature");
        let (file, line) = dosai_loc(m);
        let assembly = field_str(m, "Assembly");
        let ret = field_str(m, "ReturnType");

        lines.push(format!("# Method: {ns}.{class}.{name}"));
        lines.push(format!("  Assembly: {assembly}"));
        lines.push(format!("  Returns: {ret}"));
        lines.push(format!("  Location: {file}:{line}"));
        if sig != "?" {
            lines.push(format!("  Signature: {sig}"));
        }
    }

    lines.join("\n")
}

/// Rank a confidence label so `high > medium > low > unknown`.
fn confidence_rank(confidence: &str) -> u8 {
    match confidence.to_lowercase().as_str() {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Fixture mirroring the real dosai 3.0.5 dataflows schema (PascalCase, flat
    /// `FileName`/`LineNumber`, `EntryPoints` carrying HTTP route metadata).
    fn test_dataflows() -> Value {
        json!({
            "Metadata": { "SchemaVersion": "3.3.0", "AnalyzerVersion": "3.0.5.0" },
            "Statistics": { "SourceCount": 2, "SinkCount": 1, "SliceCount": 1, "NodeCount": 4, "EdgeCount": 3, "FilesAnalyzed": 5 },
            "Nodes": [
                { "Id": "dfn1", "Name": "key", "Kind": "Source", "Category": "crypto-material", "FileName": "LocalStorageInterop.cs", "LineNumber": 20, "IsSource": true, "IsSink": false, "Symbol": "HasKey" },
                { "Id": "dfn9", "Name": "Deserialize", "Kind": "Sink", "Category": "deserialization", "FileName": "LocalStorageInterop.cs", "LineNumber": 22, "IsSource": false, "IsSink": true, "Symbol": "JsonSerializer.Deserialize" }
            ],
            "Slices": [
                { "Id": "dfs1", "SourceId": "dfn1", "SinkId": "dfn9", "SourceCategory": "crypto-material", "SinkCategory": "deserialization", "Summary": "Data flows from dfn1 to Deserialize argument 0.", "TaintKinds": ["secret", "crypto-key"], "NodeIds": ["dfn1", "dfn2", "dfn3", "dfn9"], "Confidence": "Medium" }
            ],
            "WeaknessCandidates": [
                { "Id": "wc1", "Kind": "UnsafeDeserializationCandidate", "Cwe": "CWE-502", "Confidence": "High", "Summary": "crypto-material data reaches deserialization sink Deserialize.", "SourceLocation": "LocalStorageInterop.cs:20:81", "SinkLocation": "LocalStorageInterop.cs:22:15" }
            ],
            "DangerousApiReachability": [
                { "Id": "dar1", "Category": "crypto", "Symbol": "System.Security.Cryptography.AesGcm.Encrypt(...)", "Confidence": "High", "SliceIds": ["dfs32"] }
            ],
            "PackageReachability": [
                { "Purl": "pkg:nuget/Asp.Versioning.Abstractions@6.1.0", "Reachable": true, "Confidence": "High", "Categories": ["http", "input"] }
            ],
            "EntryPoints": [
                { "Id": "ep1", "Kind": "HttpMinimalApi", "FileName": "CategoriesApi.cs", "LineNumber": 7, "HttpMethod": "GET", "Route": "/categories", "AllowAnonymous": false, "AuthorizationPolicies": ["RequireAdmin"] }
            ]
        })
    }

    /// Fixture mirroring the real dosai 3.0.5 methods schema (`MethodsSlice` model).
    fn test_methods() -> Value {
        json!({
            "Methods": [
                { "Name": "Index", "ClassName": "HomeController", "Namespace": "MyApp.Web", "ReturnType": "IActionResult", "SourceSignature": "IActionResult Index()", "FileName": "HomeController.cs", "LineNumber": 10, "Assembly": "MyApp.dll" }
            ],
            "MethodCalls": [
                { "ClassName": "HomeController", "CalledMethod": "ExecuteQuery", "FileName": "HomeController.cs", "LineNumber": 12 }
            ],
            "ApiEndpoints": [
                { "Route": "/api/login", "HttpMethod": "POST", "MethodName": "Login", "ClassName": "AuthController", "AllowAnonymous": true, "AuthorizationRequired": false }
            ]
        })
    }

    #[test]
    fn test_extract_summary_reads_statistics() {
        let summary = extract_summary(&test_dataflows(), &Some(test_methods()));
        assert!(summary.contains("dosai"));
        assert!(summary.contains("4 nodes, 3 edges, 2 sources, 1 sinks, 1 slices"));
        assert!(summary.contains("Weakness candidates: 1"));
        assert!(summary.contains("1 methods"));
    }

    #[test]
    fn test_extract_summary_without_methods() {
        let summary = extract_summary(&test_dataflows(), &None);
        assert!(summary.contains("Methods report: not loaded"));
    }

    #[test]
    fn test_query_methods() {
        let result = query_methods(&Some(test_methods()), Some("index"), 50);
        assert!(result.contains("MyApp.Web.HomeController.Index"));
        assert!(result.contains("HomeController.cs:10"));
    }

    #[test]
    fn test_query_method_calls() {
        let result = query_method_calls(&Some(test_methods()), None, 50);
        assert!(result.contains("HomeController → ExecuteQuery"));
        assert!(result.contains("HomeController.cs:12"));
    }

    #[test]
    fn test_query_dataflow_nodes() {
        let result = query_dataflow_nodes(&test_dataflows(), Some("deserialize"), 50);
        assert!(result.contains("[source]") || result.contains("[sink]"));
        assert!(result.contains("deserialization"));
        assert!(result.contains("LocalStorageInterop.cs:22"));
    }

    #[test]
    fn test_query_slices_resolves_node_names() {
        let result = query_slices(&test_dataflows(), None, 50);
        assert!(result.contains("crypto-material → deserialization"));
        assert!(result.contains("taint: secret, crypto-key"));
        // Source/sink ids resolved to names + location.
        assert!(result.contains("key (LocalStorageInterop.cs:20)"));
        assert!(result.contains("Deserialize (LocalStorageInterop.cs:22)"));
    }

    #[test]
    fn test_query_trace_expands_node_path() {
        let result = query_trace(&test_dataflows(), Some("dfs1"), 50);
        assert!(result.contains("# Slice dfs1"));
        assert!(result.contains("1. key (LocalStorageInterop.cs:20)"));
        // Unresolved intermediate ids fall back to the raw id.
        assert!(result.contains("2. dfn2"));
        assert!(result.contains("4. Deserialize (LocalStorageInterop.cs:22)"));
    }

    #[test]
    fn test_query_endpoints_prefers_dataflows_entrypoints() {
        let result = query_endpoints(&test_dataflows(), &Some(test_methods()), None);
        assert!(result.contains("dataflows entry points"));
        assert!(result.contains("GET /categories"));
        assert!(result.contains("[auth]"));
    }

    #[test]
    fn test_query_endpoints_falls_back_to_methods() {
        let mut df = test_dataflows();
        df["EntryPoints"] = json!([]);
        let result = query_endpoints(&df, &Some(test_methods()), None);
        assert!(result.contains("POST /api/login → Login"));
        assert!(result.contains("[anonymous]"));
    }

    #[test]
    fn test_query_weakness_candidates() {
        let result = query_weakness_candidates(&test_dataflows(), 50);
        assert!(result.contains("CWE-502"));
        assert!(result.contains("UnsafeDeserializationCandidate"));
        assert!(result.contains("LocalStorageInterop.cs:20:81"));
    }

    #[test]
    fn test_query_dangerous_apis() {
        let result = query_dangerous_apis(&test_dataflows(), Some("crypto"), 50);
        assert!(result.contains("AesGcm.Encrypt"));
        assert!(result.contains("REACHABLE"));
    }

    #[test]
    fn test_detail_method() {
        let result = detail_method(&Some(test_methods()), "Index");
        assert!(result.contains("Method: MyApp.Web.HomeController.Index"));
        assert!(result.contains("MyApp.dll"));
    }

    #[test]
    fn test_missing_methods_report_is_graceful() {
        assert!(query_methods(&None, None, 50).contains("not loaded"));
        assert!(query_method_calls(&None, None, 50).contains("not loaded"));
        assert!(detail_method(&None, "x").contains("not loaded"));
    }

    #[test]
    fn test_empty_reports() {
        let empty = json!({});
        assert!(query_dataflow_nodes(&empty, None, 50).contains("No data-flow node"));
        assert!(query_security_signals(&empty, None, 50).contains("No security signal data"));
    }
}
