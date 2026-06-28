//! Field mappings for the dosai (.NET) JSON schema.
//!
//! dosai emits two independent output files:
//! - `dosai-dataflows.json`: `metadata, entryPoints[], nodes[], edges[], slices[],
//!   patterns{}, methodSummaries[], packageReachability[], dangerousApiReachability[],
//!   weaknessCandidates[], statistics, diagnostics`
//! - `dosai-methods.json`: `methods[], methodCalls[], callGraph, apiEndpoints[],
//!   entryPoints[], packageReachability[], assemblyInformation[]`
//!
//! The query functions below read from the merged reports passed as `(dataflows, methods)`.

use crate::shared::{field_i64, field_str, ListHeader};
use serde_json::Value;

/// Render a merged summary from both dosai reports.
pub fn extract_summary(dataflows: &Value, methods: &Option<Value>) -> String {
    let tool_name = "dosai";
    let stats = &dataflows["statistics"];

    let total_methods = field_i64(stats, "totalMethods");
    let total_nodes = field_i64(stats, "totalNodes");
    let total_edges = field_i64(stats, "totalEdges");
    let total_slices = field_i64(stats, "totalSlices");
    let total_endpoints = field_i64(stats, "totalEndpoints");
    let total_weakness = field_i64(stats, "totalWeaknessCandidates");

    let mut out = format!(
        "Analysis tool: {tool_name}\n\
         Methods: {total_methods} | Data-flow nodes: {total_nodes} | Edges: {total_edges}\n\
         Slices: {total_slices} | API endpoints: {total_endpoints} | Weakness candidates: {total_weakness}"
    );

    if let Some(m) = methods {
        let ms = m["methods"].as_array().map(|a| a.len()).unwrap_or(0);
        let calls = m["methodCalls"].as_array().map(|a| a.len()).unwrap_or(0);
        let endpoints = m["apiEndpoints"].as_array().map(|a| a.len()).unwrap_or(0);
        out.push_str(&format!(
            "\nMethods report: {ms} methods, {calls} calls, {endpoints} API endpoints"
        ));
    }

    out
}

pub fn query_methods(methods: &Option<Value>, pattern: Option<&str>, limit: usize) -> String {
    let ms = match methods {
        Some(m) => m["methods"].as_array(),
        None => None,
    };
    let ms = match ms {
        Some(arr) => arr,
        None => return "No method data available (dosai methods report not loaded).".to_string(),
    };

    let mut matched: Vec<&Value> = ms.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|m| {
            m["name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || m["signature"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Methods", total: ms.len(), matched: matched.len(), shown: show.len() }.to_string());

    for m in show {
        let name = field_str(m, "name");
        let sig = field_str(m, "signature");
        let file = field_str(m, "file");
        let line = field_i64(m, "line");
        let is_entry = m["isEntryPoint"].as_bool().unwrap_or(false);
        let entry = if is_entry { " [entry]" } else { "" };

        lines.push(format!("  {name}{entry}"));
        if !sig.is_empty() && sig != "?" {
            let preview: String = sig.chars().take(100).collect();
            lines.push(format!("         {preview}"));
        }
        lines.push(format!("         {file}:{line}"));
    }

    lines.join("\n")
}

pub fn query_method_calls(methods: &Option<Value>, pattern: Option<&str>, limit: usize) -> String {
    let calls = match methods {
        Some(m) => m["methodCalls"].as_array(),
        None => None,
    };
    let calls = match calls {
        Some(arr) => arr,
        None => return "No method call data available.".to_string(),
    };

    let mut matched: Vec<&Value> = calls.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|c| {
            c["caller"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || c["callee"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Method Calls", total: calls.len(), matched: matched.len(), shown: show.len() }.to_string());

    for c in show {
        let caller = field_str(c, "caller");
        let callee = field_str(c, "callee");
        let file = field_str(c, "file");
        let line = field_i64(c, "line");
        lines.push(format!("  {caller} → {callee} at {file}:{line}"));
    }

    lines.join("\n")
}

pub fn query_dataflow_nodes(dataflows: &Value, pattern: Option<&str>, limit: usize) -> String {
    let nodes = match dataflows["nodes"].as_array() {
        Some(arr) => arr,
        None => return "No data-flow node data available.".to_string(),
    };

    let mut matched: Vec<&Value> = nodes.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|n| {
            n["name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || n["kind"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Data-Flow Nodes", total: nodes.len(), matched: matched.len(), shown: show.len() }.to_string());

    for n in show {
        let name = field_str(n, "name");
        let kind = field_str(n, "kind");
        let file = field_str(n, "file");
        let line = field_i64(n, "line");
        let is_source = n["isSource"].as_bool().unwrap_or(false);
        let is_sink = n["isSink"].as_bool().unwrap_or(false);
        let tags = if is_source { " [source]" } else if is_sink { " [sink]" } else { "" };
        lines.push(format!("  [{kind}]{tags} {name} at {file}:{line}"));
    }

    lines.join("\n")
}

pub fn query_slices(dataflows: &Value, pattern: Option<&str>, limit: usize) -> String {
    let slices = match dataflows["slices"].as_array() {
        Some(arr) => arr,
        None => return "No data-flow slice data available.".to_string(),
    };

    let matched: Vec<&Value> = if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        slices
            .iter()
            .filter(|s| {
                s["sourceName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                    || s["sinkName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                    || s["ruleName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
            })
            .take(limit)
            .collect()
    } else {
        slices.iter().take(limit).collect()
    };

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# Data-Flow Slices ({} total, showing {})", slices.len(), matched.len()));

    for s in matched {
        let src = field_str(s, "sourceName");
        let sink = field_str(s, "sinkName");
        let rule = field_str(s, "ruleName");
        let path_len = field_i64(s, "pathLength");
        let method = field_str(s, "methodSummary");

        lines.push(format!("  [{rule}] {src} → {sink} ({path_len} steps)"));
        if !method.is_empty() && method != "?" {
            lines.push(format!("         method: {method}"));
        }
    }

    lines.join("\n")
}

pub fn query_endpoints(methods: &Option<Value>, pattern: Option<&str>) -> String {
    let endpoints = match methods {
        Some(m) => m["apiEndpoints"].as_array(),
        None => None,
    };
    let endpoints = match endpoints {
        Some(arr) => arr,
        None => return "No API endpoint data available.".to_string(),
    };

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# API Endpoints ({} total)", endpoints.len()));

    for ep in endpoints {
        let route = field_str(ep, "route");
        let verb = field_str(ep, "verb");
        let handler = field_str(ep, "handler");
        let auth = ep["requiresAuth"].as_bool().unwrap_or(false);
        let auth_str = if auth { " [auth]" } else { "" };

        if let Some(pat) = pattern {
            let pat_lower = pat.to_lowercase();
            if !route.to_lowercase().contains(&pat_lower)
                && !handler.to_lowercase().contains(&pat_lower)
            {
                continue;
            }
        }

        lines.push(format!("  {verb} {route} → {handler}{auth_str}"));
    }

    lines.join("\n")
}

pub fn query_weakness_candidates(dataflows: &Value, limit: usize) -> String {
    let candidates = match dataflows["weaknessCandidates"].as_array() {
        Some(arr) => arr,
        None => return "No weakness candidate data available.".to_string(),
    };

    let show = candidates.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# Weakness Candidates ({} total, showing first {})", candidates.len(), show.len()));

    for c in show {
        let cwe = field_str(c, "cweId");
        let name = field_str(c, "name");
        let severity = field_str(c, "severity");
        let desc = field_str(c, "description");
        let file = field_str(c, "file");
        let line = field_i64(c, "line");

        lines.push(format!("  [{severity}] {cwe} — {name}"));
        lines.push(format!("         {desc}"));
        lines.push(format!("         {file}:{line}"));
    }

    lines.join("\n")
}

pub fn query_dangerous_apis(dataflows: &Value, pattern: Option<&str>, limit: usize) -> String {
    let apis = match dataflows["dangerousApiReachability"].as_array() {
        Some(arr) => arr,
        None => return "No dangerous API reachability data available.".to_string(),
    };

    let mut matched: Vec<&Value> = apis.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|a| {
            a["api"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || a["method"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Dangerous API Reachability", total: apis.len(), matched: matched.len(), shown: show.len() }.to_string());

    for a in show {
        let api = field_str(a, "api");
        let method = field_str(a, "method");
        let reachable = a["isReachable"].as_bool().unwrap_or(false);
        let reachable_str = if reachable { "REACHABLE" } else { "not reachable" };
        lines.push(format!("  {api} ({reachable_str}) via {method}"));
    }

    lines.join("\n")
}

pub fn query_security_signals(dataflows: &Value, pattern: Option<&str>, limit: usize) -> String {
    // Combine weakness candidates and dangerous API reachability into a unified security signals output.
    let mut lines: Vec<String> = Vec::new();
    let weakness = query_weakness_candidates(dataflows, limit);
    if !weakness.contains("No weakness candidate") {
        lines.push(weakness);
    }
    let dangerous = query_dangerous_apis(dataflows, pattern, limit);
    if !dangerous.contains("No dangerous API") {
        lines.push(String::new());
        lines.push(dangerous);
    }
    if lines.is_empty() {
        return "No security signal data available.".to_string();
    }
    lines.join("\n")
}

pub fn detail_method(methods: &Option<Value>, name: &str) -> String {
    let ms = match methods {
        Some(m) => m["methods"].as_array(),
        None => None,
    };
    let ms = match ms {
        Some(arr) => arr,
        None => return "No method data available.".to_string(),
    };

    let name_lower = name.to_lowercase();
    let matches: Vec<&Value> = ms
        .iter()
        .filter(|m| {
            m["name"].as_str().unwrap_or("").to_lowercase() == name_lower
                || m["signature"].as_str().unwrap_or("").to_lowercase().contains(&name_lower)
        })
        .collect();

    if matches.is_empty() {
        return format!("No method matching '{name}' found.");
    }

    let mut lines: Vec<String> = Vec::new();
    for m in matches {
        let name = field_str(m, "name");
        let sig = field_str(m, "signature");
        let file = field_str(m, "file");
        let line = field_i64(m, "line");
        let assembly = field_str(m, "assembly");

        lines.push(format!("# Method: {name}"));
        lines.push(format!("  Assembly: {assembly}"));
        lines.push(format!("  Location: {file}:{line}"));
        if !sig.is_empty() && sig != "?" {
            lines.push(format!("  Signature:\n    {sig}"));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_dataflows() -> Value {
        json!({
            "statistics": {
                "totalMethods": 10,
                "totalNodes": 5,
                "totalEdges": 3,
                "totalSlices": 2,
                "totalEndpoints": 3,
                "totalWeaknessCandidates": 1
            },
            "nodes": [
                { "name": "GetUserInput", "kind": "method", "file": "Controllers/HomeController.cs", "line": 15, "isSource": true, "isSink": false },
                { "name": "ExecuteQuery", "kind": "method", "file": "Data/DbContext.cs", "line": 42, "isSource": false, "isSink": true }
            ],
            "edges": [
                { "sourceId": "1", "targetId": "2", "label": "call" }
            ],
            "slices": [
                { "sourceName": "GetUserInput", "sinkName": "ExecuteQuery", "ruleName": "user-input-to-sql", "pathLength": 3, "methodSummary": "HomeController.Index" }
            ],
            "weaknessCandidates": [
                { "cweId": "CWE-89", "name": "SQL Injection", "severity": "high", "description": "User input flows to SQL query", "file": "Controllers/HomeController.cs", "line": 15 }
            ],
            "dangerousApiReachability": [
                { "api": "SqlCommand.ExecuteReader", "method": "Data.DbContext.ExecuteQuery", "isReachable": true }
            ]
        })
    }

    fn test_methods() -> Value {
        json!({
            "methods": [
                { "name": "Index", "signature": "IActionResult Index()", "file": "Controllers/HomeController.cs", "line": 10, "assembly": "MyApp.dll", "isEntryPoint": true },
                { "name": "ExecuteQuery", "signature": "SqlDataReader ExecuteQuery(string sql)", "file": "Data/DbContext.cs", "line": 42, "assembly": "MyApp.Data.dll", "isEntryPoint": false }
            ],
            "methodCalls": [
                { "caller": "Index", "callee": "ExecuteQuery", "file": "Controllers/HomeController.cs", "line": 12 }
            ],
            "apiEndpoints": [
                { "route": "/api/users", "verb": "GET", "handler": "UsersController.List", "requiresAuth": true },
                { "route": "/api/login", "verb": "POST", "handler": "AuthController.Login", "requiresAuth": false }
            ]
        })
    }

    #[test]
    fn test_extract_summary() {
        let summary = extract_summary(&test_dataflows(), &Some(test_methods()));
        assert!(summary.contains("dosai"));
        assert!(summary.contains("Methods: 10"));
        assert!(summary.contains("2 API endpoints"));
    }

    #[test]
    fn test_query_methods() {
        let result = query_methods(&Some(test_methods()), Some("Index"), 50);
        assert!(result.contains("Index"));
        assert!(result.contains("Controllers/HomeController.cs:10"));
    }

    #[test]
    fn test_query_method_calls() {
        let result = query_method_calls(&Some(test_methods()), Some("Index"), 50);
        assert!(result.contains("Index"));
        assert!(result.contains("ExecuteQuery"));
    }

    #[test]
    fn test_query_dataflow_nodes() {
        let result = query_dataflow_nodes(&test_dataflows(), Some("GetUserInput"), 50);
        assert!(result.contains("GetUserInput"));
        assert!(result.contains("[source]"));
    }

    #[test]
    fn test_query_slices() {
        let result = query_slices(&test_dataflows(), Some("user-input-to-sql"), 50);
        assert!(result.contains("GetUserInput"));
        assert!(result.contains("ExecuteQuery"));
    }

    #[test]
    fn test_query_endpoints() {
        let result = query_endpoints(&Some(test_methods()), None);
        assert!(result.contains("/api/users"));
        assert!(result.contains("GET"));
        assert!(result.contains("[auth]"));
    }

    #[test]
    fn test_query_weakness_candidates() {
        let result = query_weakness_candidates(&test_dataflows(), 50);
        assert!(result.contains("CWE-89"));
        assert!(result.contains("SQL Injection"));
    }

    #[test]
    fn test_query_dangerous_apis() {
        let result = query_dangerous_apis(&test_dataflows(), Some("SqlCommand"), 50);
        assert!(result.contains("SqlCommand.ExecuteReader"));
        assert!(result.contains("REACHABLE"));
    }

    #[test]
    fn test_detail_method() {
        let result = detail_method(&Some(test_methods()), "Index");
        assert!(result.contains("Index"));
        assert!(result.contains("MyApp.dll"));
    }

    #[test]
    fn test_empty_reports() {
        let empty = json!({});
        assert!(query_methods(&None, None, 50).contains("No method data"));
        assert!(query_endpoints(&None, None).contains("No API endpoint data"));
        assert!(query_security_signals(&empty, None, 50).contains("No security signal data"));
    }
}
