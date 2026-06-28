//! Dosai (.NET) analysis backend — models the `dosai` CLI output.
//!
//! Dosai emits up to three independent JSON output files:
//! - `dosai-dataflows.json` — primary data-flow analysis (nodes, edges, slices, weakness candidates)
//! - `dosai-methods.json` — method inventory, call graph, API endpoints
//! - `dosai-crypto.json` — cryptographic asset evidence
//!
//! This module merges the reports at load time so the query layer can reference both.
//!
//! # Schema notes
//! dosai serializes with **PascalCase** keys and flat `FileName`/`LineNumber` positions.
//! Key top-level arrays:
//! | File | Arrays |
//! |---|---|
//! | dataflows | `Nodes`, `Edges`, `Slices`, `MethodSummaries`, `PackageReachability`, `DangerousApiReachability`, `WeaknessCandidates`, `EntryPoints` |
//! | methods | `Methods`, `MethodCalls`, `ApiEndpoints`, `EntryPoints`, `PackageReachability`, `CallGraph`, `Dependencies` |
//!
//! The methods report is optional — `dosai methods` can fail to load assemblies on some
//! inputs, so the methods-backed tools degrade gracefully when it is absent.

pub mod loader;
pub mod query;
pub mod runner;

pub use loader::DosaiReports;
#[allow(unused_imports)]
pub use runner::{dosai_dataflows_path, dosai_methods_path, run_dosai};

use crate::shared::backend::Backend;
use crate::shared::{make_tool, pattern_match};
use serde_json::{json, Value};

/// Context for dosai analysis mode, holding up to three loaded reports.
#[derive(Clone)]
#[allow(dead_code)]
pub struct DosaiCtx {
    /// The primary dataflows JSON report.
    pub dataflows: loader::LoadedReport,
    /// Optional methods JSON report.
    pub methods: Option<loader::LoadedReport>,
    /// Optional crypto JSON report.
    pub crypto: Option<loader::LoadedReport>,
    /// Path to the source directory being analyzed.
    pub source_root: String,
}

impl DosaiCtx {
    /// Render a merged summary from both dosai reports.
    pub fn summary(&self) -> String {
        let methods_val = self.methods.as_ref().map(|m| m.report.clone());
        query::extract_summary(&self.dataflows.report, &methods_val)
    }

    /// Query indexed entities by kind.
    pub fn query(&self, kind: &str, pattern: Option<&str>, limit: usize) -> String {
        let methods_val = self.methods.as_ref().map(|m| &m.report);
        match kind {
            "methods" => query::query_methods(&methods_val.cloned(), pattern, limit),
            "method_calls" => query::query_method_calls(&methods_val.cloned(), pattern, limit),
            "dependencies" => self.query_dependencies(pattern).unwrap_or_else(|e| e),
            "api_endpoints" | "endpoints" => {
                query::query_endpoints(&self.dataflows.report, &methods_val.cloned(), pattern)
            }
            "entry_points" => self.query_entry_points(pattern),
            "package_reachability" => self.query_package_reachability(pattern, limit),
            "dataflow_nodes" => query::query_dataflow_nodes(&self.dataflows.report, pattern, limit),
            "dataflow_edges" => self.query_dataflow_edges(pattern, limit),
            "security_signals" => query::query_security_signals(&self.dataflows.report, pattern, limit),
            "dataflow" => query::query_slices(&self.dataflows.report, pattern, limit),
            "flows" => query::query_slices(&self.dataflows.report, pattern, limit),
            "trace" => query::query_trace(&self.dataflows.report, pattern, limit),
            "callgraph" => self.callgraph(pattern, limit),
            "detail" => {
                let name = pattern.unwrap_or("");
                let methods_val = self.methods.as_ref().map(|m| &m.report);
                query::detail_method(&methods_val.cloned(), name)
            }
            _ => format!("Unknown query kind '{kind}'. Valid kinds: methods, method_calls, dependencies, api_endpoints, entry_points, package_reachability, dataflow_nodes, dataflow_edges, security_signals, dataflow, flows, trace, callgraph, detail"),
        }
    }

    /// Query the merged call graph (from methods report `methodCalls` + `callGraph`).
    #[allow(dead_code)]
    pub fn callgraph(&self, pattern: Option<&str>, limit: usize) -> String {
        let methods_val = self.methods.as_ref().map(|m| &m.report);
        let mc = query::query_method_calls(&methods_val.cloned(), pattern, limit);
        let cg = self.query_callgraph_edges(pattern, limit);
        format!("{mc}\n\n{cg}")
    }

    /// Query data-flow slices.
    #[allow(dead_code)]
    pub fn dataflow(&self, pattern: Option<&str>, limit: usize) -> String {
        query::query_slices(&self.dataflows.report, pattern, limit)
    }

    /// Get detailed information about a method.
    #[allow(dead_code)]
    pub fn detail(&self, name: &str) -> String {
        let methods_val = self.methods.as_ref().map(|m| &m.report);
        query::detail_method(&methods_val.cloned(), name)
    }

    /// List dependencies, preferring the dataflows `PackageReachability` (which records
    /// whether each package URL is reachable) and falling back to the methods `Dependencies`.
    fn query_dependencies(&self, pattern: Option<&str>) -> Result<String, String> {
        if let Some(arr) = self.dataflows.report["PackageReachability"].as_array() {
            let mut lines: Vec<String> = vec![format!("# Package Reachability ({} total)", arr.len())];
            for dep in arr {
                let purl = dep["Purl"].as_str().unwrap_or("?");
                if !pattern_match(purl, pattern) {
                    continue;
                }
                let reachable = dep["Reachable"].as_bool().unwrap_or(false);
                let confidence = dep["Confidence"].as_str().unwrap_or("?");
                let reach_str = if reachable { "REACHABLE" } else { "not reachable" };
                lines.push(format!("  {purl} ({reach_str}, confidence {confidence})"));
            }
            return Ok(lines.join("\n"));
        }

        if let Some(arr) = self.methods.as_ref().and_then(|m| m.report["Dependencies"].as_array()) {
            let mut lines: Vec<String> = vec![format!("# Dependencies ({} total)", arr.len())];
            for dep in arr {
                let name = dep["Name"].as_str().unwrap_or("?");
                let purl = dep["Purl"].as_str().unwrap_or("?");
                if pattern_match(name, pattern) || pattern_match(purl, pattern) {
                    lines.push(format!("  {name} — {purl}"));
                }
            }
            return Ok(lines.join("\n"));
        }

        Ok("No dependency data available.".to_string())
    }

    /// List analysis entry points (HTTP routes, `Main`, etc.) from the dataflows report.
    fn query_entry_points(&self, pattern: Option<&str>) -> String {
        let entries = self.dataflows.report["EntryPoints"]
            .as_array()
            .or_else(|| self.methods.as_ref().and_then(|m| m.report["EntryPoints"].as_array()));
        match entries {
            Some(arr) => {
                let mut lines: Vec<String> = vec![format!("# Entry Points ({} total)", arr.len())];
                for ep in arr {
                    let kind = ep["Kind"].as_str().unwrap_or("?");
                    let route = ep["Route"].as_str().unwrap_or("");
                    let verb = ep["HttpMethod"].as_str().unwrap_or("");
                    let file = ep["FileName"].as_str().unwrap_or("?");
                    let line = ep["LineNumber"].as_i64().unwrap_or(0);
                    if !pattern_match(kind, pattern) && !pattern_match(route, pattern) {
                        continue;
                    }
                    if route.is_empty() {
                        lines.push(format!("  [{kind}] at {file}:{line}"));
                    } else {
                        lines.push(format!("  [{kind}] {verb} {route} at {file}:{line}"));
                    }
                }
                lines.join("\n")
            }
            None => "No entry point data available.".to_string(),
        }
    }

    /// List package reachability (does taint analysis reach each package URL).
    fn query_package_reachability(&self, pattern: Option<&str>, limit: usize) -> String {
        let reach = self.dataflows.report["PackageReachability"]
            .as_array()
            .or_else(|| self.methods.as_ref().and_then(|m| m.report["PackageReachability"].as_array()));
        match reach {
            Some(arr) => {
                let mut matched: Vec<&serde_json::Value> = arr.iter().collect();
                if let Some(pat) = pattern {
                    matched.retain(|r| pattern_match(r["Purl"].as_str().unwrap_or(""), Some(pat)));
                }
                let show: Vec<&serde_json::Value> = matched.iter().take(limit).copied().collect();
                let mut lines: Vec<String> = vec![format!(
                    "# Package Reachability ({} of {} matched, showing first {})",
                    matched.len(),
                    arr.len(),
                    show.len()
                )];
                for r in show {
                    let purl = r["Purl"].as_str().unwrap_or("?");
                    let reachable = r["Reachable"].as_bool().unwrap_or(false);
                    let reach_str = if reachable { "REACHABLE" } else { "not reachable" };
                    lines.push(format!("  {purl} ({reach_str})"));
                }
                lines.join("\n")
            }
            None => "No package reachability data available.".to_string(),
        }
    }

    /// List data-flow edges from the dataflows report (`SourceId → TargetId` with a label).
    fn query_dataflow_edges(&self, pattern: Option<&str>, limit: usize) -> String {
        let edges = match self.dataflows.report["Edges"].as_array() {
            Some(arr) => arr,
            None => return "No data-flow edge data available.".to_string(),
        };

        let matched: Vec<&serde_json::Value> = if let Some(pat) = pattern {
            let pat_lower = pat.to_lowercase();
            edges
                .iter()
                .filter(|e| {
                    e["Label"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || e["Kind"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                })
                .take(limit)
                .collect()
        } else {
            edges.iter().take(limit).collect()
        };

        let mut lines: Vec<String> =
            vec![format!("# Data-Flow Edges ({} total, showing {})", edges.len(), matched.len())];
        for e in matched {
            let src = e["SourceId"].as_str().unwrap_or("?");
            let tgt = e["TargetId"].as_str().unwrap_or("?");
            let label = e["Label"].as_str().unwrap_or("");
            let kind = e["Kind"].as_str().unwrap_or("");
            lines.push(format!("  {src} → {tgt} [{kind}: {label}]"));
        }
        lines.join("\n")
    }

    /// List call-graph edges from the methods report (`MethodCallEdge` records).
    fn query_callgraph_edges(&self, pattern: Option<&str>, limit: usize) -> String {
        let cg = match &self.methods {
            Some(m) => m.report["CallGraph"].as_object(),
            None => None,
        };
        let edges = match cg.and_then(|c| c["Edges"].as_array()) {
            Some(arr) => arr,
            None => return String::new(),
        };

        let matched: Vec<&serde_json::Value> = if let Some(pat) = pattern {
            let pat_lower = pat.to_lowercase();
            edges
                .iter()
                .filter(|e| {
                    e["SourceId"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || e["TargetId"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || e["CalledMethodName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                })
                .take(limit)
                .collect()
        } else {
            edges.iter().take(limit).collect()
        };

        if matched.is_empty() {
            return String::new();
        }

        let mut lines: Vec<String> = vec![format!("# Call Graph Edges (showing {})", matched.len())];
        for e in matched {
            let caller = e["SourceName"].as_str().or_else(|| e["SourceId"].as_str()).unwrap_or("?");
            let callee = e["TargetName"].as_str().or_else(|| e["TargetId"].as_str()).or_else(|| e["CalledMethodName"].as_str()).unwrap_or("?");
            let call_type = e["CallType"].as_str().unwrap_or("");
            lines.push(format!("  {caller} → {callee} ({call_type})"));
        }
        lines.join("\n")
    }
}

/// Build the dosai-specific system prompt for the LLM agent.
pub fn build_dosai_system_prompt(
    summary_text: &str,
    bom_summary: Option<&str>,
    bom_components: Option<&str>,
    console_history: Option<&str>,
) -> String {
    let bom_section = match (bom_summary, bom_components) {
        (Some(summary), Some(components)) => {
            format!(
                r#"
## Software Bill of Materials (CycloneDX SBOM)
{summary}

Key components:
{components}
"#
            )
        }
        _ => String::new(),
    };

    let console_section = console_history
        .filter(|s| !s.is_empty())
        .map(|s| {
            format!(
                "\n## Console output\nBelow are the recent commands the user ran and their results. Use this context to answer questions about what was shown.\n{s}\n"
            )
        })
        .unwrap_or_default();

    let identity_rules = crate::shared::backend::PROJECT_IDENTITY_RULES;

    format!(
        r#"You are chennai, an AI-powered code & security analysis agent. You are analyzing a .NET codebase using structured analysis reports produced by the dosai tool — not over your training prior.

## Analysis report
{summary_text}{console_section}{bom_section}

## Available tools
- dosai_summary: Re-fetch the summary of the dosai analysis report.
- dosai_query: Query indexed analysis data: methods, method_calls, dependencies, api_endpoints, entry_points, package_reachability, dataflow_nodes, dataflow_edges, security_signals, flows.
- dosai_callgraph: Query the call graph (method calls + call graph edges).
- dosai_flows: Query data-flow slices (source to sink) with resolved source/sink node names + locations.
- dosai_trace: Expand a slice (by id, e.g. dfs1) into its full ordered node path with names and file:line.
- dosai_detail: Get detailed information about a specific method.
- dosai_endpoints: List API endpoints with route, verb, handler, and auth status.
- bom_query: Query the CycloneDX SBOM for dependency information.
- git_diff / git_log / git_show: Read-only git history.
- ripgrep / read_file: Read source file content. Last resort; use dosai tools listed above first.

## How to analyze
1. Call dosai_summary once to understand the .NET codebase structure.
2. Use dosai_query with kind="methods" to find methods.
3. Use dosai_query with kind="api_endpoints" to understand the web surface.
4. Use dosai_callgraph to trace call relationships.
5. Use dosai_flows to find security-relevant data-flow paths.
6. Use dosai_detail to zoom into a specific method.
7. Use dosai_query with kind="package_reachability" to identify reachable dependencies.

## Data model reference
dosai uses PascalCase keys and flat FileName/LineNumber positions.

The dosai dataflows report contains:
- Nodes: Name, Kind, Category, FileName, LineNumber, IsSource, IsSink
- Slices: SourceCategory, SinkCategory, Summary, TaintKinds, NodeIds, Confidence
- WeaknessCandidates: Cwe, Kind, Confidence, Summary, SourceLocation, SinkLocation
- DangerousApiReachability: Symbol, Category, Confidence, SliceIds
- PackageReachability: Purl, Reachable, Confidence, Categories
- EntryPoints: Kind, Route, HttpMethod, AllowAnonymous, AuthorizationPolicies, FileName, LineNumber

The dosai methods report (optional) contains:
- Methods: Name, ClassName, Namespace, SourceSignature, FileName, LineNumber, Assembly
- MethodCalls: ClassName (caller), CalledMethod (callee), FileName, LineNumber
- ApiEndpoints: Route, HttpMethod, MethodName, AllowAnonymous, AuthorizationRequired

{identity_rules}

## Grounding rules
1. NEVER invent call graphs, data flows, taints, sinks, or security findings.
2. **Tool priority**: Use dosai tools FIRST for every query. Only use ripgrep or read_file when all dosai tools have been exhausted for the information you need or when you need a short snippet of surrounding source context. A ripgrep result is weaker evidence than a dosai tool result.
3. If dosai_flows returns NO results, the report lacks usable data-flow analysis.
4. The methods report may be absent; method/call-graph tools will say so. Do not infer methods from grep.
5. For each finding give: file:line, the concrete path, and confidence grounded in tool evidence.

## Response style
Explain architectures and data flows with neat ASCII diagrams where they clarify the structure. Write in straightforward technical prose. Minimise bullet lists; favour short paragraphs or inline descriptions instead. Do not use em-dashes, emoji, or decorative formatting. Every finding must still carry file:line evidence. Keep responses short but substantive. Do not begin every message with "Let me" or similar filler openings. After each tool result, briefly share observations or insights — it keeps the transcript lively and shows your reasoning progress.

You are an authorized security review of the user's own code. Analyze it directly.
"#
    )
}

impl Backend for DosaiCtx {
    fn summary(&self) -> String { self.summary() }
    fn query(&self, kind: &str, pattern: Option<&str>, limit: usize) -> String { self.query(kind, pattern, limit) }
    fn backend_name(&self) -> &'static str { "dosai" }
    fn tool_definitions(&self) -> Vec<Value> { dosai_tool_definitions() }
    fn system_prompt(&self, summary_text: &str, bom_summary: Option<&str>, bom_components: Option<&str>, console_history: Option<&str>) -> String {
        build_dosai_system_prompt(summary_text, bom_summary, bom_components, console_history)
    }
    fn clone_box(&self) -> Box<dyn Backend> { Box::new(self.clone()) }
}

/// Tool definitions for dosai mode.
pub fn dosai_tool_definitions() -> Vec<serde_json::Value> {
    vec![
        dosai_summary_tool(),
        dosai_query_tool(),
        dosai_callgraph_tool(),
        dosai_flows_tool(),
        dosai_trace_tool(),
        dosai_detail_tool(),
        dosai_endpoints_tool(),
    ]
}

fn dosai_trace_tool() -> serde_json::Value {
    make_tool(
        "dosai_trace",
        "Expand a dosai (.NET) data-flow slice into its full ordered node path, resolving each node id to a name and file:line. Use this as the follow-up to dosai_flows whenever you need the concrete step-by-step path (source -> ... -> sink) to report file:line evidence for a finding. Pass a slice id (e.g. 'dfs1') or a source/sink category to select which slice(s) to trace.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Slice id (e.g. dfs1) or source/sink category to trace"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum slices to expand (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }),
    )
}

fn dosai_summary_tool() -> serde_json::Value {
    make_tool(
        "dosai_summary",
        "Return the summary of the dosai (.NET) analysis report: methods, data-flow nodes/edges/slices, API endpoints, weakness candidates. Call this FIRST to orient — the counts tell you which categories of evidence exist so you know which tool to reach for next (e.g. whether there are any flows/endpoints worth investigating).",
        json!({ "type": "object", "properties": {}, "required": [] }),
    )
}

fn dosai_query_tool() -> serde_json::Value {
    make_tool(
        "dosai_query",
        "Primary structured entry point for the dosai (.NET) reports — prefer it over ripgrep for finding any indexed entity, since results carry exact file:line and signatures rather than raw text hits. Indexed entities: methods, method_calls, dependencies, api_endpoints, entry_points, package_reachability, dataflow_nodes, dataflow_edges, security_signals, flows.",
        json!({
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "description": "Entity type to query: methods, method_calls, dependencies, api_endpoints, entry_points, package_reachability, dataflow_nodes, dataflow_edges, security_signals, flows",
                    "enum": ["methods", "method_calls", "dependencies", "api_endpoints", "entry_points", "package_reachability", "dataflow_nodes", "dataflow_edges", "security_signals", "flows"]
                },
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive search pattern"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            },
            "required": ["kind"]
        }),
    )
}

fn dosai_callgraph_tool() -> serde_json::Value {
    make_tool(
        "dosai_callgraph",
        "Query the call graph from the dosai methods report. Shows method calls (caller→callee) and call graph edges matching an optional pattern.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter by caller or callee name"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }),
    )
}

fn dosai_flows_tool() -> serde_json::Value {
    make_tool(
        "dosai_flows",
        "THE authoritative tool for reachability/taint questions in the dosai (.NET) report — 'can untrusted input reach X', injection, or whether a sink is exploitable. Each slice is a source-to-sink path with source name, sink name, rule, path length, and method summary. ripgrep CANNOT prove a path reaches a sink; this can. Reach for it whenever the user asks about vulnerabilities or how data moves, then use dosai_trace to expand a slice into its full node-by-node path.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter slices by source, sink, or rule name"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum slices (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }),
    )
}

fn dosai_detail_tool() -> serde_json::Value {
    make_tool(
        "dosai_detail",
        "Get detailed information about a specific method from the dosai methods report. Shows signature, file:line location, and assembly.",
        json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name or signature of the method to look up"
                }
            },
            "required": ["name"]
        }),
    )
}

fn dosai_endpoints_tool() -> serde_json::Value {
    make_tool(
        "dosai_endpoints",
        "List API endpoints from the dosai methods report with route, HTTP verb, handler method, and authentication requirement.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter endpoints by route or handler"
                }
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::LoadedReport;

    fn test_ctx() -> DosaiCtx {
        let dataflows = LoadedReport {
            report: serde_json::json!({
                "Metadata": { "SchemaVersion": "3.3.0", "AnalyzerVersion": "3.0.5.0" },
                "Statistics": { "SourceCount": 1, "SinkCount": 1, "SliceCount": 1, "NodeCount": 3, "EdgeCount": 2, "FilesAnalyzed": 4 },
                "Nodes": [],
                "Edges": [],
                "Slices": [],
                "WeaknessCandidates": [],
                "DangerousApiReachability": [],
                "PackageReachability": [
                    { "Purl": "pkg:nuget/Newtonsoft.Json@13.0.0", "Reachable": true, "Confidence": "High" }
                ],
                "EntryPoints": []
            }),
            report_path: "/tmp/dosai-dataflows.json".to_string(),
        };
        let methods = Some(LoadedReport {
            report: serde_json::json!({
                "Methods": [
                    { "Name": "Main", "ClassName": "Program", "Namespace": "MyApp", "SourceSignature": "void Main()", "FileName": "Program.cs", "LineNumber": 1, "Assembly": "app.dll" }
                ],
                "MethodCalls": [],
                "ApiEndpoints": [],
                "CallGraph": { "Edges": [], "Nodes": [] }
            }),
            report_path: "/tmp/dosai-methods.json".to_string(),
        });
        DosaiCtx { dataflows, methods, crypto: None, source_root: "/tmp/test".to_string() }
    }

    #[test]
    fn test_dosai_summary() {
        let ctx = test_ctx();
        let summary = ctx.summary();
        assert!(summary.contains("dosai"));
        assert!(summary.contains("3 nodes, 2 edges"));
    }

    #[test]
    fn test_dosai_query_methods() {
        let ctx = test_ctx();
        let result = ctx.query("methods", Some("Main"), 50);
        assert!(result.contains("Main"));
    }

    #[test]
    fn test_dosai_query_dependencies() {
        let ctx = test_ctx();
        let result = ctx.query("dependencies", None, 50);
        assert!(result.contains("Newtonsoft.Json"));
        assert!(result.contains("REACHABLE"));
    }

    #[test]
    fn test_dosai_tool_definitions() {
        let defs = dosai_tool_definitions();
        let names: Vec<&str> = defs.iter().filter_map(|d| d["name"].as_str()).collect();
        assert!(names.contains(&"dosai_summary"));
        assert!(names.contains(&"dosai_query"));
        assert!(names.contains(&"dosai_callgraph"));
        assert!(names.contains(&"dosai_flows"));
        assert!(names.contains(&"dosai_trace"));
        assert!(names.contains(&"dosai_detail"));
        assert!(names.contains(&"dosai_endpoints"));
        assert_eq!(defs.len(), 7);
    }

    #[test]
    fn test_dosai_system_prompt() {
        let prompt = build_dosai_system_prompt("Methods: 10", Some("components: 3"), Some("  - lib v1.0"), None);
        assert!(prompt.contains("dosai"));
        assert!(prompt.contains("dosai_summary"));
        assert!(prompt.contains("dosai_query"));
        assert!(prompt.contains("dosai_flows"));
        assert!(prompt.contains("Grounding rules"));
    }
}
