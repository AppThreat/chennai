//! Golem (Go) analysis backend — models the `golem analyze` CLI output.
//!
//! Golem's JSON schema uses camelCase keys (e.g., `callGraph`, `dataFlow`,
//! `securitySignals`). Data flow is represented as per-function taint `summaries`
//! plus flagged source/sink `nodes` (not a flat slice list), and source positions
//! are nested under `range.start` or `position`. The schema-specific field mappings
//! live in [`query`]; this module wires up the [`crate::shared::backend::Backend`]
//! trait, tool definitions, and the system prompt.

pub mod loader;
pub mod query;
pub mod runner;

#[allow(unused_imports)]
pub use loader::LoadedReport;
pub use runner::{golem_report_path, run_golem};

use crate::shared::backend::Backend;
use crate::shared::make_tool;
use serde_json::{json, Value};

/// Context for golem analysis mode, holding the loaded report and analysis paths.
#[derive(Clone)]
#[allow(dead_code)]
pub struct GolemCtx {
    /// Loaded golem JSON report.
    pub report: loader::LoadedReport,
    /// Path to the source directory being analyzed.
    pub source_root: String,
    /// Optional path to the call graph GraphML export.
    pub callgraph_path: Option<String>,
    /// Optional path to the data flow GraphML export.
    pub dataflow_path: Option<String>,
}

impl GolemCtx {
    /// Render a summary of the golem analysis report.
    pub fn summary(&self) -> String {
        query::extract_summary(&self.report.report)
    }

    /// Query indexed entities by kind.
    pub fn query(&self, kind: &str, pattern: Option<&str>, limit: usize) -> String {
        match kind {
            "packages" => query::query_packages(&self.report.report, pattern),
            "files" => query::query_files(&self.report.report, pattern),
            "imports" => query::query_imports(&self.report.report, pattern, limit),
            "declarations" => query::query_declarations(&self.report.report, pattern, limit),
            "usages" => query::query_usages(&self.report.report, pattern, limit),
            "security_signals" => query::query_security_signals(&self.report.report, pattern, limit),
            "callgraph" => query::query_callgraph(&self.report.report, pattern, limit),
            "dataflow" => query::query_dataflow(&self.report.report, pattern, limit),
            "crypto" => query::query_crypto(&self.report.report, pattern),
            "flows" => query::query_slices_ranked(&self.report.report, limit),
            "sources" => query::query_source_sink_categories(&self.report.report, "sources"),
            "sinks" => query::query_source_sink_categories(&self.report.report, "sinks"),
            "endpoints" | "api_endpoints" => query::query_endpoints(&self.report.report, pattern),
            "detail" => query::detail_declaration(&self.report.report, pattern.unwrap_or("")),
            _ => format!("Unknown query kind '{kind}'. Valid kinds: packages, files, imports, declarations, usages, security_signals, callgraph, dataflow, crypto, flows, sources, sinks, endpoints, detail"),
        }
    }

    #[allow(dead_code)]
    /// Get detailed information about a specific declaration.
    pub fn detail(&self, name: &str) -> String {
        query::detail_declaration(&self.report.report, name)
    }

    #[allow(dead_code)]
    /// Query the call graph.
    pub fn callgraph(&self, pattern: Option<&str>, limit: usize) -> String {
        query::query_callgraph(&self.report.report, pattern, limit)
    }

    #[allow(dead_code)]
    /// Query data-flow slices.
    pub fn dataflow(&self, pattern: Option<&str>, limit: usize) -> String {
        query::query_dataflow(&self.report.report, pattern, limit)
    }

    #[allow(dead_code)]
    /// Query cryptographic evidence.
    pub fn crypto(&self, pattern: Option<&str>) -> String {
        query::query_crypto(&self.report.report, pattern)
    }
}

impl Backend for GolemCtx {
    fn summary(&self) -> String { self.summary() }
    fn query(&self, kind: &str, pattern: Option<&str>, limit: usize) -> String { self.query(kind, pattern, limit) }
    fn backend_name(&self) -> &'static str { "golem" }
    fn tool_definitions(&self) -> Vec<Value> { golem_tool_definitions() }
    fn system_prompt(&self, summary_text: &str, bom_summary: Option<&str>, bom_components: Option<&str>, console_history: Option<&str>) -> String {
        build_golem_system_prompt(summary_text, bom_summary, bom_components, console_history)
    }
    fn clone_box(&self) -> Box<dyn Backend> { Box::new(self.clone()) }
}

/// Build the golem-specific system prompt for the LLM agent.
pub fn build_golem_system_prompt(
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

    format!(
        r#"You are chennai, an AI-powered code & security analysis agent. You are analyzing a Go codebase using a structured analysis report produced by the golem tool — not over your training prior.

## Analysis report
{summary_text}{console_section}{bom_section}

## Available tools
- golem_summary: Re-fetch the summary of the golem analysis report.
- golem_query: Query indexed analysis data: packages, files, imports, declarations, usages, security_signals, callgraph, dataflow, crypto, flows, sources, sinks, endpoints.
- golem_callgraph: Query the call graph (show nodes and edges matching a name pattern).
- golem_flows: Query data-flow evidence: per-function taint summaries (which parameters reach which sink categories) plus flagged source/sink nodes.
- golem_detail: Get detailed information about a specific declaration (function, method, struct) including its signature, location, callers, and callees.
- golem_crypto: Query cryptographic evidence (libraries, materials, findings).
- golem_sources: List distinct source categories with counts (e.g., parameter, env, file, http-request).
- golem_sinks: List distinct sink categories with counts (e.g., process-exec, sql-query, network-request).
- golem_endpoints: List HTTP API endpoints with method, path, handler, and framework.
- bom_query: Query the CycloneDX SBOM for dependency information.
- git_diff / git_log / git_show: Read-only git history.
- ripgrep / read_file: Read source file content. Last resort; use golem tools listed above first.

## How to analyze
1. Call golem_summary once at the start to understand the codebase structure.
2. Use golem_query with kind="declarations" to find functions, methods, structs.
3. Use golem_query with kind="usages" to find API/library call sites.
4. Use golem_callgraph to trace call relationships between functions.
5. Use golem_flows to find security-relevant taint summaries, ranked by confidence.
6. Use golem_sources and golem_sinks to orient yourself before tracing flows.
7. Use golem_detail to zoom into a specific declaration.
8. Use golem_crypto to review cryptographic usage.

## Data model reference
The golem report uses camelCase fields. Source positions are nested: declarations,
usages, imports, security signals and crypto use `range.start.filename` / `range.start.line`;
call-graph nodes and edges use `position.filename` / `position.line`. Key entity types:

### packages
Fields: name, version, purl, files

### declarations
Fields: name, kind (function, method, struct, type), packagePath, receiver, signature, range

### usages
Fields: name (callee symbol), qualifiedName, kind (call, selector), enclosing.name, range

### security_signals
Fields: category, severity, confidence, symbol, description, recommendation, range

### callgraph
Nodes: name, kind, packagePath, local/external, position
Edges: sourceName → targetName, callType, position

### dataflow
summaries: function, packagePath, paramToSink (parameterIndex, categories), confidence
nodes: name, category, source/sink booleans, taintKinds, position

### crypto
Libraries: path, family
Materials: type, name, symbol
Findings: ruleId, severity, summary

## Grounding rules
1. NEVER invent call graphs, data flows, taints, sinks, or security findings. Every claim must trace to a tool result.
2. **Tool priority**: Use golem tools FIRST for every query. Only use ripgrep or read_file when all golem tools have been exhausted for the information you need or when you need a short snippet of surrounding source context. A ripgrep result is weaker evidence than a golem tool result.
3. If golem_flows returns NO results, the report lacks usable data-flow analysis. Do NOT dress up a grep+reasoning answer as reachability.
4. For each finding give: file:line, the concrete path, sanitizer check, and confidence grounded in tool evidence.
5. When available, use the CycloneDX SBOM to understand third-party dependencies.

## Response style
Explain architectures and data flows with neat ASCII diagrams where they clarify the structure. Write in straightforward technical prose. Minimise bullet lists; favour short paragraphs or inline descriptions instead. Do not use em-dashes, emoji, or decorative formatting. Every finding must still carry file:line evidence. Keep responses short but substantive. Do not begin every message with "Let me" or similar filler openings.

You are an authorized security review of the user's own code. Analyze it directly.
When you have enough evidence, answer concisely with specific file:line references.
"#
    )
}

/// Tool definitions for golem mode.
pub fn golem_tool_definitions() -> Vec<serde_json::Value> {
    vec![
        golem_summary_tool(),
        golem_query_tool(),
        golem_callgraph_tool(),
        golem_flows_tool(),
        golem_detail_tool(),
        golem_crypto_tool(),
        golem_sources_tool(),
        golem_sinks_tool(),
        golem_endpoints_tool(),
    ]
}

fn golem_endpoints_tool() -> serde_json::Value {
    make_tool(
        "golem_endpoints",
        "List HTTP API endpoints (routes) discovered by golem, with HTTP method, path, handler function, and web framework.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter endpoints by path, handler, or framework"
                }
            }
        }),
    )
}

fn golem_summary_tool() -> serde_json::Value {
    make_tool(
        "golem_summary",
        "Return the summary of the golem analysis report: packages, files, imports, declarations, usages, security signals, call graph, data flow, and crypto counts.",
        json!({ "type": "object", "properties": {}, "required": [] }),
    )
}

fn golem_query_tool() -> serde_json::Value {
    make_tool(
        "golem_query",
        "Query the golem analysis report for indexed entities. Use this to find packages, files, imports, declarations, usages (calls), security signals, callgraph, dataflow, crypto, flows (ranked slices), sources, or sinks.",
        json!({
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "description": "Entity type to query: packages, files, imports, declarations, usages, security_signals, callgraph, dataflow, crypto, flows, sources, sinks",
                    "enum": ["packages", "files", "imports", "declarations", "usages", "security_signals", "callgraph", "dataflow", "crypto", "flows", "sources", "sinks"]
                },
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive search pattern to filter results by name, path, or content"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            },
            "required": ["kind"]
        }),
    )
}

fn golem_callgraph_tool() -> serde_json::Value {
    make_tool(
        "golem_callgraph",
        "Query the call graph from the golem report. Shows call graph nodes and edges matching an optional name pattern.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter nodes and edges by name"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }),
    )
}

fn golem_flows_tool() -> serde_json::Value {
    make_tool(
        "golem_flows",
        "Query data-flow evidence from the golem report: per-function taint summaries (which parameters reach which sink categories, with confidence) plus flagged source/sink nodes. Results are ranked by confidence. Pass an optional pattern to filter.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter slices by source name, sink name, or rule name"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum slices to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }),
    )
}

fn golem_detail_tool() -> serde_json::Value {
    make_tool(
        "golem_detail",
        "Get detailed information about a specific declaration (function, method, struct) from the golem report. Shows signature, file:line location, package, PURL, and call-graph neighbors.",
        json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name or qualified name of the declaration to look up"
                }
            },
            "required": ["name"]
        }),
    )
}

fn golem_crypto_tool() -> serde_json::Value {
    make_tool(
        "golem_crypto",
        "Query cryptographic evidence from the golem report. Shows crypto libraries, assets (algorithms + providers), materials, and findings.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter crypto evidence by library name, algorithm, provider, or finding summary"
                }
            }
        }),
    )
}

fn golem_sources_tool() -> serde_json::Value {
    make_tool(
        "golem_sources",
        "List distinct data-flow source categories (e.g., env, file, http-request, crypto-material) with their counts. Use this to understand what untrusted inputs the codebase processes.",
        json!({ "type": "object", "properties": {}, "required": [] }),
    )
}

fn golem_sinks_tool() -> serde_json::Value {
    make_tool(
        "golem_sinks",
        "List distinct data-flow sink categories (e.g., process-exec, sql-query, network-request, file-write) with their counts. Use this to understand what dangerous operations exist in the codebase.",
        json!({ "type": "object", "properties": {}, "required": [] }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::LoadedReport;

    fn test_ctx() -> GolemCtx {
        let report = LoadedReport {
            report: serde_json::json!({
                "tool": { "name": "golem", "version": "2.5.1" },
                "stats": {
                    "packageCount": 1, "fileCount": 2, "importCount": 3, "declarationCount": 4,
                    "usageCount": 5, "securitySignalCount": 1, "apiEndpointCount": 0,
                    "cryptoLibraryCount": 1, "cryptoMaterialCount": 0, "cryptoFindingCount": 0
                },
                "packages": [
                    { "name": "myapp", "version": "0.1.0", "purl": "pkg:golang/myapp@0.1.0", "files": ["main.go"] }
                ],
                "declarations": [
                    { "name": "main", "kind": "function", "packagePath": "myapp", "signature": "func main()", "range": { "start": { "filename": "main.go", "line": 5 } } }
                ],
                "usages": [
                    { "kind": "call", "name": "Getenv", "qualifiedName": "os.Getenv", "enclosing": { "name": "main" }, "range": { "start": { "filename": "main.go", "line": 6 } } }
                ],
                "callGraph": {
                    "mode": "static",
                    "stats": { "nodeCount": 1, "edgeCount": 0 },
                    "nodes": [
                        { "name": "main", "kind": "function", "packagePath": "myapp", "local": true, "external": false, "position": { "filename": "main.go", "line": 5 } }
                    ],
                    "edges": []
                },
                "dataFlow": {
                    "mode": "security",
                    "stats": { "sourceCount": 1, "sinkCount": 0, "sliceCount": 0, "summaryCount": 0 },
                    "nodes": [
                        { "kind": "source", "name": "input", "source": true, "sink": false, "category": "env" }
                    ],
                    "summaries": []
                },
                "crypto": { "libraries": [], "materials": [], "findings": [] }
            }),
            report_path: "/tmp/golem.json".to_string(),
        };
        GolemCtx {
            report,
            source_root: "/tmp/test".to_string(),
            callgraph_path: None,
            dataflow_path: None,
        }
    }

    #[test]
    fn test_golem_summary() {
        let ctx = test_ctx();
        let summary = ctx.summary();
        assert!(summary.contains("golem"));
        assert!(summary.contains("Declarations: 4"));
        assert!(summary.contains("Call graph: 1 nodes, 0 edges"));
    }

    #[test]
    fn test_golem_query_declarations() {
        let ctx = test_ctx();
        let result = ctx.query("declarations", Some("main"), 50);
        assert!(result.contains("main"));
        assert!(result.contains("main.go:5"));
    }

    #[test]
    fn test_golem_query_endpoints_kind() {
        let ctx = test_ctx();
        let result = ctx.query("endpoints", None, 50);
        assert!(result.contains("No API endpoint data"));
    }

    #[test]
    fn test_golem_query_unknown_kind() {
        let ctx = test_ctx();
        let result = ctx.query("nonexistent", None, 50);
        assert!(result.contains("Unknown query kind"));
    }

    #[test]
    fn test_golem_tool_definitions() {
        let defs = golem_tool_definitions();
        let names: Vec<&str> = defs.iter().filter_map(|d| d["name"].as_str()).collect();
        assert!(names.contains(&"golem_summary"));
        assert!(names.contains(&"golem_query"));
        assert!(names.contains(&"golem_callgraph"));
        assert!(names.contains(&"golem_flows"));
        assert!(names.contains(&"golem_detail"));
        assert!(names.contains(&"golem_crypto"));
        assert!(names.contains(&"golem_sources"));
        assert!(names.contains(&"golem_sinks"));
        assert!(names.contains(&"golem_endpoints"));
        assert_eq!(defs.len(), 9);
    }

    #[test]
    fn test_golem_system_prompt() {
        let prompt = build_golem_system_prompt(
            "Packages: 1 | Files: 2",
            Some("components: 5"),
            Some("  - lib v1.0.0"),
            None,
        );
        assert!(prompt.contains("golem"));
        assert!(prompt.contains("golem_summary"));
        assert!(prompt.contains("golem_query"));
        assert!(prompt.contains("golem_flows"));
        assert!(prompt.contains("golem_sources"));
        assert!(prompt.contains("Grounding rules"));
        assert!(prompt.contains("Software Bill of Materials"));
    }
}
