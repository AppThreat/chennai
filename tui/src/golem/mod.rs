//! Golem (Go) analysis backend — models the `golem` CLI output.
//!
//! Golem's JSON schema uses camelCase (e.g., `callGraph`, `dataFlow`, `securitySignals`)
//! and emits richly structured data-flow slices with `riskScore`, `flowKey`, `taintKinds`,
//! and `sanitizerNodeIds`. This module parallels the `rusi` backend with golem-specific
//! field mappings in `query.rs`.
//!
//! # Schema note
//! | rusi (snake_case) | golem (camelCase) |
//! |---|---|
//! | `call_graph` | `callGraph` |
//! | `data_flow` | `dataFlow` |
//! | `security_signals` | `securitySignals` |
//! | `qualified_name` | `qualifiedName` |
//! | `file_path` | `filePath` |

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
            "detail" => query::detail_declaration(&self.report.report, pattern.unwrap_or("")),
            _ => format!("Unknown query kind '{kind}'. Valid kinds: packages, files, imports, declarations, usages, security_signals, callgraph, dataflow, crypto, flows, sources, sinks, detail"),
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
- golem_summary — Re-fetch the summary of the golem analysis report.
- golem_query — Query indexed analysis data: packages, files, imports, declarations, usages, security_signals, callgraph, dataflow, crypto, flows, sources, sinks.
- golem_callgraph — Query the call graph (show nodes and edges matching a name pattern).
- golem_flows — Query data-flow slices (source→sink paths). Each slice has a source, a sink, categories, risk score, confidence, and taint kinds.
- golem_detail — Get detailed information about a specific declaration (function, method, struct) including its signature, location, callers, and callees.
- golem_crypto — Query cryptographic evidence (libraries, assets, operations, materials, findings).
- golem_sources — List distinct source categories with counts (e.g., env, file, http-request).
- golem_sinks — List distinct sink categories with counts (e.g., process-exec, sql-query, network-request).
- ripgrep / read_file — Search and read source code (confined to the project root).
- git_diff / git_log / git_show — Read-only git history.
- bom_query — Query the CycloneDX SBOM for dependency information.

## How to analyze
1. Call golem_summary once at the start to understand the codebase structure.
2. Use golem_query with kind="declarations" to find functions, methods, structs.
3. Use golem_query with kind="usages" to find API/library call sites.
4. Use golem_callgraph to trace call relationships between functions.
5. Use golem_flows to find security-relevant data-flow paths, ranked by risk score.
6. Use golem_sources and golem_sinks to orient yourself before tracing flows.
7. Use golem_detail to zoom into a specific declaration.
8. Use golem_crypto to review cryptographic usage.

## Data model reference
The golem report uses camelCase fields. Key entity types:

### packages
Fields: name, version, purl, files

### declarations
Fields: name, qualifiedName, kind (function, method, struct), filePath, signature, line

### usages
Fields: name (callee symbol), kind (call, method-call), enclosingDeclaration, position (filename, line)

### security_signals
Fields: category, severity, confidence, description, filePath

### callgraph
Nodes: name, qualifiedName, kind, filePath, local/external
Edges: sourceName → targetName, callType

### dataflow
Slices: sourceName, sinkName, sourceCategory, sinkCategory, ruleName, pathLength, flowKey, riskScore, severity, confidence, taintKinds, sanitizerNodeIds

### crypto
Libraries: path, family
Assets: kind, algorithm, provider, operation
Materials: kind, name
Findings: category, severity, summary

## Grounding rules
1. NEVER invent call graphs, data flows, taints, sinks, or security findings. Every claim must trace to a tool result.
2. Prefer structured evidence from golem tools over ripgrep.
3. If golem_flows returns NO results, the report lacks usable data-flow analysis. Do NOT dress up a grep+reasoning answer as reachability.
4. For each finding give: file:line, the concrete path, sanitizer check, and confidence grounded in tool evidence.
5. When available, use the CycloneDX SBOM to understand third-party dependencies.

You are an authorized security review of the user's OWN code — analyze it directly.
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
    ]
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
        "Query data-flow source-to-sink slices from the golem report. Each slice has a source, sink, risk score, severity, confidence, taint kinds, and path length. Results are ranked by risk score. Pass an optional pattern to filter.",
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
                    "packageCount": 1,
                    "fileCount": 2,
                    "importCount": 3,
                    "declarationCount": 4,
                    "usageCount": 5,
                    "securitySignalCount": 1,
                    "callGraphNodeCount": 3,
                    "callGraphEdgeCount": 2,
                    "dataFlowNodeCount": 4,
                    "dataFlowSliceCount": 1,
                    "cryptoLibraryCount": 1,
                    "cryptoComponentCount": 2
                },
                "packages": [
                    { "name": "myapp", "version": "0.1.0", "purl": "pkg:go/myapp@0.1.0", "files": ["main.go"] }
                ],
                "declarations": [
                    { "name": "main", "qualifiedName": "myapp.main", "kind": "function", "filePath": "main.go", "signature": "func main()", "line": 5 }
                ],
                "usages": [
                    { "kind": "call", "name": "os.Getenv", "enclosingDeclaration": "myapp.main", "position": { "filename": "main.go", "line": 6 } }
                ],
                "callGraph": {
                    "mode": "static",
                    "nodes": [
                        { "name": "main", "qualifiedName": "myapp.main", "kind": "function", "filePath": "main.go", "local": true, "external": false, "line": 5 }
                    ],
                    "edges": []
                },
                "dataFlow": {
                    "mode": "security",
                    "nodes": [
                        { "kind": "source", "name": "os.Getenv", "source": true, "sink": false, "category": "env" }
                    ],
                    "edges": [],
                    "slices": []
                },
                "crypto": {
                    "libraries": [],
                    "assets": [],
                    "materials": [],
                    "findings": []
                }
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
    }

    #[test]
    fn test_golem_query_declarations() {
        let ctx = test_ctx();
        let result = ctx.query("declarations", Some("main"), 50);
        assert!(result.contains("myapp.main"));
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
        assert_eq!(defs.len(), 8);
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
