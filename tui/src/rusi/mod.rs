pub mod loader;
pub mod query;
pub mod runner;

pub use loader::LoadedReport;
pub use runner::{run_rusi, rusi_report_path};

use crate::shared::backend::Backend;
use serde_json::{json, Value};

#[derive(Clone)]
pub struct RusiCtx {
    /// Loaded rusi JSON report.
    pub report: LoadedReport,
    /// Path to the source directory being analyzed.
    #[allow(dead_code)]
    pub source_root: String,
    /// Optional path to the call graph GraphML export.
    #[allow(dead_code)]
    pub callgraph_path: Option<String>,
    /// Optional path to the data flow GraphML export.
    #[allow(dead_code)]
    pub dataflow_path: Option<String>,
}

impl RusiCtx {
    pub fn summary(&self) -> String {
        query::extract_summary(&self.report.report)
    }

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
            "detail" => query::detail_declaration(&self.report.report, pattern.unwrap_or("")),
            "flows" => query::query_dataflow(&self.report.report, pattern, limit),
            "endpoints" | "api_endpoints" => query::query_endpoints(&self.report.report, pattern),
            _ => format!("Unknown query kind '{kind}'. Valid kinds: packages, files, imports, declarations, usages, security_signals, callgraph, dataflow, crypto, detail, flows, endpoints"),
        }
    }

    #[allow(dead_code)]
    pub fn detail(&self, name: &str) -> String {
        query::detail_declaration(&self.report.report, name)
    }

    #[allow(dead_code)]
    pub fn callgraph(&self, pattern: Option<&str>, limit: usize) -> String {
        query::query_callgraph(&self.report.report, pattern, limit)
    }

    #[allow(dead_code)]
    pub fn dataflow(&self, pattern: Option<&str>, limit: usize) -> String {
        query::query_dataflow(&self.report.report, pattern, limit)
    }

    #[allow(dead_code)]
    pub fn crypto(&self, pattern: Option<&str>) -> String {
        query::query_crypto(&self.report.report, pattern)
    }
}

impl Backend for RusiCtx {
    fn summary(&self) -> String { self.summary() }
    fn query(&self, kind: &str, pattern: Option<&str>, limit: usize) -> String { self.query(kind, pattern, limit) }
    fn backend_name(&self) -> &'static str { "rusi" }
    fn tool_definitions(&self) -> Vec<Value> { rusi_tool_definitions() }
    fn system_prompt(&self, summary_text: &str, bom_summary: Option<&str>, bom_components: Option<&str>, console_history: Option<&str>) -> String {
        build_rusi_system_prompt(summary_text, bom_summary, bom_components, console_history)
    }
    fn clone_box(&self) -> Box<dyn Backend> { Box::new(self.clone()) }
}

/// Build the rusi-specific system prompt for the LLM agent.
pub fn build_rusi_system_prompt(
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
        r#"You are chennai, an AI-powered code & security analysis agent. You are analyzing a Rust codebase using a structured analysis report produced by the Rust Source Inspector (rusi) tool — not over your training prior.

## Analysis report
{summary_text}{console_section}{bom_section}

## Available tools
- rusi_summary: Re-fetch the summary of the rusi analysis report.
- rusi_query: Query indexed analysis data: packages, files, imports, declarations, usages, security_signals, callgraph, dataflow, crypto. Use this to find symbols, functions, API calls, and structural information.
- rusi_callgraph: Query the call graph (show nodes and edges matching a name pattern).
- rusi_flows: Query data-flow slices (source to sink paths). Each slice has a source, a sink, categories, and a path.
- rusi_detail: Get detailed information about a specific declaration (function, method, struct) including its signature, location, callers, and callees.
- rusi_crypto: Query cryptographic evidence (libraries, components, materials, findings).
- rusi_endpoints: List HTTP API endpoints (axum, actix-web, rocket) with method, path, handler, and framework.
- bom_query: Query the CycloneDX SBOM for dependency information.
- git_diff / git_log / git_show: Read-only git history.
- ripgrep / read_file: Read source file content. Last resort; use rusi tools listed above first.

## How to analyze
1. Call rusi_summary once at the start to understand the codebase structure.
2. Use rusi_query with kind="declarations" to find functions, methods, structs. Use the pattern parameter to search by name.
3. Use rusi_query with kind="usages" to find API/library call sites.
4. Use rusi_callgraph to trace call relationships between functions. Pass a pattern to find specific call chains.
5. Use rusi_flows to find security-relevant data-flow paths (e.g., environment variable → command execution).
6. Use rusi_detail to zoom into a specific declaration (its source signature, callers, callees).
7. Use rusi_crypto to review cryptographic usage.
8. Use ripgrep and read_file to inspect actual source code around points of interest.

## Data model reference
The rusi report contains these entity types accessible via rusi_query:

### packages
Fields: name, version, manifest_path, purl, files

### files
Fields: path, package_name, purl

### imports
Fields: path (the imported symbol), alias, position (filename, line)

### declarations
Fields: name, qualified_name, canonical_name, kind (function, method, struct, trait, module), file_path, signature, position

### usages (API/library calls)
Fields: name (callee symbol), kind (call, method-call), enclosing_declaration, position (filename, line)

### security_signals
Fields: category (unsafe-code, async-model, native-interop, etc.), severity, confidence, description, file_path, position

### callgraph
Nodes: name, qualified_name, kind, file_path, local/external
Edges: source_name → target_name, call_type (static, external, trait-dispatch, etc.), position

### dataflow
Slices: source_name, sink_name, source_category, sink_category, rule_name, path_length, purls

### crypto
Libraries: path, family (hash, aead, kdf, protocol, etc.)
Components: kind, algorithm, provider, operation
Materials: kind (key, nonce, token, salt), name
Findings: category, severity, summary

{identity_rules}

## Grounding rules (this is the whole point of chennai)
1. NEVER invent call graphs, data flows, taints, sinks, or security findings. Every claim must trace to a tool result. If you cannot trace it, say so explicitly.
2. **Tool priority**: Use rusi tools FIRST for every query. Only use ripgrep or read_file when all rusi tools have been exhausted for the information you need or when you need a short snippet of surrounding source context. A ripgrep result is weaker evidence than a rusi tool result.
3. If rusi_flows/rusi_callgraph return NO results, the report lacks usable analysis data for that query. Do NOT dress up a grep+reasoning answer as a reachability finding. Present only what the source text supports and mark every finding LOW confidence.
4. For each security finding give: file:line, the concrete path (when available), sanitizer check, and a confidence grounded in the tool evidence.
5. When available, use the CycloneDX SBOM above to understand third-party dependencies. Cross-reference dependency data with analysis findings.

## Response style
Explain architectures and data flows with neat ASCII diagrams where they clarify the structure. Write in straightforward technical prose. Minimise bullet lists; favour short paragraphs or inline descriptions instead. Do not use em-dashes, emoji, or decorative formatting. Every finding must still carry file:line evidence. Keep responses short but substantive. Do not begin every message with "Let me" or similar filler openings.

You are an authorized security review of the user's own code. Analyze it directly.
When you have enough evidence, answer concisely with specific file:line references.
"#
    )
}

/// Tool definitions for rusi mode.
/// These are sent to the LLM as available tool definitions.
pub fn rusi_tool_definitions() -> Vec<serde_json::Value> {
    vec![
        rusi_summary_tool(),
        rusi_query_tool(),
        rusi_callgraph_tool(),
        rusi_flows_tool(),
        rusi_detail_tool(),
        rusi_crypto_tool(),
        rusi_endpoints_tool(),
    ]
}

fn rusi_endpoints_tool() -> serde_json::Value {
    json!({
        "name": "rusi_endpoints",
        "description": "List HTTP API endpoints discovered by rusi (axum, actix-web, rocket) with HTTP method, fully-qualified path, handler function, and framework. Empty for workspaces with no supported web framework.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter endpoints by path, handler, or framework"
                }
            }
        }
    })
}

fn rusi_summary_tool() -> serde_json::Value {
    json!({
        "name": "rusi_summary",
        "description": "Return the summary of the rusi (Rust) analysis report: packages, files, imports, declarations, usages, security signals, call graph, data flow, and crypto counts. Call this FIRST to orient — the counts tell you which categories of evidence exist so you know which tool to reach for next (e.g. whether there are any flows/endpoints worth investigating).",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    })
}

fn rusi_query_tool() -> serde_json::Value {
    json!({
        "name": "rusi_query",
        "description": "Primary structured entry point for the rusi (Rust) report — prefer it over ripgrep for finding any indexed entity, since results carry exact file:line, package, and PURL rather than raw text hits. Use it to find packages, files, imports, declarations, usages (calls), security signals, callgraph, dataflow, or crypto evidence. The pattern parameter does a case-insensitive substring match against names, paths, and relevant fields.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "description": "Entity type to query: packages, files, imports, declarations, usages, security_signals, callgraph, dataflow, crypto, endpoints",
                    "enum": ["packages", "files", "imports", "declarations", "usages", "security_signals", "callgraph", "dataflow", "crypto", "endpoints"]
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
        }
    })
}

fn rusi_callgraph_tool() -> serde_json::Value {
    json!({
        "name": "rusi_callgraph",
        "description": "Query the call graph from the rusi report. Shows call graph nodes (functions/methods) and edges (call relationships) matching an optional name pattern.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter nodes and edges by name, qualified name, or file path"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }
    })
}

fn rusi_flows_tool() -> serde_json::Value {
    json!({
        "name": "rusi_flows",
        "description": "THE authoritative tool for reachability/taint questions in the rusi (Rust) report — 'can untrusted input reach X', injection, or whether a sink is exploitable. Each slice is a proven taint path from a source (e.g., env, file, http-request, crypto-material) to a sink (e.g., process-exec, sql-query, network-request). ripgrep CANNOT prove a path reaches a sink; this can. Reach for it whenever the user asks about vulnerabilities or how data moves. Pass an optional pattern to filter by source name, sink name, or rule name.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter slices by source name, sink name, rule name, or description"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum slices to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }
    })
}

fn rusi_detail_tool() -> serde_json::Value {
    json!({
        "name": "rusi_detail",
        "description": "Get detailed information about a specific declaration (function, method, struct, trait, module) from the rusi report. Shows the signature, file:line location, package, PURL, and call-graph neighbors (who this calls and who calls it). The name parameter matches against both short name and fully qualified name.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name or qualified name of the declaration to look up"
                }
            },
            "required": ["name"]
        }
    })
}

fn rusi_crypto_tool() -> serde_json::Value {
    json!({
        "name": "rusi_crypto",
        "description": "Query cryptographic evidence from the rusi report. Shows crypto libraries (e.g., sha2, aes-gcm, rustls), components (algorithm + provider), materials (keys, nonces, tokens), and findings (weak crypto, etc.). Pass an optional pattern to filter by algorithm, provider, or name.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter crypto evidence by library name, algorithm, provider, or finding summary"
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rusi::loader::LoadedReport;

    fn load_test_report() -> RusiCtx {
        let report = LoadedReport {
            report: serde_json::json!({
                "tool": { "name": "rusi", "version": "2.5.2" },
                "options": { "directory": "/tmp/test" },
                "stats": {
                    "package_count": 1,
                    "file_count": 2,
                    "import_count": 5,
                    "declaration_count": 4,
                    "usage_count": 3,
                    "security_signal_count": 1,
                    "call_graph_node_count": 3,
                    "call_graph_edge_count": 2,
                    "data_flow_node_count": 4,
                    "data_flow_slice_count": 1,
                    "crypto_library_count": 1,
                    "crypto_component_count": 2,
                    "api_endpoint_count": 1
                },
                "api_endpoints": [
                    { "id": "ep-1", "method": "GET", "path": "/api/v1/users", "framework": "axum", "handler": "myapp::handlers::list_users", "package_path": "myapp", "purl": "pkg:cargo/myapp@0.1.0", "file_path": "src/handlers.rs", "position": { "filename": "src/handlers.rs", "line": 20, "column": 1 } }
                ],
                "packages": [
                    { "name": "myapp", "version": "0.1.0", "purl": "pkg:cargo/myapp@0.1.0", "files": ["src/main.rs", "src/lib.rs"] }
                ],
                "files": [
                    { "path": "src/main.rs", "package_name": "myapp", "purl": "pkg:cargo/myapp@0.1.0" },
                    { "path": "src/lib.rs", "package_name": "myapp", "purl": "pkg:cargo/myapp@0.1.0" }
                ],
                "imports": [
                    { "path": "std::env", "alias": null, "position": { "filename": "src/main.rs", "line": 1, "column": 1 } },
                    { "path": "std::process::Command", "alias": null, "position": { "filename": "src/main.rs", "line": 2, "column": 1 } }
                ],
                "declarations": [
                    { "id": "decl-1", "name": "main", "qualified_name": "myapp::main", "canonical_name": "myapp::main", "kind": "function", "package_path": "myapp", "purl": "pkg:cargo/myapp@0.1.0", "file_path": "src/main.rs", "signature": "fn main()", "receiver": null, "position": { "filename": "src/main.rs", "line": 5, "column": 4 } },
                    { "id": "decl-2", "name": "run_command", "qualified_name": "myapp::run_command", "canonical_name": "myapp::run_command", "kind": "function", "package_path": "myapp", "purl": "pkg:cargo/myapp@0.1.0", "file_path": "src/lib.rs", "signature": "fn run_command(cmd: &str)", "receiver": null, "position": { "filename": "src/lib.rs", "line": 10, "column": 4 } }
                ],
                "usages": [
                    { "id": "usage-1", "kind": "call", "name": "env::var", "package_path": "myapp", "enclosing_declaration": "myapp::main", "position": { "filename": "src/main.rs", "line": 6, "column": 10 } },
                    { "id": "usage-2", "kind": "call", "name": "Command::new", "package_path": "myapp", "enclosing_declaration": "myapp::main", "position": { "filename": "src/main.rs", "line": 7, "column": 10 } }
                ],
                "security_signals": [
                    { "id": "sig-1", "category": "unsafe-code", "severity": "medium", "confidence": "high", "description": "Unsafe function used", "package_path": "myapp", "file_path": "src/lib.rs", "position": { "filename": "src/lib.rs", "line": 15, "column": 5 } }
                ],
                "call_graph": {
                    "mode": "static",
                    "nodes": [
                        { "id": "node-1", "name": "main", "qualified_name": "myapp::main", "kind": "function", "file_path": "src/main.rs", "local": true, "external": false, "position": { "filename": "src/main.rs", "line": 5, "column": 4 } },
                        { "id": "node-2", "name": "run_command", "qualified_name": "myapp::run_command", "kind": "function", "file_path": "src/lib.rs", "local": true, "external": false, "position": { "filename": "src/lib.rs", "line": 10, "column": 4 } }
                    ],
                    "edges": [
                        { "id": "edge-1", "source_id": "node-1", "target_id": "node-2", "source_name": "main", "target_name": "run_command", "call_type": "static", "position": { "filename": "src/main.rs", "line": 8, "column": 5 } }
                    ],
                    "stats": { "node_count": 2, "edge_count": 1 }
                },
                "data_flow": {
                    "mode": "security",
                    "nodes": [
                        { "id": "df-node-1", "kind": "source", "name": "env::var", "source": true, "sink": false, "category": "env" },
                        { "id": "df-node-2", "kind": "sink", "name": "Command::new", "source": false, "sink": true, "category": "process-exec" }
                    ],
                    "edges": [],
                    "slices": [
                        { "id": "slice-1", "source_name": "env::var", "sink_name": "Command::new", "source_category": "env", "sink_category": "process-exec", "rule_name": "env-to-process-exec", "path_length": 2, "description": "Environment variable flows to command execution" }
                    ],
                    "stats": { "source_count": 1, "sink_count": 1, "slice_count": 1 }
                },
                "crypto": {
                    "libraries": [
                        { "id": "crypto-lib-1", "path": "sha2", "family": "hash", "file_path": "src/lib.rs", "position": { "filename": "src/lib.rs", "line": 3, "column": 1 } }
                    ],
                    "components": [
                        { "id": "crypto-comp-1", "kind": "hash", "algorithm": "SHA-256", "provider": "sha2", "operation": "digest", "file_path": "src/lib.rs", "position": { "filename": "src/lib.rs", "line": 20, "column": 5 } }
                    ],
                    "materials": [],
                    "findings": []
                }
            }),
            report_path: "/tmp/test.json".to_string(),
        };
        RusiCtx {
            report,
            source_root: "/tmp/test".to_string(),
            callgraph_path: None,
            dataflow_path: None,
        }
    }

    #[test]
    fn test_rusi_summary() {
        let ctx = load_test_report();
        let summary = ctx.summary();
        assert!(summary.contains("rusi"));
        assert!(summary.contains("Declarations: 4"));
        assert!(summary.contains("Usages"));
        assert!(summary.contains("Call graph"));
        assert!(summary.contains("Data flow"));
    }

    #[test]
    fn test_summary_contains_counts() {
        let ctx = load_test_report();
        let s = ctx.summary();
        assert!(s.contains("Packages: 1"));
        assert!(s.contains("Files: 2"));
        assert!(s.contains("Imports: 5"));
    }

    #[test]
    fn test_rusi_query_declarations() {
        let ctx = load_test_report();
        let result = ctx.query("declarations", Some("main"), 50);
        assert!(result.contains("myapp::main"));
        assert!(result.contains("fn main()"));
        assert!(result.contains("src/main.rs:5"));
    }

    #[test]
    fn test_rusi_query_usages() {
        let ctx = load_test_report();
        let result = ctx.query("usages", Some("env::var"), 50);
        assert!(result.contains("env::var"));
        assert!(result.contains("src/main.rs:6"));
    }

    #[test]
    fn test_rusi_query_callgraph() {
        let ctx = load_test_report();
        let result = ctx.query("callgraph", Some("main"), 50);
        assert!(result.contains("Call Graph"));
        assert!(result.contains("main"));
        assert!(result.contains("src/main.rs:5"));
    }

    #[test]
    fn test_rusi_query_dataflow() {
        let ctx = load_test_report();
        let result = ctx.query("dataflow", Some("env"), 50);
        assert!(result.contains("Data Flow"));
        assert!(result.contains("env::var"));
        assert!(result.contains("Command::new"));
    }

    #[test]
    fn test_rusi_query_crypto() {
        let ctx = load_test_report();
        let result = ctx.query("crypto", Some("sha2"), 50);
        assert!(result.contains("sha2"));
        assert!(result.contains("hash"));
        assert!(result.contains("SHA-256"));
    }

    #[test]
    fn test_rusi_query_endpoints() {
        let ctx = load_test_report();
        let result = ctx.query("endpoints", None, 50);
        assert!(result.contains("GET /api/v1/users"));
        assert!(result.contains("axum"));
        assert!(result.contains("src/handlers.rs:20"));
    }

    #[test]
    fn test_rusi_detail() {
        let ctx = load_test_report();
        let result = ctx.detail("run_command");
        assert!(result.contains("myapp::run_command"));
        assert!(result.contains("src/lib.rs:10"));
        assert!(result.contains("fn run_command"));
    }

    #[test]
    fn test_rusi_tool_definitions() {
        let defs = rusi_tool_definitions();
        let names: Vec<&str> = defs.iter().filter_map(|d| d["name"].as_str()).collect();
        assert!(names.contains(&"rusi_summary"));
        assert!(names.contains(&"rusi_query"));
        assert!(names.contains(&"rusi_callgraph"));
        assert!(names.contains(&"rusi_flows"));
        assert!(names.contains(&"rusi_detail"));
        assert!(names.contains(&"rusi_crypto"));
        assert!(names.contains(&"rusi_endpoints"));
        assert_eq!(defs.len(), 7);
    }

    #[test]
    fn test_rusi_system_prompt() {
        let prompt = crate::rusi::build_rusi_system_prompt(
            "Packages: 1 | Files: 2\nCall graph: 3 nodes",
            Some("components: 5"),
            Some("  - lib v1.0.0"),
            None,
        );
        assert!(prompt.contains("Rust Source Inspector"));
        assert!(prompt.contains("rusi_summary"));
        assert!(prompt.contains("rusi_query"));
        assert!(prompt.contains("rusi_callgraph"));
        assert!(prompt.contains("rusi_flows"));
        assert!(prompt.contains("rusi_detail"));
        assert!(prompt.contains("rusi_crypto"));
        assert!(prompt.contains("Grounding rules"));
        assert!(prompt.contains("Software Bill of Materials"));
        assert!(!prompt.contains("atom.")); // No atom DSL references
    }

    #[test]
    fn test_map_atom_to_rusi() {
        assert_eq!(crate::app::map_atom_to_rusi_tool("atom_summary"), "rusi_summary");
        assert_eq!(crate::app::map_atom_to_rusi_tool("atom_query"), "rusi_query");
        assert_eq!(crate::app::map_atom_to_rusi_tool("atom_dsl_eval"), "rusi_query");
        assert_eq!(crate::app::map_atom_to_rusi_tool("atom_flows"), "rusi_flows");
        assert_eq!(crate::app::map_atom_to_rusi_tool("atom_flows_through"), "rusi_flows");
        assert_eq!(crate::app::map_atom_to_rusi_tool("atom_detail"), "rusi_detail");
        assert_eq!(crate::app::map_atom_to_rusi_tool("atom_algorithms"), "rusi_callgraph");
        assert_eq!(crate::app::map_atom_to_rusi_tool("ripgrep"), "ripgrep");
    }

    #[test]
    fn integration_rusi_load_and_query_multi_file_app() {
        // This test loads a real rusi report generated from the multi-file-app fixture.
        let report_path = std::path::Path::new("/tmp/multi-file-rusi.json");
        if !report_path.exists() {
            eprintln!("Skipping integration test: /tmp/multi-file-rusi.json not found. Generate it with:");
            eprintln!("  rusi analyze --dir rusi/fixtures/multi-file-app --callgraph static --dataflow security --out /tmp/multi-file-rusi.json --pretty");
            return;
        }

        let report = match crate::rusi::loader::LoadedReport::from_file(report_path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Skipping integration test: could not load report: {e}");
                return;
            }
        };

        let ctx = RusiCtx {
            report,
            source_root: "/tmp".to_string(),
            callgraph_path: None,
            dataflow_path: None,
        };

        // Summary contains package info
        let summary = ctx.summary();
        assert!(summary.contains("Packages:"));
        assert!(summary.contains("Declarations:"));
        eprintln!("Summary:\n{summary}");

        // Query declarations
        let decls = ctx.query("declarations", Some("compute"), 50);
        assert!(!decls.is_empty());
        assert!(decls.contains("compute"));
        assert!(decls.contains("multi_file_app::util::compute"));
        eprintln!("Declarations matching 'compute':\n{decls}");

        // Query usages (function calls)
        let usages = ctx.query("usages", Some("to_string"), 50);
        assert!(!usages.is_empty());
        assert!(usages.contains("to_string"));
        eprintln!("Usages matching 'to_string':\n{usages}");

        // Query packages
        let packages = ctx.query("packages", None, 50);
        assert!(packages.contains("multi-file-app"));
        eprintln!("Packages:\n{packages}");

        // Query call graph
        let cg = ctx.query("callgraph", None, 50);
        assert!(cg.contains("Call Graph"));
        eprintln!("Call graph:\n{cg}");

        // Query data flow
        let df = ctx.query("dataflow", None, 50);
        eprintln!("Data flow:\n{df}");

        // Detail for a known function
        let detail = ctx.detail("read_secret");
        assert!(detail.contains("read_secret"));
        eprintln!("Detail for read_secret:\n{detail}");
    }
}
