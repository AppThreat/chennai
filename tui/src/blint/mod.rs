//! Blint (binary / APK / IPA) analysis backend.
//!
//! Blint analyses compiled binaries rather than source code. It reports:
//! - **Metadata**: architecture, platform, file type, functions, symbols, imports/exports,
//!   build info, dependencies, strings, security properties, sections, call graph
//! - **Findings**: binary hardening issues (PIE, NX, RELRO, canary, CFG)
//! - **Reviews**: capability evidence (network, crypto, exec, reflection, etc.)
//! - **SBOM**: CycloneDX components and `internal:behaviours` for Android/iOS
//!
//! # Important
//! Every result from blint is *static evidence* — symbol presence or capability surface.
//! **It does not prove runtime execution.** The LLM prompt includes grounding rules to
//! make this distinction clear to the model.

pub mod loader;
pub mod query;
pub mod runner;

pub use loader::BlintReports;
#[allow(unused_imports)]
pub use runner::find_blint;

use crate::shared::backend::Backend;
use crate::shared::make_tool;
use serde_json::{json, Value};

/// Context for blint analysis mode, holding all loaded reports for a binary artifact.
#[derive(Clone)]
pub struct BlintCtx {
    /// The primary metadata report.
    pub reports: BlintReports,
    /// Path to the source/binary artifact being analyzed.
    #[allow(dead_code)]
    pub artifact_path: String,
}

#[allow(dead_code)]
impl BlintCtx {
    /// Render a summary of the binary analysis.
    pub fn summary(&self) -> String {
        let sbom_val = self.reports.sbom.as_ref().map(|r| &r.report);
        query::extract_summary(
            &self.reports.metadata.report,
            &self.reports.findings.as_ref().map(|r| &r.report).cloned(),
            &self.reports.reviews.as_ref().map(|r| &r.report).cloned(),
            sbom_val,
        )
    }

    /// Query blint analysis data by kind.
    pub fn query(&self, kind: &str, pattern: Option<&str>, limit: usize) -> String {
        match kind {
            "capabilities" => query::query_capabilities(
                &self.reports.reviews.as_ref().map(|r| r.report.clone()),
                pattern,
                limit,
            ),
            "findings" => query::query_findings(
                &self.reports.findings.as_ref().map(|r| r.report.clone()),
                pattern,
                limit,
            ),
            "symbols" => query::query_symbols(&self.reports.metadata.report, pattern, limit),
            "strings" => query::query_strings(&self.reports.metadata.report, pattern, limit),
            "components" => query::query_components(
                &self.reports.sbom.as_ref().map(|r| r.report.clone()),
                pattern,
                limit,
            ),
            "behaviours" => query::query_behaviours(
                &self.reports.sbom.as_ref().map(|r| r.report.clone()),
                pattern,
                limit,
            ),
            "security_properties" => query::query_security_properties(&self.reports.metadata.report),
            "callgraph" => query::query_callgraph(&self.reports.metadata.report),
            _ => format!(
                "Unknown query kind '{kind}'. Valid kinds: capabilities, findings, symbols, strings, components, behaviours, security_properties, callgraph"
            ),
        }
    }

    /// Query binary capabilities.
    pub fn capabilities(&self, pattern: Option<&str>, limit: usize) -> String {
        query::query_capabilities(
            &self.reports.reviews.as_ref().map(|r| &r.report).cloned(),
            pattern,
            limit,
        )
    }

    /// Query security findings.
    pub fn findings(&self, pattern: Option<&str>, limit: usize) -> String {
        query::query_findings(
            &self.reports.findings.as_ref().map(|r| &r.report).cloned(),
            pattern,
            limit,
        )
    }

    /// Query symbols.
    pub fn symbols(&self, pattern: Option<&str>, limit: usize) -> String {
        query::query_symbols(&self.reports.metadata.report, pattern, limit)
    }

    /// Query SBOM components.
    pub fn components(&self, pattern: Option<&str>, limit: usize) -> String {
        query::query_components(
            &self.reports.sbom.as_ref().map(|r| r.report.clone()),
            pattern,
            limit,
        )
    }

    /// Query binary behaviours (Dalvik, iOS privacy).
    pub fn behaviours(&self, pattern: Option<&str>, limit: usize) -> String {
        query::query_behaviours(
            &self.reports.sbom.as_ref().map(|r| r.report.clone()),
            pattern,
            limit,
        )
    }
}

impl Backend for BlintCtx {
    fn summary(&self) -> String { self.summary() }
    fn query(&self, kind: &str, pattern: Option<&str>, limit: usize) -> String { self.query(kind, pattern, limit) }
    fn backend_name(&self) -> &'static str { "blint" }
    fn tool_definitions(&self) -> Vec<Value> { blint_tool_definitions() }
    fn system_prompt(&self, summary_text: &str, bom_summary: Option<&str>, bom_components: Option<&str>, console_history: Option<&str>) -> String {
        build_blint_system_prompt(summary_text, bom_summary, bom_components, console_history)
    }
    fn clone_box(&self) -> Box<dyn Backend> { Box::new(self.clone()) }
}

/// Build the blint-specific system prompt for the LLM agent.
pub fn build_blint_system_prompt(
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
        r#"You are chennai, an AI-powered code & security analysis agent. You are analyzing a binary / APK / IPA artifact using the blint tool — not over your training prior.

## Analysis report
{summary_text}{console_section}{bom_section}

## IMPORTANT: Binary analysis limitations
Blint performs **static analysis** of compiled binaries. Its outputs show:
- What **symbols** are present in the binary (imported and exported functions)
- What **capabilities** can be inferred from symbol presence (network, crypto, exec, reflection, etc.)
- Binary **hardening properties** (PIE, NX, RELRO, stack canary, CFG)
- Recovered **strings** (URLs, secrets, paths)
- For Android APKs: **Dalvik behaviours** (weak crypto, native exec, cleartext, webview, root detection, trackers, AI calls)
- For iOS IPAs: **privacy surface** (ios_bundle, objc_metadata, privacy manifest)
- SBOM **components** (Go modules, Rust crates, .NET packages, native libraries, trackers)

**What blint CANNOT do:**
- Prove that a capability symbol is actually *called* at runtime
- Prove that a detected string is actually *used* in a security-relevant context
- Perform taint or data-flow analysis on source code
- Confirm exploitability

## Available tools
- blint_summary: Re-fetch the summary of the blint analysis report.
- blint_capabilities: Query capability evidence (symbol-based: network, crypto, exec, reflection, etc.).
- blint_findings: Query binary hardening findings (PIE, NX, RELRO, canary, CFG) with severity.
- blint_symbols: Query imports, exports, and dynamic symbols by pattern.
- blint_components: Query SBOM components and dependencies by name or PURL.
- blint_behaviours: Query detected behaviours (Android Dalvik, iOS privacy surface).
- blint_strings: Query informative/high-entropy strings (URLs, secrets, paths).
- blint_callgraph: Query the disassembly-based call graph (when available).
- bom_query: Query the CycloneDX SBOM for dependency information.
- ripgrep / read_file: Read source file content. Last resort; use blint tools listed above first.

## How to analyze
1. Call blint_summary once to understand the binary structure.
2. Use blint_capabilities to understand what the binary can do (network, execute, crypto…).
3. Use blint_findings to check for missing hardening (PIE, NX, RELRO, canary).
4. Use blint_symbols to find specific imported or exported functions.
5. Use blint_components to review third-party dependencies and their versions.
6. For Android APKs, use blint_behaviours to find Dalvik-level behavioural issues.
7. Use blint_strings to discover URLs, hardcoded secrets, and paths.

## Grounding rules
1. **Tool priority**: Use blint tools FIRST for every query (blint_capabilities, blint_findings, blint_symbols, blint_components, blint_behaviours, blint_strings, blint_callgraph). Only use ripgrep or read_file when no blint tool answers the question. A ripgrep result is weaker evidence than a blint tool result.
2. **Capabilities/symbols are static evidence of presence, NOT proof of execution.** Do not assert that a capability is reachable without a call-graph path or source evidence.
3. If a binary is **stripped**, note that symbol confidence is lower and many function names may be unavailable.
4. For binary hardening findings, report the property status (yes/no/partial) and explain the concrete risk.
5. For Android APKs, cross-reference AndroidManifest permissions with detected behaviours.
6. For iOS IPAs, check the privacy manifest against collected data types.
7. For each finding give: the specific symbol, file/offset, the evidence, and a confidence grounded in the tool.

## Response style
Explain architectures and data flows with neat ASCII diagrams where they clarify the structure. Write in straightforward technical prose. Minimise bullet lists; favour short paragraphs or inline descriptions instead. Do not use em-dashes, emoji, or decorative formatting. Every finding must still carry file:line evidence. Keep responses short but substantive. Do not begin every message with "Let me" or similar filler openings.

You are an authorized security review of the user's own code. Analyze it directly.
"#
    )
}

/// Tool definitions for blint mode.
pub fn blint_tool_definitions() -> Vec<serde_json::Value> {
    vec![
        blint_summary_tool(),
        blint_capabilities_tool(),
        blint_findings_tool(),
        blint_symbols_tool(),
        blint_components_tool(),
        blint_behaviours_tool(),
        blint_strings_tool(),
        blint_callgraph_tool(),
    ]
}

fn blint_summary_tool() -> serde_json::Value {
    make_tool(
        "blint_summary",
        "Return the summary of the blint binary analysis: architecture, platform, file type, functions, symbols, imports/exports, security findings, capabilities, and SBOM component counts.",
        json!({ "type": "object", "properties": {}, "required": [] }),
    )
}

fn blint_capabilities_tool() -> serde_json::Value {
    make_tool(
        "blint_capabilities",
        "Query capability evidence from the blint binary review. Each capability (e.g., Command Execution, Network Access, Crypto) lists the evidence symbols that triggered it. Use this to understand what the binary CAN do at the API/symbol level.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter capabilities by name or description"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum capabilities to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }),
    )
}

fn blint_findings_tool() -> serde_json::Value {
    make_tool(
        "blint_findings",
        "Query binary hardening findings from blint. Reports issues like missing PIE, NX, RELRO, stack canary, or CFG with severity ratings.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter findings by name, severity, or category"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum findings to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }),
    )
}

fn blint_symbols_tool() -> serde_json::Value {
    make_tool(
        "blint_symbols",
        "Query imported, exported, and dynamic symbols from the blint metadata. Use this to find specific API calls or functions the binary uses.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Case-insensitive pattern to filter symbols by name or type"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum symbols to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            },
            "required": ["pattern"]
        }),
    )
}

fn blint_components_tool() -> serde_json::Value {
    make_tool(
        "blint_components",
        "Query SBOM components and dependencies from the blint CycloneDX output. Includes Go modules, Rust crates, .NET packages, native libraries, and detected services/trackers.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter components by name, type, or PURL"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum components to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }),
    )
}

fn blint_behaviours_tool() -> serde_json::Value {
    make_tool(
        "blint_behaviours",
        "Query detected behaviours from the SBOM's internal:behaviours properties. For Android APKs this shows Dalvik-level behavioural analysis (weak crypto, native exec, cleartext, webview, root detection, trackers, AI calls). For iOS IPAs it shows privacy surface indicators.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional case-insensitive pattern to filter behaviours by name or description"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum behaviours to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            }
        }),
    )
}

fn blint_strings_tool() -> serde_json::Value {
    make_tool(
        "blint_strings",
        "Query informative strings recovered from the binary by blint. Includes URLs, file paths, hardcoded secrets, and other high-entropy strings.",
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Case-insensitive pattern to filter strings by value or category"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum strings to return (default: 50, max: 500)",
                    "default": 50,
                    "maximum": 500
                }
            },
            "required": ["pattern"]
        }),
    )
}

fn blint_callgraph_tool() -> serde_json::Value {
    make_tool(
        "blint_callgraph",
        "Query the call graph generated from disassembly (when --disassemble was enabled). Shows function call relationships within the binary.",
        json!({ "type": "object", "properties": {}, "required": [] }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::LoadedReport;

    fn test_ctx() -> BlintCtx {
        let reports = BlintReports {
            metadata: LoadedReport {
                report: serde_json::json!({
                    "binary_type": "ELF",
                    "machine_type": "x86_64",
                    "file_type": "DYN",
                    "exe_type": "genericbinary",
                    "dynamic_symbols": [{ "name": "system", "type": "FUNC", "binding": "GLOBAL", "is_imported": true, "is_exported": false, "address": "0x401000" }],
                    "dynamic_entries": [{ "name": "libc.so", "tag": "NEEDED" }],
                    "functions": [{"index": 0, "name": "main", "address": "0x1000"}],
                    "strings": [{ "value": "https://example.com", "category": "url" }],
                    "security_properties": { "nx": true, "pie": true, "relro": "full" }
                }),
                report_path: "/tmp/blint-metadata.json".to_string(),
            },
            findings: Some(LoadedReport {
                report: serde_json::json!({ "findings": [{ "id": "CHECK_PIE", "title": "No PIE", "severity": "medium" }] }),
                report_path: "/tmp/blint-findings.json".to_string(),
            }),
            reviews: Some(LoadedReport {
                report: serde_json::json!({ "reviews": [{ "id": "CMD_EXEC", "title": "Command Execution", "severity": "high", "summary": "Can exec commands", "evidence": [{"pattern": "system", "function": "exec"}] }] }),
                report_path: "/tmp/blint-reviews.json".to_string(),
            }),
            fuzzables: None,
            sbom: None,
            callgraph_path: None,
            artifact_type: "ELF".to_string(),
        };
        BlintCtx { reports, artifact_path: "/tmp/test.elf".to_string() }
    }

    #[test]
    fn test_blint_summary() {
        let ctx = test_ctx();
        let summary = ctx.summary();
        assert!(summary.contains("ELF"), "summary={summary}");
        assert!(summary.contains("x86_64"), "summary={summary}");
    }

    #[test]
    fn test_blint_query_capabilities() {
        let ctx = test_ctx();
        let result = ctx.query("capabilities", Some("exec"), 50);
        assert!(result.contains("Command Execution"));
    }

    #[test]
    fn test_blint_query_findings() {
        let ctx = test_ctx();
        let result = ctx.query("findings", Some("PIE"), 50);
        assert!(result.contains("No PIE"));
    }

    #[test]
    fn test_blint_query_symbols() {
        let ctx = test_ctx();
        let result = ctx.query("symbols", Some("system"), 50);
        assert!(result.contains("system"));
    }

    #[test]
    fn test_blint_query_unknown_kind() {
        let ctx = test_ctx();
        let result = ctx.query("nonexistent", None, 50);
        assert!(result.contains("Unknown query kind"));
    }

    #[test]
    fn test_blint_tool_definitions() {
        let defs = blint_tool_definitions();
        let names: Vec<&str> = defs.iter().filter_map(|d| d["name"].as_str()).collect();
        assert!(names.contains(&"blint_summary"));
        assert!(names.contains(&"blint_capabilities"));
        assert!(names.contains(&"blint_findings"));
        assert!(names.contains(&"blint_symbols"));
        assert!(names.contains(&"blint_components"));
        assert!(names.contains(&"blint_behaviours"));
        assert!(names.contains(&"blint_strings"));
        assert!(names.contains(&"blint_callgraph"));
        assert_eq!(defs.len(), 8);
    }

    #[test]
    fn test_blint_system_prompt() {
        let prompt = build_blint_system_prompt("ELF | x86_64", None, None, None);
        assert!(prompt.contains("blint"));
        assert!(prompt.contains("blint_summary"));
        assert!(prompt.contains("blint_capabilities"));
        assert!(prompt.contains("static analysis"));
        assert!(prompt.contains("Grounding rules"));
    }
}
