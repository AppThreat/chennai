//! Field mappings for the golem (Go) JSON schema.
//!
//! Golem uses camelCase keys (e.g., `securitySignals`, `callGraph`, `dataFlow`,
//! `crypto`, `flowKey`, `riskScore`) whereas rusi uses snake_case. Each query
//! function reads the camelCase variant of the relevant fields.

use crate::shared::{field_i64, field_str, pattern_match, ListHeader};
use serde_json::Value;

/// Render the golem report summary from the `stats` object.
pub fn extract_summary(report: &Value) -> String {
    let tool_name = report["tool"]["name"].as_str().unwrap_or("golem");
    let tool_ver = report["tool"]["version"].as_str().unwrap_or("?");
    let stats = &report["stats"];

    let packages = field_i64(stats, "packageCount");
    let files = field_i64(stats, "fileCount");
    let imports = field_i64(stats, "importCount");
    let declarations = field_i64(stats, "declarationCount");
    let usages = field_i64(stats, "usageCount");
    let security = field_i64(stats, "securitySignalCount");
    let cg_nodes = field_i64(stats, "callGraphNodeCount");
    let cg_edges = field_i64(stats, "callGraphEdgeCount");
    let df_nodes = field_i64(stats, "dataFlowNodeCount");
    let df_slices = field_i64(stats, "dataFlowSliceCount");
    let crypto_libs = field_i64(stats, "cryptoLibraryCount");
    let crypto_comps = field_i64(stats, "cryptoComponentCount");

    format!(
        "Analysis tool: {tool_name} v{tool_ver}\n\
         Packages: {packages} | Files: {files} | Imports: {imports}\n\
         Declarations: {declarations} | Usages (calls): {usages} | Security signals: {security}\n\
         Call graph: {cg_nodes} nodes, {cg_edges} edges\n\
         Data flow: {df_nodes} nodes, {df_slices} slices\n\
         Crypto libraries: {crypto_libs} | Crypto components: {crypto_comps}"
    )
}

pub fn query_packages(report: &Value, pattern: Option<&str>) -> String {
    let packages = match report["packages"].as_array() {
        Some(arr) => arr,
        None => return "No package data available.".to_string(),
    };

    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Packages", total: packages.len(), matched: packages.len(), shown: packages.len() }.to_string());

    for pkg in packages {
        let name = field_str(pkg, "name");
        let version = field_str(pkg, "version");
        let purl = field_str(pkg, "purl");
        if !pattern_match(name, pattern) && !pattern_match(purl, pattern) {
            continue;
        }
        let files_count = pkg["files"].as_array().map(|f| f.len()).unwrap_or(0);
        lines.push(format!("  {name} ({version}) — {files_count} files — {purl}"));
    }

    lines.join("\n")
}

pub fn query_files(report: &Value, pattern: Option<&str>) -> String {
    let files = match report["files"].as_array() {
        Some(arr) => arr,
        None => return "No file data available.".to_string(),
    };

    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Files", total: files.len(), matched: files.len(), shown: files.len() }.to_string());

    for file in files {
        let path = field_str(file, "path");
        let package = field_str(file, "packageName");
        if !pattern_match(path, pattern) && !pattern_match(package, pattern) {
            continue;
        }
        lines.push(format!("  {path} ({package})"));
    }

    lines.join("\n")
}

pub fn query_declarations(report: &Value, pattern: Option<&str>, limit: usize) -> String {
    let decls = match report["declarations"].as_array() {
        Some(arr) => arr,
        None => return "No declaration data available.".to_string(),
    };

    let mut matched: Vec<&Value> = decls.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|d| {
            d["name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || d["qualifiedName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || d["filePath"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Declarations", total: decls.len(), matched: matched.len(), shown: show.len() }.to_string());

    for d in show {
        let name = field_str(d, "name");
        let kind = field_str(d, "kind");
        let qname = field_str(d, "qualifiedName");
        let file = field_str(d, "filePath");
        let line = field_i64(d, "line");
        let sig = d["signature"].as_str().unwrap_or("");

        lines.push(format!("  [{kind}] {name}"));
        lines.push(format!("         {qname}"));
        lines.push(format!("         {file}:{line}"));
        if !sig.is_empty() {
            let preview: String = sig.chars().take(120).collect();
            lines.push(format!("         {preview}"));
        }
    }

    lines.join("\n")
}

pub fn query_usages(report: &Value, pattern: Option<&str>, limit: usize) -> String {
    let usages = match report["usages"].as_array() {
        Some(arr) => arr,
        None => return "No usage/call data available.".to_string(),
    };

    let mut matched: Vec<&Value> = usages.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|u| {
            u["name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || u["kind"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || u["position"]["filename"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Usages/Calls", total: usages.len(), matched: matched.len(), shown: show.len() }.to_string());

    for u in show {
        let name = field_str(u, "name");
        let kind = field_str(u, "kind");
        let file = u["position"]["filename"].as_str().unwrap_or("?");
        let line = field_i64(u, "line");
        let enclosing = field_str(u, "enclosingDeclaration");

        lines.push(format!("  [{kind}] {name} at {file}:{line}"));
        if !enclosing.is_empty() && enclosing != "?" {
            lines.push(format!("         in: {enclosing}"));
        }
    }

    lines.join("\n")
}

pub fn query_security_signals(report: &Value, category_filter: Option<&str>, limit: usize) -> String {
    let signals = match report["securitySignals"].as_array() {
        Some(arr) => arr,
        None => return "No security signal data available.".to_string(),
    };

    let mut matched: Vec<&Value> = signals.iter().collect();
    if let Some(cat) = category_filter {
        let cat_lower = cat.to_lowercase();
        matched.retain(|s| {
            s["category"].as_str().unwrap_or("").to_lowercase().contains(&cat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Security Signals", total: signals.len(), matched: matched.len(), shown: show.len() }.to_string());

    for s in show {
        let category = field_str(s, "category");
        let severity = field_str(s, "severity");
        let confidence = field_str(s, "confidence");
        let desc = field_str(s, "description");
        let file = field_str(s, "filePath");
        let line = field_i64(s, "line");

        lines.push(format!("  [{severity}][{confidence}] {category} — {desc}"));
        lines.push(format!("         {file}:{line}"));
    }

    lines.join("\n")
}

pub fn query_callgraph(report: &Value, pattern: Option<&str>, limit: usize) -> String {
    let cg = match report["callGraph"].as_object() {
        Some(cg) => cg,
        None => return "No call graph data available (not enabled in analysis).".to_string(),
    };

    let mode = cg.get("mode").and_then(Value::as_str).unwrap_or("?");
    let nodes = cg["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
    let edges = cg["edges"].as_array().map(|a| a.len()).unwrap_or(0);

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# Call Graph (mode: {mode}, {nodes} nodes, {edges} edges)"));

    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        if let Some(node_list) = cg["nodes"].as_array() {
            let matched: Vec<&Value> = node_list
                .iter()
                .filter(|n| {
                    n["name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || n["qualifiedName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || n["filePath"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                })
                .take(limit)
                .collect();

            lines.push(format!("  Matching nodes (showing {}):", matched.len()));
            for n in matched {
                let name = field_str(n, "name");
                let kind = field_str(n, "kind");
                let file = field_str(n, "filePath");
                let line = field_i64(n, "line");
                let local = n["local"].as_bool().unwrap_or(false);
                let ext = n["external"].as_bool().unwrap_or(false);
                let loc = if local { "local" } else if ext { "external" } else { "?" };
                lines.push(format!("    [{kind}][{loc}] {name} at {file}:{line}"));
            }
        }

        if let Some(edge_list) = cg["edges"].as_array() {
            let matched: Vec<&Value> = edge_list
                .iter()
                .filter(|e| {
                    e["sourceName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || e["targetName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                })
                .take(limit)
                .collect();

            lines.push(format!("  Matching edges (showing {}):", matched.len()));
            for e in matched {
                let src = field_str(e, "sourceName");
                let tgt = field_str(e, "targetName");
                let call_type = field_str(e, "callType");
                let file = e["position"]["filename"].as_str().unwrap_or("?");
                let line = field_i64(e, "line");
                lines.push(format!("    {call_type}: {src} → {tgt} at {file}:{line}"));
            }
        }
    }

    lines.join("\n")
}

pub fn query_dataflow(report: &Value, pattern: Option<&str>, limit: usize) -> String {
    let df = match report["dataFlow"].as_object() {
        Some(df) => df,
        None => return "No data-flow data available (not enabled in analysis).".to_string(),
    };

    let mode = df.get("mode").and_then(Value::as_str).unwrap_or("?");
    let slices = df["slices"].as_array().map(|a| a.len()).unwrap_or(0);
    let nodes = df["nodes"].as_array().map(|a| a.len()).unwrap_or(0);

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# Data Flow (mode: {mode}, {nodes} nodes, {slices} slices)"));

    if let Some(slice_list) = df["slices"].as_array() {
        let matched: Vec<&Value> = if let Some(pat) = pattern {
            let pat_lower = pat.to_lowercase();
            slice_list
                .iter()
                .filter(|s| {
                    s["sourceName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || s["sinkName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || s["ruleName"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || s["description"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                })
                .take(limit)
                .collect()
        } else {
            slice_list.iter().take(limit).collect()
        };

        lines.push(format!("  Slices (showing {} of {}):", matched.len(), slices));
        for s in matched {
            let src_name = field_str(s, "sourceName");
            let sink_name = field_str(s, "sinkName");
            let src_cat = field_str(s, "sourceCategory");
            let sink_cat = field_str(s, "sinkCategory");
            let rule = field_str(s, "ruleName");
            let path_len = field_i64(s, "pathLength");
            let risk = field_i64(s, "riskScore");
            let flow_key = field_str(s, "flowKey");

            lines.push(format!(
                "    [{rule}] {src_name} ({src_cat}) → {sink_name} ({sink_cat}) — {path_len} steps (risk: {risk}, key: {flow_key})"
            ));
        }
    }

    lines.join("\n")
}

pub fn query_imports(report: &Value, pattern: Option<&str>, limit: usize) -> String {
    let imports = match report["imports"].as_array() {
        Some(arr) => arr,
        None => return "No import data available.".to_string(),
    };

    let mut matched: Vec<&Value> = imports.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|i| {
            i["path"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || i["alias"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Imports", total: imports.len(), matched: matched.len(), shown: show.len() }.to_string());

    for i in show {
        let path = field_str(i, "path");
        let alias = i["alias"].as_str().filter(|a| !a.is_empty());
        let file = i["position"]["filename"].as_str().unwrap_or("?");
        let line = field_i64(i, "line");

        match alias {
            Some(a) => lines.push(format!("  {path} as {a} at {file}:{line}")),
            None => lines.push(format!("  {path} at {file}:{line}")),
        }
    }

    lines.join("\n")
}

pub fn query_crypto(report: &Value, pattern: Option<&str>) -> String {
    let crypto = match report["crypto"].as_object() {
        Some(c) => c,
        None => return "No crypto evidence available.".to_string(),
    };

    let mut lines: Vec<String> = Vec::new();

    // Libraries
    if let Some(libs) = crypto["libraries"].as_array() {
        lines.push(format!("# Crypto Libraries ({})", libs.len()));
        for lib in libs {
            let path = field_str(lib, "path");
            let family = field_str(lib, "family");
            let file = field_str(lib, "filePath");
            if !pattern_match(path, pattern) && !pattern_match(family, pattern) {
                continue;
            }
            lines.push(format!("  [{family}] {path} — {file}"));
        }
    }

    // Assets (golem-specific: cryptoAssets instead of components)
    if let Some(assets) = crypto["assets"].as_array() {
        lines.push(format!("# Crypto Assets ({})", assets.len()));
        for asset in assets {
            let kind = field_str(asset, "kind");
            let algorithm = field_str(asset, "algorithm");
            let provider = field_str(asset, "provider");
            let operation = field_str(asset, "operation");
            let file = field_str(asset, "filePath");
            if !pattern_match(algorithm, pattern)
                && !pattern_match(provider, pattern)
                && !pattern_match(kind, pattern)
            {
                continue;
            }
            lines.push(format!("  [{kind}] {algorithm} ({provider}) — {operation} at {file}"));
        }
    }

    // Materials
    if let Some(mats) = crypto["materials"].as_array() {
        lines.push(format!("# Crypto Materials ({})", mats.len()));
        for mat in mats {
            let kind = field_str(mat, "kind");
            let name = field_str(mat, "name");
            let file = field_str(mat, "filePath");
            if !pattern_match(name, pattern) && !pattern_match(kind, pattern) {
                continue;
            }
            lines.push(format!("  [{kind}] {name} — {file}"));
        }
    }

    // Findings
    if let Some(finds) = crypto["findings"].as_array() {
        lines.push(format!("# Crypto Findings ({})", finds.len()));
        for f in finds {
            let category = field_str(f, "category");
            let severity = field_str(f, "severity");
            let summary = field_str(f, "summary");
            let file = field_str(f, "filePath");
            if !pattern_match(summary, pattern) && !pattern_match(category, pattern) {
                continue;
            }
            lines.push(format!("  [{severity}] {category} — {summary} at {file}"));
        }
    }

    if lines.is_empty() {
        return "No crypto evidence available.".to_string();
    }
    lines.join("\n")
}

pub fn query_slices_ranked(report: &Value, limit: usize) -> String {
    let df = match report["dataFlow"].as_object() {
        Some(df) => df,
        None => return "No data-flow slices available.".to_string(),
    };

    let slice_list = match df["slices"].as_array() {
        Some(s) => s,
        None => return "No data-flow slices available.".to_string(),
    };

    let mut ranked: Vec<&Value> = slice_list.iter().collect();
    // Sort by riskScore descending, then severity
    ranked.sort_by(|a, b| {
        let risk_a = field_i64(a, "riskScore");
        let risk_b = field_i64(b, "riskScore");
        risk_b.cmp(&risk_a)
    });

    let show = ranked.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# Data-Flow Slices (top {} by risk score)", show.len()));

    for s in show {
        let src = field_str(s, "sourceName");
        let sink = field_str(s, "sinkName");
        let rule = field_str(s, "ruleName");
        let path_len = field_i64(s, "pathLength");
        let risk = field_i64(s, "riskScore");
        let severity = field_str(s, "severity");
        let confidence = field_str(s, "confidence");
        let taint_kinds = s["taintKinds"].as_array()
            .map(|k| k.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();

        lines.push(format!(
            "  [{severity}][risk={risk}][conf={confidence}] {rule}: {src} → {sink} ({path_len} hops)"
        ));
        if !taint_kinds.is_empty() {
            lines.push(format!("         taint: {taint_kinds}"));
        }
    }

    lines.join("\n")
}

pub fn query_source_sink_categories(report: &Value, which: &str) -> String {
    let df = match report["dataFlow"].as_object() {
        Some(df) => df,
        None => return format!("No data-flow data available for {which} categories."),
    };

    let nodes = match df["nodes"].as_array() {
        Some(n) => n,
        None => return format!("No data-flow nodes available for {which} categories."),
    };

    let categories: Vec<String> = nodes
        .iter()
        .filter(|n| which == "sources" && n["source"].as_bool().unwrap_or(false)
            || which == "sinks" && n["sink"].as_bool().unwrap_or(false))
        .filter_map(|n| n["category"].as_str().map(|c| c.to_string()))
        .collect();

    if categories.is_empty() {
        return format!("No {which} categories found.");
    }

    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for cat in categories {
        *counts.entry(cat).or_default() += 1;
    }

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# {} categories ({} unique):", which, counts.len()));
    for (cat, count) in &counts {
        lines.push(format!("  {cat}: {count}"));
    }

    lines.join("\n")
}

pub fn detail_declaration(report: &Value, name: &str) -> String {
    let decls = match report["declarations"].as_array() {
        Some(arr) => arr,
        None => return "No declaration data available.".to_string(),
    };

    let name_lower = name.to_lowercase();
    let matches: Vec<&Value> = decls
        .iter()
        .filter(|d| {
            d["name"].as_str().unwrap_or("").to_lowercase() == name_lower
                || d["qualifiedName"].as_str().unwrap_or("").to_lowercase() == name_lower
                || d["qualifiedName"].as_str().unwrap_or("").to_lowercase().contains(&name_lower)
        })
        .collect();

    if matches.is_empty() {
        return format!("No declaration matching '{name}' found.");
    }

    let mut lines: Vec<String> = Vec::new();
    for d in matches {
        let qname = field_str(d, "qualifiedName");
        let kind = field_str(d, "kind");
        let file = field_str(d, "filePath");
        let line = field_i64(d, "line");
        let sig = field_str(d, "signature");
        let package = field_str(d, "packagePath");
        let purl = field_str(d, "purl");
        let canonical = field_str(d, "canonicalName");

        lines.push(format!("# Declaration: {qname}"));
        lines.push(format!("  Kind: {kind}"));
        lines.push(format!("  Location: {file}:{line}"));
        lines.push(format!("  Package: {package}"));
        lines.push(format!("  PURL: {purl}"));
        lines.push(format!("  Canonical: {canonical}"));
        if !sig.is_empty() && sig != "?" {
            lines.push(format!("  Signature:\n    {sig}"));
        }

        // Find callers/callees from call graph
        if let Some(cg) = report["callGraph"].as_object()
            && let Some(edges) = cg["edges"].as_array() {
                let outgoing: Vec<&Value> = edges
                    .iter()
                    .filter(|e| {
                        e["sourceName"].as_str().unwrap_or("").to_lowercase() == name_lower
                            || e["sourceId"].as_str().unwrap_or("").to_lowercase() == name_lower
                    })
                    .collect();
                if !outgoing.is_empty() {
                    lines.push(format!("  Calls ({}):", outgoing.len()));
                    for e in outgoing.iter().take(10) {
                        let tgt = field_str(e, "targetName");
                        let call_type = field_str(e, "callType");
                        lines.push(format!("    → {tgt} ({call_type})"));
                    }
                }

                let incoming: Vec<&Value> = edges
                    .iter()
                    .filter(|e| {
                        e["targetName"].as_str().unwrap_or("").to_lowercase() == name_lower
                            || e["targetId"].as_str().unwrap_or("").to_lowercase() == name_lower
                    })
                    .collect();
                if !incoming.is_empty() {
                    lines.push(format!("  Called by ({}):", incoming.len()));
                    for e in incoming.iter().take(10) {
                        let src = field_str(e, "sourceName");
                        let call_type = field_str(e, "callType");
                        lines.push(format!("    ← {src} ({call_type})"));
                    }
                }
            }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_report() -> Value {
        json!({
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
                "dataFlowSliceCount": 2,
                "cryptoLibraryCount": 1,
                "cryptoComponentCount": 2
            },
            "packages": [
                { "name": "myapp", "version": "0.1.0", "purl": "pkg:go/myapp@0.1.0", "files": ["main.go", "lib.go"] }
            ],
            "files": [
                { "path": "main.go", "packageName": "myapp" },
                { "path": "lib.go", "packageName": "myapp" }
            ],
            "imports": [
                { "path": "os", "alias": null, "position": { "filename": "main.go", "line": 1 } },
                { "path": "os/exec", "alias": null, "position": { "filename": "main.go", "line": 2 } }
            ],
            "declarations": [
                { "name": "main", "qualifiedName": "myapp.main", "canonicalName": "myapp.main", "kind": "function", "packagePath": "myapp", "purl": "pkg:go/myapp@0.1.0", "filePath": "main.go", "signature": "func main()", "line": 5 }
            ],
            "usages": [
                { "kind": "call", "name": "os.Getenv", "packagePath": "myapp", "enclosingDeclaration": "myapp.main", "position": { "filename": "main.go", "line": 6 } }
            ],
            "securitySignals": [
                { "category": "unsafe-code", "severity": "medium", "confidence": "high", "description": "Unsafe function used", "filePath": "lib.go", "line": 15 }
            ],
            "callGraph": {
                "mode": "static",
                "nodes": [
                    { "name": "main", "qualifiedName": "myapp.main", "kind": "function", "filePath": "main.go", "local": true, "external": false, "line": 5 }
                ],
                "edges": [
                    { "sourceName": "main", "targetName": "runCmd", "callType": "static", "position": { "filename": "main.go", "line": 8 } }
                ]
            },
            "dataFlow": {
                "mode": "security",
                "nodes": [
                    { "kind": "source", "name": "os.Getenv", "source": true, "sink": false, "category": "env" },
                    { "kind": "sink", "name": "exec.Command", "source": false, "sink": true, "category": "process-exec" }
                ],
                "edges": [],
                "slices": [
                    { "sourceName": "os.Getenv", "sinkName": "exec.Command", "sourceCategory": "env", "sinkCategory": "process-exec", "ruleName": "env-to-exec", "pathLength": 2, "flowKey": "env-to-exec-1", "riskScore": 85, "severity": "high", "confidence": "high", "taintKinds": ["os-env"] }
                ]
            },
            "crypto": {
                "libraries": [
                    { "path": "crypto/sha256", "family": "hash", "filePath": "lib.go" }
                ],
                "assets": [
                    { "kind": "hash", "algorithm": "SHA-256", "provider": "crypto/sha256", "operation": "digest", "filePath": "lib.go" }
                ],
                "materials": [],
                "findings": []
            }
        })
    }

    #[test]
    fn test_extract_summary() {
        let summary = extract_summary(&test_report());
        assert!(summary.contains("golem"));
        assert!(summary.contains("Declarations: 4"));
        assert!(summary.contains("Data flow"));
    }

    #[test]
    fn test_query_packages() {
        let result = query_packages(&test_report(), None);
        assert!(result.contains("myapp"));
        assert!(result.contains("pkg:go/myapp@0.1.0"));
    }

    #[test]
    fn test_query_declarations() {
        let result = query_declarations(&test_report(), Some("main"), 50);
        assert!(result.contains("myapp.main"));
        assert!(result.contains("func main()"));
    }

    #[test]
    fn test_query_dataflow() {
        let result = query_dataflow(&test_report(), Some("os.Getenv"), 50);
        assert!(result.contains("os.Getenv"));
        assert!(result.contains("exec.Command"));
        assert!(result.contains("risk: 85"));
    }

    #[test]
    fn test_query_callgraph() {
        let result = query_callgraph(&test_report(), Some("main"), 50);
        assert!(result.contains("main"));
    }

    #[test]
    fn test_query_security_signals() {
        let result = query_security_signals(&test_report(), None, 50);
        assert!(result.contains("unsafe-code"));
    }

    #[test]
    fn test_query_crypto() {
        let result = query_crypto(&test_report(), Some("sha256"));
        assert!(result.contains("SHA-256"));
    }

    #[test]
    fn test_query_imports() {
        let result = query_imports(&test_report(), Some("os/exec"), 50);
        assert!(result.contains("os/exec"));
    }

    #[test]
    fn test_detail_declaration() {
        let result = detail_declaration(&test_report(), "main");
        assert!(result.contains("myapp.main"));
        assert!(result.contains("main.go:5"));
    }

    #[test]
    fn test_query_slices_ranked() {
        let result = query_slices_ranked(&test_report(), 10);
        assert!(result.contains("risk=85"));
        assert!(result.contains("env-to-exec"));
    }

    #[test]
    fn test_query_source_sink_categories() {
        let result = query_source_sink_categories(&test_report(), "sources");
        assert!(result.contains("env"));
    }

    #[test]
    fn test_empty_report_returns_helpful_message() {
        let empty = json!({});
        assert!(query_packages(&empty, None).contains("No package data"));
        assert!(query_dataflow(&empty, None, 50).contains("No data-flow data"));
        assert!(query_crypto(&empty, None).contains("No crypto evidence"));
    }
}
