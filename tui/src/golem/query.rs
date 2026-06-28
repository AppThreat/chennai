//! Query formatters for the golem (Go) JSON schema.
//!
//! These functions translate the structured `golem analyze` report into compact,
//! LLM- and human-friendly text. Each function is read-only and never panics on a
//! missing key — absent data yields a clear "No … available" message instead.
//!
//! # Schema reference (verified against golem 2.5.1 output)
//! golem uses camelCase keys. Source positions are nested, and differ by entity:
//! - declarations / usages / imports / securitySignals / crypto → `range.start.{filename,line}`
//! - callGraph nodes & edges → `position.{filename,line}`
//!
//! Other notable shapes:
//! - `stats` holds top-level counts; call-graph and data-flow counts live under
//!   `callGraph.stats` and `dataFlow.stats` respectively.
//! - `dataFlow` exposes taint `summaries` (per-function param→sink-category) and
//!   flagged `nodes` (each with `source`/`sink` booleans and a `category`). It may also
//!   emit a flat `slices` array of fully materialized source→sink paths — but only when
//!   the scan is run with `--include-all-flows` (and often `--include-stdlib`); the
//!   default scan leaves `slices` empty and reports only `summaries`. When slices are
//!   present they are the richest evidence (named source/sink functions, rule, severity,
//!   taint kinds), so the formatter prefers them.
//! - `crypto` exposes `libraries`, `materials`, and `findings` (no `assets`).

use crate::shared::{field_i64, field_str, pattern_match, ListHeader};
use serde_json::Value;

/// Extract a `(filename, line)` position from a golem entity.
///
/// Golem stores positions either under `range.start.{filename,line}` (declarations,
/// usages, imports, security signals, crypto entries) or under `position.{filename,line}`
/// (call-graph nodes and edges). Returns `("?", 0)` when neither is present.
fn golem_loc(obj: &Value) -> (String, i64) {
    if let Some(start) = obj.get("range").and_then(|r| r.get("start")) {
        return (
            start.get("filename").and_then(Value::as_str).unwrap_or("?").to_string(),
            start.get("line").and_then(Value::as_i64).unwrap_or(0),
        );
    }
    if let Some(pos) = obj.get("position") {
        return (
            pos.get("filename").and_then(Value::as_str).unwrap_or("?").to_string(),
            pos.get("line").and_then(Value::as_i64).unwrap_or(0),
        );
    }
    ("?".to_string(), 0)
}

/// Count entries in an array field, falling back to a stats counter when absent.
fn count_or(report: &Value, array_path: &[&str], stat_key: &str) -> i64 {
    let mut node = report;
    for key in array_path {
        node = &node[key];
    }
    if let Some(arr) = node.as_array() {
        return arr.len() as i64;
    }
    field_i64(&report["stats"], stat_key)
}

/// Render the golem report summary from the `stats` object (with array fallbacks).
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

    // Call-graph counts live under `callGraph.stats`.
    let cg_stats = &report["callGraph"]["stats"];
    let cg_nodes = field_i64(cg_stats, "nodeCount");
    let cg_edges = field_i64(cg_stats, "edgeCount");

    // Data-flow counts live under `dataFlow.stats`.
    let df_stats = &report["dataFlow"]["stats"];
    let df_sources = field_i64(df_stats, "sourceCount");
    let df_sinks = field_i64(df_stats, "sinkCount");
    let df_slices = field_i64(df_stats, "sliceCount");
    let df_summaries = field_i64(df_stats, "summaryCount");

    let crypto_libs = field_i64(stats, "cryptoLibraryCount");
    let crypto_mats = field_i64(stats, "cryptoMaterialCount");
    let crypto_finds = field_i64(stats, "cryptoFindingCount");
    let endpoints = count_or(report, &["apiEndpoints"], "apiEndpointCount");

    // golem sets `dataFlow.stats.truncated` when very large functions were skipped during
    // slice materialization (summaries are still inferred). Surface this so the agent treats
    // an empty/short slice list as a coverage limit, not proof of "no flows".
    let truncation_note = if df_stats["truncated"].as_bool().unwrap_or(false) {
        "\nNote: data-flow slice materialization was TRUNCATED (some very large functions were skipped); rely on function summaries and treat a low slice count as incomplete, not as absence of flows."
    } else {
        ""
    };

    format!(
        "Analysis tool: {tool_name} v{tool_ver}\n\
         Packages: {packages} | Files: {files} | Imports: {imports}\n\
         Declarations: {declarations} | Usages (calls): {usages} | Security signals: {security}\n\
         Call graph: {cg_nodes} nodes, {cg_edges} edges\n\
         Data flow: {df_sources} sources, {df_sinks} sinks, {df_slices} slices, {df_summaries} function summaries\n\
         API endpoints: {endpoints}\n\
         Crypto: {crypto_libs} libraries, {crypto_mats} materials, {crypto_finds} findings{truncation_note}"
    )
}

pub fn query_packages(report: &Value, pattern: Option<&str>) -> String {
    let packages = match report["packages"].as_array() {
        Some(arr) => arr,
        None => return "No package data available.".to_string(),
    };

    let matched: Vec<&Value> = packages
        .iter()
        .filter(|pkg| {
            pattern_match(field_str(pkg, "name"), pattern)
                || pattern_match(field_str(pkg, "purl"), pattern)
        })
        .collect();

    let mut lines: Vec<String> = vec![ListHeader {
        title: "Packages",
        total: packages.len(),
        matched: matched.len(),
        shown: matched.len(),
    }
    .to_string()];

    for pkg in matched {
        let name = field_str(pkg, "name");
        let version = field_str(pkg, "version");
        let purl = field_str(pkg, "purl");
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

    let matched: Vec<&Value> = files
        .iter()
        .filter(|file| {
            pattern_match(field_str(file, "path"), pattern)
                || pattern_match(field_str(file, "packageName"), pattern)
        })
        .collect();

    let mut lines: Vec<String> = vec![ListHeader {
        title: "Files",
        total: files.len(),
        matched: matched.len(),
        shown: matched.len(),
    }
    .to_string()];

    for file in matched {
        let path = field_str(file, "path");
        let package = field_str(file, "packageName");
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
            field_str(d, "name").to_lowercase().contains(&pat_lower)
                || field_str(d, "packagePath").to_lowercase().contains(&pat_lower)
                || field_str(d, "signature").to_lowercase().contains(&pat_lower)
        });
    }

    let show: Vec<&Value> = matched.iter().take(limit).copied().collect();
    let mut lines: Vec<String> = vec![ListHeader {
        title: "Declarations",
        total: decls.len(),
        matched: matched.len(),
        shown: show.len(),
    }
    .to_string()];

    for d in show {
        let name = field_str(d, "name");
        let kind = field_str(d, "kind");
        let package = field_str(d, "packagePath");
        let receiver = d["receiver"].as_str().filter(|r| !r.is_empty());
        let (file, line) = golem_loc(d);
        let sig = d["signature"].as_str().unwrap_or("");

        match receiver {
            Some(r) => lines.push(format!("  [{kind}] ({r}) {name}")),
            None => lines.push(format!("  [{kind}] {name}")),
        }
        lines.push(format!("         {package}"));
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
            field_str(u, "name").to_lowercase().contains(&pat_lower)
                || field_str(u, "qualifiedName").to_lowercase().contains(&pat_lower)
                || field_str(u, "kind").to_lowercase().contains(&pat_lower)
        });
    }

    let show: Vec<&Value> = matched.iter().take(limit).copied().collect();
    let mut lines: Vec<String> = vec![ListHeader {
        title: "Usages/Calls",
        total: usages.len(),
        matched: matched.len(),
        shown: show.len(),
    }
    .to_string()];

    for u in show {
        let name = field_str(u, "name");
        let qname = u["qualifiedName"].as_str().filter(|q| !q.is_empty() && *q != "?");
        let kind = field_str(u, "kind");
        let (file, line) = golem_loc(u);
        let enclosing = u["enclosing"]["name"].as_str().filter(|e| !e.is_empty());

        match qname {
            Some(q) => lines.push(format!("  [{kind}] {name} ({q}) at {file}:{line}")),
            None => lines.push(format!("  [{kind}] {name} at {file}:{line}")),
        }
        if let Some(e) = enclosing {
            lines.push(format!("         in: {e}"));
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
            field_str(s, "category").to_lowercase().contains(&cat_lower)
                || field_str(s, "symbol").to_lowercase().contains(&cat_lower)
                || field_str(s, "description").to_lowercase().contains(&cat_lower)
        });
    }

    let show: Vec<&Value> = matched.iter().take(limit).copied().collect();
    let mut lines: Vec<String> = vec![ListHeader {
        title: "Security Signals",
        total: signals.len(),
        matched: matched.len(),
        shown: show.len(),
    }
    .to_string()];

    for s in show {
        let category = field_str(s, "category");
        let severity = field_str(s, "severity");
        let confidence = field_str(s, "confidence");
        let symbol = field_str(s, "symbol");
        let desc = field_str(s, "description");
        let (file, line) = golem_loc(s);

        lines.push(format!("  [{severity}][{confidence}] {category} — {symbol}"));
        if desc != "?" {
            lines.push(format!("         {desc}"));
        }
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

    let mut lines: Vec<String> =
        vec![format!("# Call Graph (mode: {mode}, {nodes} nodes, {edges} edges)")];

    let pat_lower = pattern.map(|p| p.to_lowercase());

    if let Some(node_list) = cg["nodes"].as_array() {
        let matched: Vec<&Value> = node_list
            .iter()
            .filter(|n| match &pat_lower {
                Some(p) => {
                    field_str(n, "name").to_lowercase().contains(p)
                        || field_str(n, "packagePath").to_lowercase().contains(p)
                }
                None => true,
            })
            .take(limit)
            .collect();

        lines.push(format!("  Matching nodes (showing {}):", matched.len()));
        for n in matched {
            let name = field_str(n, "name");
            let kind = field_str(n, "kind");
            let (file, line) = golem_loc(n);
            let local = n["local"].as_bool().unwrap_or(false);
            let ext = n["external"].as_bool().unwrap_or(false);
            let loc = if local { "local" } else if ext { "external" } else { "?" };
            lines.push(format!("    [{kind}][{loc}] {name} at {file}:{line}"));
        }
    }

    if let Some(edge_list) = cg["edges"].as_array() {
        let matched: Vec<&Value> = edge_list
            .iter()
            .filter(|e| match &pat_lower {
                Some(p) => {
                    field_str(e, "sourceName").to_lowercase().contains(p)
                        || field_str(e, "targetName").to_lowercase().contains(p)
                }
                None => true,
            })
            .take(limit)
            .collect();

        lines.push(format!("  Matching edges (showing {}):", matched.len()));
        for e in matched {
            let src = field_str(e, "sourceName");
            let tgt = field_str(e, "targetName");
            let call_type = field_str(e, "callType");
            let (file, line) = golem_loc(e);
            lines.push(format!("    {call_type}: {src} → {tgt} at {file}:{line}"));
        }
    }

    lines.join("\n")
}

/// Query data-flow evidence: per-function taint summaries plus flagged source/sink nodes.
///
/// golem represents flows as `dataFlow.summaries` (each links a function's parameters
/// to the sink categories they reach) rather than a flat slice list.
pub fn query_dataflow(report: &Value, pattern: Option<&str>, limit: usize) -> String {
    let df = match report["dataFlow"].as_object() {
        Some(df) => df,
        None => return "No data-flow data available (not enabled in analysis).".to_string(),
    };

    let mode = df.get("mode").and_then(Value::as_str).unwrap_or("?");
    let stats = &df["stats"];
    let sources = field_i64(stats, "sourceCount");
    let sinks = field_i64(stats, "sinkCount");
    let slices = field_i64(stats, "sliceCount");

    let mut lines: Vec<String> = vec![format!(
        "# Data Flow (mode: {mode}, {sources} sources, {sinks} sinks, {slices} slices)"
    )];

    // Prefer materialized slices (richest evidence) when present, then fall back to
    // per-function summaries, then to raw flagged source/sink nodes.
    let slice_arr = df.get("slices").and_then(Value::as_array);
    let summary_arr = df.get("summaries").and_then(Value::as_array);
    match (slice_arr, summary_arr) {
        (Some(arr), _) if !arr.is_empty() => {
            lines.push(format_slices(arr, pattern, limit));
        }
        (_, Some(arr)) if !arr.is_empty() => {
            lines.push(format_summaries(arr, pattern, limit));
        }
        _ => {
            lines.push(
                "  No taint slices or function summaries reported. Showing flagged source/sink nodes instead:"
                    .to_string(),
            );
            lines.push(format_flagged_nodes(df.get("nodes").and_then(Value::as_array), pattern, limit));
        }
    }

    lines.join("\n")
}

/// Extract a `(filename, line)` position from a golem data-flow node id.
///
/// Slice node ids are pipe-delimited and encode the position near the end as
/// `…|<filename>|<line>|<column>|<category>`, e.g.
/// `df-node|source|fn|symbol|name|/path/file.go|319|20|parameter`. We read the
/// filename and line from the trailing fixed-position fields. Returns `("?", 0)`
/// when the id is too short or the line is not numeric.
fn node_id_loc(id: &str) -> (String, i64) {
    let parts: Vec<&str> = id.split('|').collect();
    if parts.len() >= 4 {
        let file = parts[parts.len() - 4].to_string();
        let line = parts[parts.len() - 3].parse::<i64>().unwrap_or(0);
        return (file, line);
    }
    ("?".to_string(), 0)
}

/// Render fully materialized taint slices ranked by severity then confidence.
///
/// Each slice is a concrete source→sink path. We surface the named source/sink
/// functions, the firing rule, severity, taint kinds, and the source/sink file
/// positions (decoded from the node ids).
fn format_slices(slices: &[Value], pattern: Option<&str>, limit: usize) -> String {
    let matched: Vec<&Value> = slices
        .iter()
        .filter(|s| {
            pattern_match(field_str(s, "sourceFunction"), pattern)
                || pattern_match(field_str(s, "sinkFunction"), pattern)
                || pattern_match(field_str(s, "ruleId"), pattern)
                || pattern_match(field_str(s, "sinkCategory"), pattern)
                || pattern_match(field_str(s, "sourcePackagePath"), pattern)
        })
        .collect();

    let mut ranked = matched;
    ranked.sort_by_key(|s| {
        std::cmp::Reverse((
            severity_rank(field_str(s, "severity")),
            confidence_rank(field_str(s, "confidence")),
            field_i64(s, "riskScore"),
        ))
    });

    let mut lines: Vec<String> = vec![format!(
        "  Taint slices (showing {} of {}, ranked by severity):",
        ranked.len().min(limit),
        slices.len()
    )];

    for s in ranked.into_iter().take(limit) {
        let severity = field_str(s, "severity");
        let confidence = field_str(s, "confidence");
        let rule = field_str(s, "ruleName");
        let src_fn = field_str(s, "sourceFunction");
        let src_name = field_str(s, "sourceName");
        let sink_fn = field_str(s, "sinkFunction");
        let sink_name = field_str(s, "sinkName");
        let path_len = field_i64(s, "pathLength");
        let taints = s["taintKinds"]
            .as_array()
            .map(|t| t.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        let (src_file, src_line) = node_id_loc(field_str(s, "sourceId"));
        let (sink_file, sink_line) = node_id_loc(field_str(s, "sinkId"));

        lines.push(format!("    [{severity}][conf={confidence}] {rule}"));
        lines.push(format!("         source: {src_fn} ({src_name}) at {src_file}:{src_line}"));
        lines.push(format!("         sink:   {sink_fn} ({sink_name}) at {sink_file}:{sink_line}"));
        if !taints.is_empty() {
            lines.push(format!("         taint: {taints} | path length: {path_len}"));
        }
    }

    lines.join("\n")
}

/// Rank a severity label so `critical > high > medium > low > unknown`.
fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Render per-function taint summaries ranked by confidence.
fn format_summaries(summaries: &[Value], pattern: Option<&str>, limit: usize) -> String {
    let mut matched: Vec<&Value> = summaries
        .iter()
        .filter(|s| {
            pattern_match(field_str(s, "function"), pattern)
                || pattern_match(field_str(s, "packagePath"), pattern)
        })
        .collect();

    matched.sort_by_key(|s| std::cmp::Reverse(confidence_rank(field_str(s, "confidence"))));

    let mut lines: Vec<String> = vec![format!(
        "  Function taint summaries (showing {} of {}):",
        matched.len().min(limit),
        summaries.len()
    )];

    for s in matched.into_iter().take(limit) {
        let function = field_str(s, "function");
        let confidence = field_str(s, "confidence");
        let sinks: Vec<String> = s["paramToSink"]
            .as_array()
            .map(|ps| {
                ps.iter()
                    .map(|p| {
                        let idx = field_i64(p, "parameterIndex");
                        let cats = p["categories"]
                            .as_array()
                            .map(|c| c.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default();
                        format!("param[{idx}] → {cats}")
                    })
                    .collect()
            })
            .unwrap_or_default();
        lines.push(format!("    [conf={confidence}] {function}"));
        for sink in sinks {
            lines.push(format!("         {sink}"));
        }
    }

    lines.join("\n")
}

/// Render flagged source/sink data-flow nodes (fallback when no summaries exist).
fn format_flagged_nodes(nodes: Option<&Vec<Value>>, pattern: Option<&str>, limit: usize) -> String {
    let nodes = match nodes {
        Some(n) => n,
        None => return "  No data-flow nodes available.".to_string(),
    };
    let matched: Vec<&Value> = nodes
        .iter()
        .filter(|n| n["source"].as_bool().unwrap_or(false) || n["sink"].as_bool().unwrap_or(false))
        .filter(|n| {
            pattern_match(field_str(n, "name"), pattern)
                || pattern_match(field_str(n, "category"), pattern)
                || pattern_match(field_str(n, "function"), pattern)
        })
        .take(limit)
        .collect();

    if matched.is_empty() {
        return "  No flagged source/sink nodes.".to_string();
    }

    let mut lines: Vec<String> = Vec::new();
    for n in matched {
        let role = if n["source"].as_bool().unwrap_or(false) { "source" } else { "sink" };
        let name = field_str(n, "name");
        let category = field_str(n, "category");
        let (file, line) = golem_loc(n);
        lines.push(format!("    [{role}] {name} ({category}) at {file}:{line}"));
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

pub fn query_imports(report: &Value, pattern: Option<&str>, limit: usize) -> String {
    let imports = match report["imports"].as_array() {
        Some(arr) => arr,
        None => return "No import data available.".to_string(),
    };

    let mut matched: Vec<&Value> = imports.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|i| field_str(i, "path").to_lowercase().contains(&pat_lower));
    }

    let show: Vec<&Value> = matched.iter().take(limit).copied().collect();
    let mut lines: Vec<String> = vec![ListHeader {
        title: "Imports",
        total: imports.len(),
        matched: matched.len(),
        shown: show.len(),
    }
    .to_string()];

    for i in show {
        let path = field_str(i, "path");
        let standard = i["standard"].as_bool().unwrap_or(false);
        let tag = if standard { " [stdlib]" } else { "" };
        let (file, line) = golem_loc(i);
        lines.push(format!("  {path}{tag} at {file}:{line}"));
    }

    lines.join("\n")
}

pub fn query_crypto(report: &Value, pattern: Option<&str>) -> String {
    let crypto = match report["crypto"].as_object() {
        Some(c) => c,
        None => return "No crypto evidence available.".to_string(),
    };

    let mut lines: Vec<String> = Vec::new();

    if let Some(libs) = crypto["libraries"].as_array() {
        lines.push(format!("# Crypto Libraries ({})", libs.len()));
        for lib in libs {
            let path = field_str(lib, "path");
            let family = field_str(lib, "family");
            if !pattern_match(path, pattern) && !pattern_match(family, pattern) {
                continue;
            }
            let (file, line) = golem_loc(lib);
            lines.push(format!("  [{family}] {path} — {file}:{line}"));
        }
    }

    if let Some(mats) = crypto["materials"].as_array() {
        lines.push(format!("# Crypto Materials ({})", mats.len()));
        for mat in mats {
            let kind = field_str(mat, "type");
            let name = field_str(mat, "name");
            let symbol = field_str(mat, "symbol");
            if !pattern_match(name, pattern) && !pattern_match(kind, pattern) {
                continue;
            }
            let (file, line) = golem_loc(mat);
            lines.push(format!("  [{kind}] {name} ({symbol}) — {file}:{line}"));
        }
    }

    if let Some(finds) = crypto["findings"].as_array() {
        lines.push(format!("# Crypto Findings ({})", finds.len()));
        for f in finds {
            let rule = field_str(f, "ruleId");
            let severity = field_str(f, "severity");
            let summary = field_str(f, "summary");
            if !pattern_match(summary, pattern) && !pattern_match(rule, pattern) {
                continue;
            }
            let (file, line) = golem_loc(f);
            lines.push(format!("  [{severity}] {rule} — {summary} at {file}:{line}"));
        }
    }

    if lines.is_empty() {
        return "No crypto evidence available.".to_string();
    }
    lines.join("\n")
}

/// List API endpoints (HTTP routes) discovered by golem.
pub fn query_endpoints(report: &Value, pattern: Option<&str>) -> String {
    let endpoints = match report["apiEndpoints"].as_array() {
        Some(arr) => arr,
        None => return "No API endpoint data available.".to_string(),
    };

    let matched: Vec<&Value> = endpoints
        .iter()
        .filter(|ep| {
            pattern_match(field_str(ep, "path"), pattern)
                || pattern_match(field_str(ep, "handler"), pattern)
                || pattern_match(field_str(ep, "framework"), pattern)
        })
        .collect();

    let mut lines: Vec<String> = vec![ListHeader {
        title: "API Endpoints",
        total: endpoints.len(),
        matched: matched.len(),
        shown: matched.len(),
    }
    .to_string()];

    for ep in matched {
        let method = field_str(ep, "method");
        let path = field_str(ep, "path");
        let handler = field_str(ep, "handler");
        let framework = field_str(ep, "framework");
        let (file, line) = golem_loc(ep);
        lines.push(format!("  {method} {path} → {handler} ({framework}) at {file}:{line}"));
    }

    lines.join("\n")
}

/// Rank flows for the `flows` tool: same data as [`query_dataflow`] with no pattern filter.
pub fn query_slices_ranked(report: &Value, limit: usize) -> String {
    query_dataflow(report, None, limit)
}

/// List the distinct source or sink categories with counts, for orientation.
pub fn query_source_sink_categories(report: &Value, which: &str) -> String {
    let nodes = match report["dataFlow"]["nodes"].as_array() {
        Some(n) => n,
        None => return format!("No data-flow nodes available for {which} categories."),
    };

    let want_source = which == "sources";
    let categories: Vec<String> = nodes
        .iter()
        .filter(|n| {
            if want_source {
                n["source"].as_bool().unwrap_or(false)
            } else {
                n["sink"].as_bool().unwrap_or(false)
            }
        })
        .filter_map(|n| n["category"].as_str().map(str::to_string))
        .collect();

    if categories.is_empty() {
        return format!("No {which} categories found.");
    }

    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for cat in categories {
        *counts.entry(cat).or_default() += 1;
    }

    let mut lines: Vec<String> = vec![format!("# {} categories ({} unique):", which, counts.len())];
    for (cat, count) in &counts {
        lines.push(format!("  {cat}: {count}"));
    }

    lines.join("\n")
}

/// Look up a declaration by name, package path, or signature and show its call-graph neighbours.
pub fn detail_declaration(report: &Value, name: &str) -> String {
    let decls = match report["declarations"].as_array() {
        Some(arr) => arr,
        None => return "No declaration data available.".to_string(),
    };

    let name_lower = name.to_lowercase();
    let matches: Vec<&Value> = decls
        .iter()
        .filter(|d| {
            field_str(d, "name").to_lowercase() == name_lower
                || field_str(d, "name").to_lowercase().contains(&name_lower)
                || field_str(d, "packagePath").to_lowercase().contains(&name_lower)
        })
        .collect();

    if matches.is_empty() {
        return format!("No declaration matching '{name}' found.");
    }

    let mut lines: Vec<String> = Vec::new();
    for d in matches.iter().take(10) {
        let name = field_str(d, "name");
        let kind = field_str(d, "kind");
        let (file, line) = golem_loc(d);
        let sig = field_str(d, "signature");
        let package = field_str(d, "packagePath");
        let receiver = d["receiver"].as_str().filter(|r| !r.is_empty());

        lines.push(format!("# Declaration: {name}"));
        lines.push(format!("  Kind: {kind}"));
        if let Some(r) = receiver {
            lines.push(format!("  Receiver: {r}"));
        }
        lines.push(format!("  Location: {file}:{line}"));
        lines.push(format!("  Package: {package}"));
        if sig != "?" {
            lines.push(format!("  Signature: {sig}"));
        }

        if let Some(edges) = report["callGraph"]["edges"].as_array() {
            let outgoing: Vec<&Value> = edges
                .iter()
                .filter(|e| field_str(e, "sourceName").to_lowercase().contains(&name_lower))
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
                .filter(|e| field_str(e, "targetName").to_lowercase().contains(&name_lower))
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

    /// A fixture mirroring the real golem 2.5.1 schema (trimmed records captured from
    /// `golem analyze` output): nested `range.start` / `position` positions, `callGraph.stats`,
    /// `dataFlow.summaries`, and `crypto.{libraries,materials,findings}`.
    fn test_report() -> Value {
        json!({
            "tool": { "name": "golem", "version": "2.5.1" },
            "stats": {
                "packageCount": 1, "fileCount": 2, "importCount": 1, "declarationCount": 1,
                "usageCount": 1, "securitySignalCount": 1, "apiEndpointCount": 1,
                "cryptoLibraryCount": 1, "cryptoMaterialCount": 1, "cryptoFindingCount": 1
            },
            "packages": [
                { "name": "myapp", "version": "0.1.0", "purl": "pkg:golang/myapp@0.1.0", "files": ["main.go", "lib.go"] }
            ],
            "files": [
                { "path": "main.go", "packageName": "myapp" },
                { "path": "lib.go", "packageName": "myapp" }
            ],
            "imports": [
                { "path": "os/exec", "aliasKind": "default", "standard": true, "range": { "start": { "filename": "main.go", "line": 4 } } }
            ],
            "declarations": [
                { "id": "myapp|*Gorm|Close|func()", "name": "Close", "kind": "method", "packagePath": "myapp", "receiver": "*Gorm", "signature": "func()", "range": { "start": { "filename": "db.go", "line": 74 } } }
            ],
            "usages": [
                { "kind": "call", "name": "Getenv", "qualifiedName": "os.Getenv", "enclosing": { "name": "main" }, "range": { "start": { "filename": "main.go", "line": 6 } } }
            ],
            "securitySignals": [
                { "category": "http-client", "severity": "medium", "confidence": "type-resolved", "symbol": "net/http.Get", "description": "Uses package-level HTTP client defaults.", "range": { "start": { "filename": "mw.go", "line": 14 } } }
            ],
            "apiEndpoints": [
                { "kind": "http-route", "framework": "echo", "method": "GET", "path": "/connect/token", "handler": "token", "range": { "start": { "filename": "oauth2.go", "line": 112 } } }
            ],
            "callGraph": {
                "mode": "static",
                "stats": { "nodeCount": 2, "edgeCount": 1 },
                "nodes": [
                    { "name": "main", "kind": "function", "packagePath": "myapp", "local": true, "external": false, "position": { "filename": "main.go", "line": 5 } }
                ],
                "edges": [
                    { "sourceName": "main", "targetName": "runCmd", "callType": "static", "position": { "filename": "main.go", "line": 8 } }
                ]
            },
            "dataFlow": {
                "mode": "security",
                "stats": { "sourceCount": 1, "sinkCount": 1, "sliceCount": 0, "summaryCount": 1 },
                "nodes": [
                    { "kind": "source", "name": "input", "source": true, "sink": false, "category": "parameter", "function": "GetTypeName", "position": { "filename": "type_mapper.go", "line": 72 } },
                    { "kind": "sink", "name": "exec.Command", "source": false, "sink": true, "category": "process-exec", "position": { "filename": "run.go", "line": 20 } }
                ],
                "summaries": [
                    { "function": "myapp/mapper.Map", "packagePath": "myapp/mapper", "paramToSink": [ { "parameterIndex": 0, "categories": ["unsafe"] } ], "confidence": "medium" }
                ],
                "slices": [
                    {
                        "sourceId": "df-node|source|myapp.handler|parameter req : string|req|/app/handler.go|42|20|parameter",
                        "sinkId": "df-node|sink|myapp.run|exec.Command|Command|/app/run.go|88|17|process-exec",
                        "sourceFunction": "myapp.handler", "sourceName": "req",
                        "sinkFunction": "myapp.run", "sinkName": "Command",
                        "sinkCategory": "process-exec", "sourcePackagePath": "myapp",
                        "taintKinds": ["user-input", "process-exec"], "pathLength": 3,
                        "ruleId": "GOLEM-DATAFLOW-CMD-INJECTION", "ruleName": "User input reaches process execution",
                        "severity": "critical", "riskScore": 95, "confidence": "high"
                    }
                ]
            },
            "crypto": {
                "libraries": [
                    { "path": "golang.org/x/crypto/bcrypt", "family": "x-crypto", "range": { "start": { "filename": "password.go", "line": 3 } } }
                ],
                "materials": [
                    { "type": "token", "name": "token", "symbol": "literal", "range": { "start": { "filename": "mw.go", "line": 49 } } }
                ],
                "findings": [
                    { "ruleId": "GOLEM-CRYPTO-LITERAL-MATERIAL", "severity": "medium", "summary": "Potential hardcoded cryptographic material indicator detected.", "range": { "start": { "filename": "mw.go", "line": 54 } } }
                ]
            }
        })
    }

    #[test]
    fn test_extract_summary() {
        let summary = extract_summary(&test_report());
        assert!(summary.contains("golem v2.5.1"));
        assert!(summary.contains("Declarations: 1"));
        assert!(summary.contains("Call graph: 2 nodes, 1 edges"));
        assert!(summary.contains("1 sources, 1 sinks"));
        assert!(summary.contains("API endpoints: 1"));
    }

    #[test]
    fn test_query_packages() {
        let result = query_packages(&test_report(), None);
        assert!(result.contains("myapp"));
        assert!(result.contains("pkg:golang/myapp@0.1.0"));
        assert!(result.contains("2 files"));
    }

    #[test]
    fn test_query_declarations_resolves_location() {
        let result = query_declarations(&test_report(), Some("close"), 50);
        assert!(result.contains("Close"));
        assert!(result.contains("(*Gorm)"));
        assert!(result.contains("db.go:74"));
    }

    #[test]
    fn test_query_usages_resolves_location_and_enclosing() {
        let result = query_usages(&test_report(), Some("getenv"), 50);
        assert!(result.contains("os.Getenv"));
        assert!(result.contains("main.go:6"));
        assert!(result.contains("in: main"));
    }

    #[test]
    fn test_query_imports_location() {
        let result = query_imports(&test_report(), Some("exec"), 50);
        assert!(result.contains("os/exec"));
        assert!(result.contains("[stdlib]"));
        assert!(result.contains("main.go:4"));
    }

    #[test]
    fn test_query_security_signals_location() {
        let result = query_security_signals(&test_report(), None, 50);
        assert!(result.contains("http-client"));
        assert!(result.contains("net/http.Get"));
        assert!(result.contains("mw.go:14"));
    }

    #[test]
    fn test_query_callgraph_node_and_edge_locations() {
        let result = query_callgraph(&test_report(), Some("main"), 50);
        assert!(result.contains("main.go:5"));
        assert!(result.contains("static: main → runCmd at main.go:8"));
    }

    #[test]
    fn test_query_dataflow_prefers_slices() {
        // When materialized slices are present they win over summaries: the formatter
        // surfaces the named source→sink path, the rule, severity, and decoded positions.
        let result = query_dataflow(&test_report(), None, 50);
        assert!(result.contains("Taint slices"));
        assert!(result.contains("[critical][conf=high]"));
        assert!(result.contains("User input reaches process execution"));
        assert!(result.contains("myapp.handler (req) at /app/handler.go:42"));
        assert!(result.contains("myapp.run (Command) at /app/run.go:88"));
        assert!(result.contains("user-input, process-exec"));
    }

    #[test]
    fn test_query_dataflow_falls_back_to_summaries() {
        // Default scans leave `slices` empty; the formatter then uses per-function summaries.
        let mut report = test_report();
        report["dataFlow"]["slices"] = json!([]);
        let result = query_dataflow(&report, None, 50);
        assert!(result.contains("myapp/mapper.Map"));
        assert!(result.contains("param[0] → unsafe"));
    }

    #[test]
    fn test_query_dataflow_falls_back_to_nodes() {
        let mut report = test_report();
        report["dataFlow"]["slices"] = json!([]);
        report["dataFlow"]["summaries"] = json!([]);
        let result = query_dataflow(&report, None, 50);
        assert!(result.contains("exec.Command"));
        assert!(result.contains("process-exec"));
    }

    #[test]
    fn test_query_source_sink_categories() {
        assert!(query_source_sink_categories(&test_report(), "sources").contains("parameter"));
        assert!(query_source_sink_categories(&test_report(), "sinks").contains("process-exec"));
    }

    #[test]
    fn test_query_endpoints() {
        let result = query_endpoints(&test_report(), None);
        assert!(result.contains("GET /connect/token → token"));
        assert!(result.contains("oauth2.go:112"));
    }

    #[test]
    fn test_query_crypto() {
        let result = query_crypto(&test_report(), None);
        assert!(result.contains("x-crypto"));
        assert!(result.contains("bcrypt"));
        assert!(result.contains("password.go:3"));
        assert!(result.contains("GOLEM-CRYPTO-LITERAL-MATERIAL"));
    }

    #[test]
    fn test_detail_declaration() {
        let result = detail_declaration(&test_report(), "Close");
        assert!(result.contains("Declaration: Close"));
        assert!(result.contains("db.go:74"));
        assert!(result.contains("Receiver: *Gorm"));
    }

    #[test]
    fn test_empty_report_returns_helpful_message() {
        let empty = json!({});
        assert!(query_packages(&empty, None).contains("No package data"));
        assert!(query_dataflow(&empty, None, 50).contains("No data-flow data"));
        assert!(query_crypto(&empty, None).contains("No crypto evidence"));
        assert!(query_endpoints(&empty, None).contains("No API endpoint data"));
    }
}
