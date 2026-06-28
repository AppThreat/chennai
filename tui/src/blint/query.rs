//! Blint (binary analysis) query functions.
//!
//! Blint output is not source-code taint analysis. Instead, it provides:
//! - **Metadata**: binary header, architecture, functions, symbols, imports/exports,
//!   build info, dependencies, strings, security properties, sections
//! - **Findings**: binary hardening issues (PIE, NX, RELRO, canary, CFG, etc.)
//! - **Reviews**: capability analysis with evidence symbols and descriptions
//! - **Fuzzables**: potential fuzzable entry points
//! - **SBOM**: CycloneDX with dependency data and `internal:behaviours` (Android Dalvik)
//!
//! Every result from these queries is *static evidence* — symbol presence, capability
//! surface, or structural metadata. It does **not** prove runtime execution.
//!
//! # Schema normalization
//! Blint's JSON output is flat — no nested `header` key.  Different binary types
//! (ELF/PE/MachO, WASM, DEX) produce different top-level keys.  This module
//! normalises across all variants:
//!
//! | Concept | Native ELF/PE | DEX/APK | WASM |
//! |---------|--------------|---------|------|
//! | binary type | `binary_type` | `exe_type: "dexbinary"` | `binary_type: "WASM"` |
//! | architecture | `machine_type` | `machine_type` | `machine_type` |
//! | symbols | `dynamic_symbols` + `symtab_symbols` | — | `dynamic_symbols` + `symtab_symbols` |
//! | strings | `strings` / `informative_strings` | `informative_strings` | `strings` / `informative_strings` |
//! | security | `security_properties` | — | — |
//! | callgraph | `callgraph {nodes,edges,external}` | `callgraph {nodes,edges}` | `callgraph` |
//! | imports | `dynamic_entries` / `imports` | — | `imports` / `dynamic_entries` |
//! | exports | `exports` / `symtab_symbols` | — | `exports` |
//! | reviews wrapper | `reviews` array (not `capabilities`) | same | same |

use crate::shared::{field_str, pattern_match, ListHeader};
use serde_json::Value;

/// Collect all symbols from `dynamic_symbols` and `symtab_symbols` (whichever exists).
fn collect_symbols(metadata: &Value) -> Vec<&Value> {
    let mut symbols: Vec<&Value> = Vec::new();
    if let Some(dyn_syms) = metadata["dynamic_symbols"].as_array() {
        symbols.extend(dyn_syms.iter());
    }
    if let Some(sym_syms) = metadata["symtab_symbols"].as_array() {
        symbols.extend(sym_syms.iter());
    }
    symbols
}

/// Collect strings from either `strings` (list of objects with `value`) or
/// `informative_strings` (list of strings or list of objects with `value`/`category`).
fn collect_strings(metadata: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    if let Some(arr) = metadata["strings"].as_array() {
        for item in arr {
            let value = item["value"].as_str().unwrap_or("");
            let category = item["category"].as_str().unwrap_or("string");
            if !value.is_empty() {
                out.push((value.to_string(), category.to_string()));
            }
        }
    }
    if let Some(arr) = metadata["informative_strings"].as_array() {
        for item in arr {
            match item {
                Value::String(s) => {
                    if !s.is_empty() {
                        out.push((s.clone(), "informative".to_string()));
                    }
                }
                Value::Object(_) => {
                    let value = item["value"].as_str().unwrap_or("");
                    let category = item["category"].as_str().unwrap_or("informative");
                    if !value.is_empty() {
                        out.push((value.to_string(), category.to_string()));
                    }
                }
                _ => {}
            }
        }
    }
    out
}
/// Extract the binary type string from flat metadata, trying multiple keys.
#[allow(dead_code)]
fn binary_type(metadata: &Value) -> String {
    let bt = field_str(metadata, "binary_type");
    if bt != "?" { return bt.to_string(); }
    let et = field_str(metadata, "exe_type");
    if et != "?" { return et.to_string(); }
    if metadata["callgraph"].is_object() { "binary".to_string() } else { "?".to_string() }
}

/// Extract the architecture string from flat metadata.
fn architecture(metadata: &Value) -> String {
    let mt = field_str(metadata, "machine_type");
    if mt != "?" { return mt.to_string(); }
    field_str(metadata, "cpu_type").to_string()
}

/// Render a summary from the loaded blint reports.
pub fn extract_summary(
    metadata: &Value,
    findings: &Option<Value>,
    reviews: &Option<Value>,
    sbom: Option<&Value>,
) -> String {
    let btype = field_str(metadata, "binary_type");
    let arch = architecture(metadata);
    let file_type = field_str(metadata, "file_type");
    let exe_type = field_str(metadata, "exe_type");

    let funcs = metadata["functions"].as_array().map(|a| a.len()).unwrap_or(0);
    let imp_count = metadata["imports"].as_array().map(|a| a.len()).unwrap_or(0);
    let exp_count = metadata["exports"].as_array().map(|a| a.len()).unwrap_or(0);
    let syms = collect_symbols(metadata);
    let dyn_entries = metadata["dynamic_entries"].as_array().map(|a| a.len()).unwrap_or(0);
    let strings_count = collect_strings(metadata).len();
    let callgraph_nodes = metadata["callgraph"]["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
    let callgraph_edges = metadata["callgraph"]["edges"].as_array().map(|a| a.len()).unwrap_or(0);

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "Analysis tool: blint\n\
         Binary type: {btype} | exe_type: {exe_type} | Architecture: {arch} | File type: {file_type}\n\
         Functions: {funcs} | Symbols: {syms_len} | Dynamic entries: {dyn_entries} | \
         Imports: {imp_count} | Exports: {exp_count} | Strings: {strings_count}\n\
         Callgraph nodes: {callgraph_nodes} | Callgraph edges: {callgraph_edges}",
        syms_len = syms.len(),
    ));

    if let Some(f) = findings {
        let findings_arr = f["findings"].as_array().map(|a| a.len()).unwrap_or(0);
        lines.push(format!("Security findings: {findings_arr}"));
    }

    if let Some(r) = reviews {
        let caps = r["reviews"].as_array().map(|a| a.len()).unwrap_or(0);
        lines.push(format!("Capability reviews: {caps}"));
    }

    if let Some(s) = sbom {
        let comps = s["components"].as_array().map(|a| a.len()).unwrap_or(0);
        lines.push(format!("SBOM components: {comps}"));
    }

    // Android-specific
    let behaviours = metadata["functions"].as_array().map(|a| {
        a.iter().filter(|f| {
            let name = f["name"].as_str().unwrap_or("");
            name.contains("behaviour") || name.contains("permission")
        }).count()
    }).unwrap_or(0);
    if behaviours > 0 {
        lines.push(format!("Behaviour-related functions: {behaviours}"));
    }

    lines.join("\n")
}

pub fn query_capabilities(reviews: &Option<Value>, pattern: Option<&str>, limit: usize) -> String {
    let caps = match reviews {
        Some(r) => r["reviews"].as_array(),
        None => None,
    };
    let caps = match caps {
        Some(arr) => arr,
        None => return "No capability review data available.".to_string(),
    };

    let mut matched: Vec<&Value> = caps.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|c| {
            c["id"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || c["title"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || c["summary"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Capabilities", total: caps.len(), matched: matched.len(), shown: show.len() }.to_string());

    for c in show {
        let id = field_str(c, "id");
        let title = field_str(c, "title");
        let severity = field_str(c, "severity");
        let summary = field_str(c, "summary");
        let evidence = c["evidence"].as_array().map(|e| {
            e.iter().filter_map(|v| {
                let fn_name = v["function"].as_str();
                let pattern = v["pattern"].as_str();
                match (fn_name, pattern) {
                    (Some(f), Some(p)) => Some(format!("{f} ({p})")),
                    (Some(f), None) => Some(f.to_string()),
                    (None, Some(p)) => Some(p.to_string()),
                    _ => None,
                }
            }).collect::<Vec<_>>().join(", ")
        }).unwrap_or_default();

        lines.push(format!("  [{severity}] {id} — {title}"));
        if !summary.is_empty() && summary != "?" {
            lines.push(format!("         {summary}"));
        }
        if !evidence.is_empty() {
            lines.push(format!("         evidence: {evidence}"));
        }
    }

    lines.join("\n")
}

pub fn query_findings(findings: &Option<Value>, pattern: Option<&str>, limit: usize) -> String {
    let finds = match findings {
        Some(f) => f["findings"].as_array(),
        None => None,
    };
    let finds = match finds {
        Some(arr) => arr,
        None => return "No security finding data available.".to_string(),
    };

    let mut matched: Vec<&Value> = finds.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|f| {
            f["id"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || f["title"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || f["severity"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Findings", total: finds.len(), matched: matched.len(), shown: show.len() }.to_string());

    for f in show {
        let id = field_str(f, "id");
        let title = field_str(f, "title");
        let severity = field_str(f, "severity");
        let desc = field_str(f, "description");

        lines.push(format!("  [{severity}] {id} — {title}"));
        if !desc.is_empty() && desc != "?" {
            // Truncate long descriptions
            let truncated = if desc.len() > 160 { format!("{}...", &desc[..157]) } else { desc.to_string() };
            lines.push(format!("         {truncated}"));
        }
    }

    lines.join("\n")
}

pub fn query_symbols(metadata: &Value, pattern: Option<&str>, limit: usize) -> String {
    let symbols = collect_symbols(metadata);
    if symbols.is_empty() {
        return "No symbol data available.".to_string();
    }

    let mut matched: Vec<&Value> = symbols.into_iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|s| {
            s["name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || s["type"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Symbols", total: matched.len(), matched: matched.len(), shown: show.len() }.to_string());

    for s in show {
        let name = field_str(s, "name");
        let sym_type = field_str(s, "type");
        let binding = field_str(s, "binding");
        let is_imported = s["is_imported"].as_bool().unwrap_or(false);
        let is_exported = s["is_exported"].as_bool().unwrap_or(false);
        let tag = if is_imported { "IMPORT" } else if is_exported { "EXPORT" } else { sym_type };
        let addr = field_str(s, "address");
        lines.push(format!("  [{tag}] {name} @ {addr} ({binding})"));
    }

    lines.join("\n")
}

pub fn query_strings(metadata: &Value, pattern: Option<&str>, limit: usize) -> String {
    let strings = collect_strings(metadata);
    if strings.is_empty() {
        return "No string data available.".to_string();
    }

    let mut matched: Vec<(String, String)> = strings.into_iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|(value, category)| {
            value.to_lowercase().contains(&pat_lower) || category.to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "Strings", total: matched.len(), matched: matched.len(), shown: show.len() }.to_string());

    for (value, category) in show {
        lines.push(format!("  [{category}] {value}"));
    }

    lines.join("\n")
}

pub fn query_components(sbom: &Option<Value>, pattern: Option<&str>, limit: usize) -> String {
    let comps = match sbom {
        Some(s) => s["components"].as_array(),
        None => None,
    };
    let comps = match comps {
        Some(arr) => arr,
        None => return "No SBOM component data available.".to_string(),
    };

    let mut matched: Vec<&Value> = comps.iter().collect();
    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        matched.retain(|c| {
            c["name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || c["purl"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || c["type"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(ListHeader { title: "SBOM Components", total: comps.len(), matched: matched.len(), shown: show.len() }.to_string());

    for c in show {
        let name = field_str(c, "name");
        let version = field_str(c, "version");
        let comp_type = field_str(c, "type");
        let purl = field_str(c, "purl");
        lines.push(format!("  [{comp_type}] {name}@{version} — {purl}"));
    }

    lines.join("\n")
}

pub fn query_behaviours(sbom: &Option<Value>, pattern: Option<&str>, limit: usize) -> String {
    let sbom = match sbom {
        Some(s) => s,
        None => return "No SBOM data available for behaviour analysis.".to_string(),
    };

    let comps = match sbom["components"].as_array() {
        Some(arr) => arr,
        None => return "No components in SBOM.".to_string(),
    };

    let mut matched: Vec<(String, String)> = Vec::new();
    for comp in comps {
        if let Some(props) = comp["properties"].as_array() {
            for prop in props {
                if (prop["name"].as_str() == Some("internal:behaviours")
                    || prop["name"].as_str().is_some_and(|n| n.contains("behaviour")))
                    && let Some(val) = prop["value"].as_str()
                        && pattern_match(val, pattern) {
                            matched.push((
                                field_str(comp, "name").to_string(),
                                val.to_string(),
                            ));
                        }
            }
        }
    }

    if matched.is_empty() {
        return "No behaviour data available.".to_string();
    }

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# Detected Behaviours (showing first {})", limit.min(matched.len())));
    for (comp, behaviour) in matched.iter().take(limit) {
        lines.push(format!("  {comp}: {behaviour}"));
    }

    lines.join("\n")
}

pub fn query_security_properties(metadata: &Value) -> String {
    // Blint uses `security_properties` (snake_case) at the top level.
    // Also check for the inlined `has_nx`, `is_pie`, `relro`, `has_canary` flat fields.
    let props = match metadata["security_properties"].as_object() {
        Some(o) => o,
        None => {
            // Fallback: build from flat fields
            let flat: Vec<(&str, &str)> = vec![
                ("nx", if metadata["has_nx"].as_bool() == Some(true) { "yes" } else if metadata["has_nx"].is_boolean() { "no" } else { "" }),
                ("pie", if metadata["is_pie"].as_bool() == Some(true) { "yes" } else if metadata["is_pie"].is_boolean() { "no" } else { "" }),
                ("relro", metadata["relro"].as_str().unwrap_or("")),
                ("canary", if metadata["has_canary"].as_bool() == Some(true) { "yes" } else if metadata["has_canary"].is_boolean() { "no" } else { "" }),
                ("stripped", if metadata["static"].as_bool() == Some(false) { "yes" } else if metadata["static"].is_boolean() { "no" } else { "" }),
            ];
            let filtered: Vec<(&str, &str)> = flat.into_iter().filter(|(_, v)| !v.is_empty()).collect();
            if filtered.is_empty() {
                return "No security property data available.".to_string();
            }
            let mut lines: Vec<String> = Vec::new();
            lines.push("# Security Properties".to_string());
            for (key, val) in filtered {
                lines.push(format!("  {key}: {val}"));
            }
            return lines.join("\n");
        }
    };

    let mut lines: Vec<String> = Vec::new();
    lines.push("# Security Properties".to_string());
    for (key, val) in props {
        let display = match val {
            Value::Bool(b) => if *b { "yes" } else { "no" }.to_string(),
            Value::String(s) => s.clone(),
            _ => format!("{val}"),
        };
        lines.push(format!("  {key}: {display}"));
    }

    lines.join("\n")
}

/// Normalise a call-graph node id (int or string) to a string key for edge lookup.
fn node_id_key(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Resolve a node id to a human-readable label (`name @ address`, falling back to the id).
fn resolve_node(id_map: &std::collections::HashMap<String, String>, edge_endpoint: &Value) -> String {
    match node_id_key(edge_endpoint) {
        Some(k) => id_map.get(&k).cloned().unwrap_or(k),
        None => "?".to_string(),
    }
}

/// Render a single call graph (`{nodes, edges, external}`), resolving edge node-ids to
/// names. `pattern` filters edges by either endpoint name; returns up to `limit` edges.
fn render_callgraph(label: &str, cg: &Value, pattern: Option<&str>, limit: usize, out: &mut Vec<String>) {
    let nodes = cg["nodes"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let edges = cg["edges"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let external = cg["external"].as_array().map(Vec::as_slice).unwrap_or(&[]);

    // Build id -> "name @ address" so edges read as call relationships, not raw ids.
    let mut id_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for n in nodes {
        if let Some(k) = node_id_key(&n["id"]) {
            let name = n["name"].as_str().filter(|s| !s.is_empty()).unwrap_or("?");
            let label = match n["address"].as_str() {
                Some(a) if !a.is_empty() => format!("{name} @ {a}"),
                _ => name.to_string(),
            };
            id_map.insert(k, label);
        }
    }

    out.push(format!(
        "## {label} ({} nodes, {} edges, {} external)",
        nodes.len(), edges.len(), external.len()
    ));

    let pat_lower = pattern.map(|p| p.to_lowercase());
    let mut shown = 0usize;
    let mut filtered = 0usize;
    for edge in edges {
        let src = resolve_node(&id_map, &edge["src"]);
        let dst = resolve_node(&id_map, &edge["dst"]);
        if let Some(ref pat) = pat_lower
            && !src.to_lowercase().contains(pat) && !dst.to_lowercase().contains(pat)
        {
            continue;
        }
        filtered += 1;
        if shown >= limit {
            continue;
        }
        // Edge kind/confidence (direct/tailcall/indirect_hint) exist on native graphs,
        // not Dalvik; surface them only when present so triage can weight the evidence.
        let mut tags: Vec<String> = Vec::new();
        if let Some(k) = edge["kind"].as_str() { tags.push(k.to_string()); }
        if let Some(c) = edge["confidence"].as_str() { tags.push(c.to_string()); }
        if let Some(cnt) = edge["count"].as_i64().filter(|&c| c > 1) { tags.push(format!("x{cnt}")); }
        let suffix = if tags.is_empty() { String::new() } else { format!("  [{}]", tags.join(", ")) };
        out.push(format!("  {src} → {dst}{suffix}"));
        shown += 1;
    }
    if filtered > shown {
        out.push(format!("  … {} more edges match (raise limit to see them)", filtered - shown));
    }

    // External (unresolved) call targets with their reason bucket — the systemic-miss view.
    if !external.is_empty() && pat_lower.is_none() {
        out.push("  external (unresolved) targets:".to_string());
        for ext in external.iter().take(20) {
            let target = ext["target"].as_str().unwrap_or("?");
            let reason = ext["reason"].as_str().unwrap_or("unresolved");
            let kind = ext["kind"].as_str().map(|k| format!(":{k}")).unwrap_or_default();
            out.push(format!("    → {target} ({reason}{kind})"));
        }
    }
}

/// Query the disassembly-derived call graph. Resolves edge node-ids to function names,
/// surfaces edge kind/confidence (direct/tailcall/indirect_hint), and merges the
/// Android Dalvik / iOS Mach-O sidecar graphs when present. `pattern` filters edges by
/// either endpoint's function name.
pub fn query_callgraph(metadata: &Value, extra: &[(String, Value)], pattern: Option<&str>, limit: usize) -> String {
    let mut lines: Vec<String> = Vec::new();

    // Sidecars are the disassembly graphs for apk/ipa; when present prefer them over the
    // inline metadata["callgraph"] (which, for apk, duplicates the Dalvik sidecar).
    if !extra.is_empty() {
        lines.push(format!("# Call Graphs from {} disassembled binary/binaries", extra.len()));
        for (label, cg) in extra {
            render_callgraph(label, cg, pattern, limit, &mut lines);
        }
        return lines.join("\n");
    }

    match metadata["callgraph"].as_object() {
        Some(_) => {
            lines.push("# Call Graph".to_string());
            render_callgraph("binary", &metadata["callgraph"], pattern, limit, &mut lines);
            lines.join("\n")
        }
        None => "No call graph data available. Re-run blint with --disassemble (and for apk/ipa this also emits per-binary callgraph sidecars).".to_string(),
    }
}

/// Query disassembled functions: per-function instruction metrics and behaviour flags
/// (indirect/system/crypto calls, loops, PAC), the function-type classification, and the
/// resolved direct-call targets. `pattern` matches the function name (case-insensitive).
pub fn query_disassembly(metadata: &Value, pattern: Option<&str>, limit: usize) -> String {
    let Some(funcs) = metadata["disassembled_functions"].as_object() else {
        return "No disassembly data available. Re-run blint with --disassemble (requires the extended install with the nyxstone disassembler).".to_string();
    };
    if funcs.is_empty() {
        return "Disassembly ran but produced no functions (the binary may be encrypted, e.g. FairPlay-protected iOS, or fully stripped).".to_string();
    }

    let pat_lower = pattern.map(|p| p.to_lowercase());
    let mut matched: Vec<(&String, &Value)> = funcs.iter()
        .filter(|(k, v)| {
            let Some(ref pat) = pat_lower else { return true };
            k.to_lowercase().contains(pat)
                || v["name"].as_str().unwrap_or("").to_lowercase().contains(pat)
        })
        .collect();
    // Most-instructions-first puts the substantive functions at the top.
    matched.sort_by_key(|(_, v)| std::cmp::Reverse(v["instruction_count"].as_i64().unwrap_or(0)));

    let total = matched.len();
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# Disassembled functions ({} total, {} shown)", total, total.min(limit)));

    for (_, f) in matched.into_iter().take(limit) {
        let name = f["name"].as_str().unwrap_or("?");
        let addr = f["address"].as_str().unwrap_or("");
        let icount = f["instruction_count"].as_i64().unwrap_or(0);
        let ftype = f["function_type"].as_str().filter(|s| !s.is_empty());

        let mut flags: Vec<&str> = Vec::new();
        for (key, tag) in [
            ("has_indirect_call", "indirect-call"),
            ("has_system_call", "syscall"),
            ("has_crypto_call", "crypto"),
            ("has_gpu_call", "gpu"),
            ("has_loop", "loop"),
            ("has_pac", "pac"),
        ] {
            if f[key].as_bool().unwrap_or(false) { flags.push(tag); }
        }

        let mut header = format!("  {name} @ {addr} ({icount} instr)");
        if let Some(t) = ftype { header.push_str(&format!(" [{t}]")); }
        if !flags.is_empty() { header.push_str(&format!(" {{{}}}", flags.join(", "))); }
        lines.push(header);

        // Resolved direct callees — the per-function edge list, useful even without the
        // top-level callgraph (e.g. when only a few functions were disassembled).
        let callees: Vec<&str> = f["direct_calls"].as_array()
            .map(|a| a.iter().filter_map(|c| c.as_str()).collect())
            .unwrap_or_default();
        if !callees.is_empty() {
            let head: Vec<&str> = callees.iter().take(8).copied().collect();
            let more = callees.len().saturating_sub(head.len());
            let suffix = if more > 0 { format!(", +{more} more") } else { String::new() };
            lines.push(format!("      calls: {}{}", head.join(", "), suffix));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn native_metadata() -> Value {
        json!({
            "binary_type": "ELF",
            "machine_type": "AARCH64",
            "file_type": "DYN",
            "exe_type": "genericbinary",
            "functions": [{"index": 0, "name": "main", "address": "0x1000", "size": 42}],
            "dynamic_symbols": [
                { "name": "puts", "type": "FUNC", "binding": "GLOBAL", "is_imported": true, "is_exported": false, "address": "0x0" },
                { "name": "system", "type": "FUNC", "binding": "GLOBAL", "is_imported": true, "is_exported": false, "address": "0x0" }
            ],
            "dynamic_entries": [
                { "name": "libc.so.6", "tag": "NEEDED" }
            ],
            "strings": [
                { "value": "https://example.com", "category": "url" },
                { "value": "secret_key_12345", "category": "secret" }
            ],
            "security_properties": {
                "nx": true,
                "pie": true,
                "relro": "full",
                "canary": true,
                "stripped": false
            }
        })
    }

    fn dex_metadata() -> Value {
        json!({
            "name": "app.apk",
            "exe_type": "dexbinary",
            "functions": [
                {"name": "Lcom/example/Foo;->bar()V"},
                {"name": "Lcom/example/Foo;->baz()V"}
            ],
            "informative_strings": ["string1", "string2"],
            "callgraph": {
                "nodes": [{"id": 1, "name": "Foo::bar"}],
                "edges": [{"src": 1, "dst": 2, "count": 1}]
            }
        })
    }

    fn wasm_metadata() -> Value {
        json!({
            "binary_type": "WASM",
            "machine_type": "WASM32",
            "exe_type": "wasmbinary",
            "module_version": 1,
            "functions": [{"index": 0, "name": "main", "address": "0x0", "size": 10}],
            "imports": [{"module": "wasi", "name": "fd_write", "kind": "func"}],
            "exports": [{"name": "memory", "kind": "memory"}],
            "dynamic_symbols": [
                {"name": "wasi::fd_write", "is_imported": true, "is_function": true}
            ],
            "symtab_symbols": [
                {"name": "memory", "is_exported": true}
            ],
            "security_properties": {"nx": false, "pie": false, "relro": "no"},
            "callgraph": {"nodes": [{"id": 1, "name": "main"}], "edges": []}
        })
    }

    fn test_findings() -> Value {
        json!({
            "findings": [
                { "id": "CHECK_NX", "title": "NX disabled", "severity": "high", "description": "Stack is executable" },
                { "id": "CHECK_PIE", "title": "No PIE", "severity": "medium", "description": "Position-independent executable not enabled" }
            ]
        })
    }

    fn test_reviews() -> Value {
        json!({
            "reviews": [
                { "id": "ANDROID_DYNAMIC_CODE_LOADING", "title": "Dynamic Code Loading", "severity": "high", "summary": "Can load dex at runtime", "evidence": [{"pattern": "Ldalvik/system/DexClassLoader;", "function": "Lcom/example/load()V"}] },
                { "id": "ANDROID_REFLECTION", "title": "Java Reflection", "severity": "medium", "summary": "Uses reflection", "evidence": [{"pattern": "Ljava/lang/Class;->forName", "function": "Lcom/example/reflect()V"}] }
            ]
        })
    }

    fn test_sbom() -> Value {
        json!({
            "components": [
                {
                    "type": "library",
                    "name": "openssl",
                    "version": "3.0.0",
                    "purl": "pkg:generic/openssl@3.0.0",
                    "properties": [
                        { "name": "internal:behaviours", "value": "crypto,networking" }
                    ]
                }
            ]
        })
    }

    #[test]
    fn test_extract_summary_native() {
        let summary = extract_summary(&native_metadata(), &Some(test_findings()), &Some(test_reviews()), Some(&test_sbom()));
        assert!(summary.contains("ELF"));
        assert!(summary.contains("AARCH64"));
        assert!(summary.contains("Symbols: 2"));
        assert!(summary.contains("Security findings: 2"));
    }

    #[test]
    fn test_extract_summary_dex() {
        let summary = extract_summary(&dex_metadata(), &None, &None, None);
        assert!(summary.contains("dexbinary"));
    }

    #[test]
    fn test_extract_summary_wasm() {
        let summary = extract_summary(&wasm_metadata(), &None, &None, None);
        assert!(summary.contains("WASM"));
        assert!(summary.contains("WASM32"));
        assert!(summary.contains("Symbols: 2"));
    }

    #[test]
    fn test_query_capabilities() {
        let result = query_capabilities(&Some(test_reviews()), Some("dynamic"), 50);
        assert!(result.contains("Dynamic Code Loading"));
        assert!(result.contains("DexClassLoader"));
    }

    #[test]
    fn test_query_findings() {
        let result = query_findings(&Some(test_findings()), Some("NX"), 50);
        assert!(result.contains("NX disabled"));
        assert!(result.contains("[high]"));
    }

    #[test]
    fn test_query_symbols_native() {
        let result = query_symbols(&native_metadata(), Some("system"), 50);
        assert!(result.contains("system"));
        assert!(result.contains("[IMPORT]"));
    }

    #[test]
    fn test_query_symbols_wasm() {
        let result = query_symbols(&wasm_metadata(), Some("fd_write"), 50);
        assert!(result.contains("fd_write"));
    }

    #[test]
    fn test_query_symbols_dex() {
        let result = query_symbols(&dex_metadata(), None, 50);
        assert!(result.contains("No symbol data"));
    }

    #[test]
    fn test_query_strings_native() {
        let result = query_strings(&native_metadata(), Some("https://"), 50);
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_query_strings_dex() {
        let result = query_strings(&dex_metadata(), Some("string"), 50);
        assert!(result.contains("string1"));
    }

    #[test]
    fn test_query_components() {
        let result = query_components(&Some(test_sbom()), Some("openssl"), 50);
        assert!(result.contains("openssl"));
        assert!(result.contains("pkg:generic/openssl@3.0.0"));
    }

    #[test]
    fn test_query_behaviours() {
        let result = query_behaviours(&Some(test_sbom()), Some("crypto"), 50);
        assert!(result.contains("openssl"));
        assert!(result.contains("crypto"));
    }

    #[test]
    fn test_query_security_properties_native() {
        let result = query_security_properties(&native_metadata());
        assert!(result.contains("nx: yes"));
        assert!(result.contains("relro: full"));
    }

    #[test]
    fn test_query_security_properties_wasm() {
        let result = query_security_properties(&wasm_metadata());
        assert!(result.contains("nx: no"));
    }

    #[test]
    fn test_query_security_properties_dex() {
        // DEX has no security_properties
        let result = query_security_properties(&dex_metadata());
        assert!(result.contains("No security property"));
    }

    #[test]
    fn test_query_callgraph_resolves_node_names() {
        // Edge src=1 resolves to node 1's name ("Foo::bar"); dst=2 is unknown -> raw id.
        let result = query_callgraph(&dex_metadata(), &[], None, 50);
        assert!(result.contains("Call Graph"));
        assert!(result.contains("Foo::bar → 2"), "edge ids should resolve to names: {result}");
    }

    #[test]
    fn test_query_callgraph_uses_sidecars_for_apk_ipa() {
        let metadata = json!({});
        let dex = json!({
            "nodes": [
                {"id": "0:0", "name": "La/A;->caller()V", "address": null},
                {"id": "0:1", "name": "Lb/B;->callee()V", "address": null}
            ],
            "edges": [{"src": "0:0", "dst": "0:1"}]
        });
        let extra = vec![("com.example.apk".to_string(), dex)];
        let result = query_callgraph(&metadata, &extra, None, 50);
        assert!(result.contains("com.example.apk"));
        assert!(result.contains("La/A;->caller()V → Lb/B;->callee()V"), "{result}");
    }

    #[test]
    fn test_query_callgraph_pattern_filters_edges() {
        let dex = json!({
            "nodes": [
                {"id": "1", "name": "alpha"}, {"id": "2", "name": "beta"}, {"id": "3", "name": "gamma"}
            ],
            "edges": [{"src": "1", "dst": "2"}, {"src": "2", "dst": "3"}]
        });
        let result = query_callgraph(&json!({}), &[("x".into(), dex)], Some("alpha"), 50);
        assert!(result.contains("alpha → beta"));
        assert!(!result.contains("beta → gamma"));
    }

    #[test]
    fn test_query_disassembly() {
        let metadata = json!({
            "disassembled_functions": {
                "0x1000::doCrypto": {
                    "name": "doCrypto", "address": "0x1000", "instruction_count": 80,
                    "function_type": "Has_Indirect_Calls", "has_indirect_call": true,
                    "has_crypto_call": true, "direct_calls": ["malloc", "AES_encrypt"]
                },
                "0x2000::tiny": {"name": "tiny", "address": "0x2000", "instruction_count": 3}
            }
        });
        let result = query_disassembly(&metadata, None, 50);
        // Most-instructions-first ordering puts doCrypto before tiny.
        assert!(result.find("doCrypto").unwrap() < result.find("tiny").unwrap());
        assert!(result.contains("crypto"));
        assert!(result.contains("indirect-call"));
        assert!(result.contains("calls: malloc, AES_encrypt"));
        // pattern filter
        assert!(!query_disassembly(&metadata, Some("crypto"), 50).contains("tiny"));
        // missing data
        assert!(query_disassembly(&json!({}), None, 50).contains("No disassembly data"));
    }

    #[test]
    fn test_empty_reports() {
        let empty = json!({});
        assert!(query_capabilities(&None, None, 50).contains("No capability review"));
        assert!(query_symbols(&empty, None, 50).contains("No symbol data"));
        assert!(query_strings(&empty, None, 50).contains("No string data"));
        assert!(query_components(&None, None, 50).contains("No SBOM component"));
        assert!(query_security_properties(&empty).contains("No security property"));
        assert!(query_callgraph(&empty, &[], None, 50).contains("No call graph data"));
    }
}
