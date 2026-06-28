use serde_json::Value;

pub fn extract_summary(report: &Value) -> String {
    let tool_name = report["tool"]["name"].as_str().unwrap_or("rusi");
    let tool_ver = report["tool"]["version"].as_str().unwrap_or("?");
    let stats = &report["stats"];

    let packages = stats["package_count"].as_i64().unwrap_or(0);
    let files = stats["file_count"].as_i64().unwrap_or(0);
    let imports = stats["import_count"].as_i64().unwrap_or(0);
    let declarations = stats["declaration_count"].as_i64().unwrap_or(0);
    let usages = stats["usage_count"].as_i64().unwrap_or(0);
    let security = stats["security_signal_count"].as_i64().unwrap_or(0);
    let cg_nodes = stats["call_graph_node_count"].as_i64().unwrap_or(0);
    let cg_edges = stats["call_graph_edge_count"].as_i64().unwrap_or(0);
    let df_nodes = stats["data_flow_node_count"].as_i64().unwrap_or(0);
    let df_slices = stats["data_flow_slice_count"].as_i64().unwrap_or(0);
    let crypto_libs = stats["crypto_library_count"].as_i64().unwrap_or(0);
    let crypto_comps = stats["crypto_component_count"].as_i64().unwrap_or(0);
    let endpoints = stats["api_endpoint_count"].as_i64().unwrap_or(0);

    format!(
        "Analysis tool: {tool_name} v{tool_ver}\n\
         Packages: {packages} | Files: {files} | Imports: {imports}\n\
         Declarations: {declarations} | Usages (calls): {usages} | Security signals: {security}\n\
         Call graph: {cg_nodes} nodes, {cg_edges} edges\n\
         Data flow: {df_nodes} nodes, {df_slices} slices\n\
         Crypto libraries: {crypto_libs} | Crypto components: {crypto_comps}\n\
         API endpoints: {endpoints}"
    )
}

pub fn query_packages(report: &Value, pattern: Option<&str>) -> String {
    let packages = match report["packages"].as_array() {
        Some(arr) => arr,
        None => return "No package data available.".to_string(),
    };

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# Packages ({} total)", packages.len()));

    for pkg in packages {
        let name = pkg["name"].as_str().unwrap_or("?");
        let version = pkg["version"].as_str().unwrap_or("?");
        let purl = pkg["purl"].as_str().unwrap_or("");
        let files_count = pkg["files"].as_array().map(|f| f.len()).unwrap_or(0);

        if let Some(pat) = pattern {
            let pat_lower = pat.to_lowercase();
            if !name.to_lowercase().contains(&pat_lower) && !purl.to_lowercase().contains(&pat_lower)
            {
                continue;
            }
        }

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
    lines.push(format!("# Files ({} total)", files.len()));

    for file in files {
        let path = file["path"].as_str().unwrap_or("?");
        let package = file["package_name"].as_str().unwrap_or("?");

        if let Some(pat) = pattern {
            let pat_lower = pat.to_lowercase();
            if !path.to_lowercase().contains(&pat_lower) && !package.to_lowercase().contains(&pat_lower)
            {
                continue;
            }
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
                || d["qualified_name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                || d["file_path"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
        });
    }

    let show = matched.iter().take(limit);
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "# Declarations ({} matched, showing first {})",
        matched.len(),
        show.len()
    ));

    for d in show {
        let name = d["name"].as_str().unwrap_or("?");
        let kind = d["kind"].as_str().unwrap_or("?");
        let qname = d["qualified_name"].as_str().unwrap_or("");
        let file = d["file_path"].as_str().unwrap_or("?");
        let line = d["position"]["line"].as_i64().unwrap_or(0);
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
    lines.push(format!(
        "# Usages/Calls ({} matched, showing first {})",
        matched.len(),
        show.len()
    ));

    for u in show {
        let name = u["name"].as_str().unwrap_or("?");
        let kind = u["kind"].as_str().unwrap_or("?");
        let file = u["position"]["filename"].as_str().unwrap_or("?");
        let line = u["position"]["line"].as_i64().unwrap_or(0);
        let enclosing = u["enclosing_declaration"].as_str().unwrap_or("");

        lines.push(format!("  [{kind}] {name} at {file}:{line}"));
        if !enclosing.is_empty() {
            lines.push(format!("         in: {enclosing}"));
        }
    }

    lines.join("\n")
}

pub fn query_security_signals(report: &Value, category_filter: Option<&str>, limit: usize) -> String {
    let signals = match report["security_signals"].as_array() {
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
    lines.push(format!(
        "# Security Signals ({} matched, showing first {})",
        matched.len(),
        show.len()
    ));

    for s in show {
        let category = s["category"].as_str().unwrap_or("?");
        let severity = s["severity"].as_str().unwrap_or("?");
        let confidence = s["confidence"].as_str().unwrap_or("?");
        let desc = s["description"].as_str().unwrap_or("?");
        let file = s["file_path"].as_str().unwrap_or("?");
        let line = s["position"]["line"].as_i64().unwrap_or(0);

        lines.push(format!("  [{severity}][{confidence}] {category} — {desc}"));
        lines.push(format!("         {file}:{line}"));
    }

    lines.join("\n")
}

pub fn query_callgraph(report: &Value, pattern: Option<&str>, limit: usize) -> String {
    let cg = match report["call_graph"].as_object() {
        Some(cg) => cg,
        None => return "No call graph data available (not enabled in analysis).".to_string(),
    };

    let mode = cg["mode"].as_str().unwrap_or("?");
    let nodes = cg["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
    let edges = cg["edges"].as_array().map(|a| a.len()).unwrap_or(0);

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("# Call Graph (mode: {mode}, {nodes} nodes, {edges} edges)"));

    if let Some(pat) = pattern {
        let pat_lower = pat.to_lowercase();
        // Show matching nodes
        if let Some(node_list) = cg["nodes"].as_array() {
            let matched: Vec<&Value> = node_list
                .iter()
                .filter(|n| {
                    n["name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || n["qualified_name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || n["file_path"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                })
                .take(limit)
                .collect();

            lines.push(format!("  Matching nodes (showing {}):", matched.len()));
            for n in matched {
                let name = n["name"].as_str().unwrap_or("?");
                let kind = n["kind"].as_str().unwrap_or("?");
                let file = n["file_path"].as_str().unwrap_or("?");
                let line = n["position"]["line"].as_i64().unwrap_or(0);
                let local = n["local"].as_bool().unwrap_or(false);
                let ext = n["external"].as_bool().unwrap_or(false);
                let loc = if local { "local" } else if ext { "external" } else { "?" };
                lines.push(format!("    [{kind}][{loc}] {name} at {file}:{line}"));
            }
        }

        // Show matching edges
        if let Some(edge_list) = cg["edges"].as_array() {
            let matched: Vec<&Value> = edge_list
                .iter()
                .filter(|e| {
                    e["source_name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || e["target_name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                })
                .take(limit)
                .collect();

            lines.push(format!("  Matching edges (showing {}):", matched.len()));
            for e in matched {
                let src = e["source_name"].as_str().unwrap_or("?");
                let tgt = e["target_name"].as_str().unwrap_or("?");
                let call_type = e["call_type"].as_str().unwrap_or("?");
                let file = e["position"]["filename"].as_str().unwrap_or("?");
                let line = e["position"]["line"].as_i64().unwrap_or(0);
                lines.push(format!("    {call_type}: {src} → {tgt} at {file}:{line}"));
            }
        }
    }

    lines.join("\n")
}

pub fn query_dataflow(report: &Value, pattern: Option<&str>, limit: usize) -> String {
    let df = match report["data_flow"].as_object() {
        Some(df) => df,
        None => return "No data-flow data available (not enabled in analysis).".to_string(),
    };

    let mode = df["mode"].as_str().unwrap_or("?");
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
                    s["source_name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || s["sink_name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || s["rule_name"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                        || s["description"].as_str().unwrap_or("").to_lowercase().contains(&pat_lower)
                })
                .take(limit)
                .collect()
        } else {
            slice_list.iter().take(limit).collect()
        };

        lines.push(format!("  Slices (showing {} of {}):", matched.len(), slices));
        for s in matched {
            let src_name = s["source_name"].as_str().unwrap_or("?");
            let sink_name = s["sink_name"].as_str().unwrap_or("?");
            let src_cat = s["source_category"].as_str().unwrap_or("");
            let sink_cat = s["sink_category"].as_str().unwrap_or("");
            let rule = s["rule_name"].as_str().unwrap_or("?");
            let path_len = s["path_length"].as_i64().unwrap_or(0);

            lines.push(format!(
                "    [{rule}] {src_name} ({src_cat}) → {sink_name} ({sink_cat}) — {path_len} steps"
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
    lines.push(format!(
        "# Imports ({} matched, showing first {})",
        matched.len(),
        show.len()
    ));

    for i in show {
        let path = i["path"].as_str().unwrap_or("?");
        let alias = i["alias"].as_str().filter(|a| !a.is_empty());
        let file = i["position"]["filename"].as_str().unwrap_or("?");
        let line = i["position"]["line"].as_i64().unwrap_or(0);

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
            let path = lib["path"].as_str().unwrap_or("?");
            let family = lib["family"].as_str().unwrap_or("?");
            let file = lib["file_path"].as_str().unwrap_or("?");
            if let Some(pat) = pattern {
                let lower = pat.to_lowercase();
                if !path.to_lowercase().contains(&lower) && !family.to_lowercase().contains(&lower) {
                    continue;
                }
            }
            lines.push(format!("  [{family}] {path} — {file}"));
        }
    }

    // Components
    if let Some(comps) = crypto["components"].as_array() {
        lines.push(format!("# Crypto Components ({})", comps.len()));
        for comp in comps {
            let kind = comp["kind"].as_str().unwrap_or("?");
            let algorithm = comp["algorithm"].as_str().unwrap_or("?");
            let provider = comp["provider"].as_str().unwrap_or("?");
            let operation = comp["operation"].as_str().unwrap_or("?");
            let file = comp["file_path"].as_str().unwrap_or("?");
            if let Some(pat) = pattern {
                let lower = pat.to_lowercase();
                if !algorithm.to_lowercase().contains(&lower)
                    && !provider.to_lowercase().contains(&lower)
                    && !kind.to_lowercase().contains(&lower)
                {
                    continue;
                }
            }
            lines.push(format!("  [{kind}] {algorithm} ({provider}) — {operation} at {file}"));
        }
    }

    // Materials
    if let Some(mats) = crypto["materials"].as_array() {
        lines.push(format!("# Crypto Materials ({})", mats.len()));
        for mat in mats {
            let kind = mat["kind"].as_str().unwrap_or("?");
            let name = mat["name"].as_str().unwrap_or("?");
            let file = mat["file_path"].as_str().unwrap_or("?");
            if let Some(pat) = pattern {
                let lower = pat.to_lowercase();
                if !name.to_lowercase().contains(&lower) && !kind.to_lowercase().contains(&lower) {
                    continue;
                }
            }
            lines.push(format!("  [{kind}] {name} — {file}"));
        }
    }

    // Findings
    if let Some(finds) = crypto["findings"].as_array() {
        lines.push(format!("# Crypto Findings ({})", finds.len()));
        for f in finds {
            let category = f["category"].as_str().unwrap_or("?");
            let severity = f["severity"].as_str().unwrap_or("?");
            let summary = f["summary"].as_str().unwrap_or("?");
            let file = f["file_path"].as_str().unwrap_or("?");
            if let Some(pat) = pattern {
                let lower = pat.to_lowercase();
                if !summary.to_lowercase().contains(&lower) && !category.to_lowercase().contains(&lower)
                {
                    continue;
                }
            }
            lines.push(format!("  [{severity}] {category} — {summary} at {file}"));
        }
    }

    if lines.is_empty() {
        return "No crypto evidence available.".to_string();
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
                || d["qualified_name"].as_str().unwrap_or("").to_lowercase() == name_lower
                || d["qualified_name"].as_str().unwrap_or("").to_lowercase().contains(&name_lower)
        })
        .collect();

    if matches.is_empty() {
        return format!("No declaration matching '{name}' found.");
    }

    let mut lines: Vec<String> = Vec::new();
    for d in matches {
        let qname = d["qualified_name"].as_str().unwrap_or("?");
        let kind = d["kind"].as_str().unwrap_or("?");
        let file = d["file_path"].as_str().unwrap_or("?");
        let line = d["position"]["line"].as_i64().unwrap_or(0);
        let sig = d["signature"].as_str().unwrap_or("");
        let package = d["package_path"].as_str().unwrap_or("");
        let purl = d["purl"].as_str().unwrap_or("");
        let canonical = d["canonical_name"].as_str().unwrap_or("");

        lines.push(format!("# Declaration: {qname}"));
        lines.push(format!("  Kind: {kind}"));
        lines.push(format!("  Location: {file}:{line}"));
        lines.push(format!("  Package: {package}"));
        lines.push(format!("  PURL: {purl}"));
        lines.push(format!("  Canonical: {canonical}"));
        if !sig.is_empty() {
            lines.push(format!("  Signature:\n    {sig}"));
        }

        // Find callers/callees from call graph
        if let Some(cg) = report["call_graph"].as_object() {
            // Edges where this node is the source
            if let Some(edges) = cg["edges"].as_array() {
                let outgoing: Vec<&Value> = edges
                    .iter()
                    .filter(|e| {
                        e["source_name"].as_str().unwrap_or("").to_lowercase() == name_lower
                            || e["source_id"].as_str().unwrap_or("").to_lowercase() == name_lower
                    })
                    .collect();
                if !outgoing.is_empty() {
                    lines.push(format!("  Calls ({}):", outgoing.len()));
                    for e in outgoing.iter().take(10) {
                        let tgt = e["target_name"].as_str().unwrap_or("?");
                        let call_type = e["call_type"].as_str().unwrap_or("?");
                        lines.push(format!("    → {tgt} ({call_type})"));
                    }
                }

                let incoming: Vec<&Value> = edges
                    .iter()
                    .filter(|e| {
                        e["target_name"].as_str().unwrap_or("").to_lowercase() == name_lower
                            || e["target_id"].as_str().unwrap_or("").to_lowercase() == name_lower
                    })
                    .collect();
                if !incoming.is_empty() {
                    lines.push(format!("  Called by ({}):", incoming.len()));
                    for e in incoming.iter().take(10) {
                        let src = e["source_name"].as_str().unwrap_or("?");
                        let call_type = e["call_type"].as_str().unwrap_or("?");
                        lines.push(format!("    ← {src} ({call_type})"));
                    }
                }
            }
        }
    }

    lines.join("\n")
}

/// List HTTP API endpoints discovered by rusi's api-discovery pass.
///
/// rusi resolves endpoints for axum, actix-web, and rocket and composes nested
/// route prefixes into the fully-qualified path. Each `ApiEndpoint` carries
/// `method`, `path`, `framework`, `handler`, `file_path`, and `position`. The
/// array is empty for workspaces that import no supported web framework.
pub fn query_endpoints(report: &Value, pattern: Option<&str>) -> String {
    let endpoints = match report["api_endpoints"].as_array() {
        Some(arr) => arr,
        None => return "No API endpoint data available.".to_string(),
    };

    let matched: Vec<&Value> = endpoints
        .iter()
        .filter(|ep| {
            let path = ep["path"].as_str().unwrap_or("");
            let handler = ep["handler"].as_str().unwrap_or("");
            let framework = ep["framework"].as_str().unwrap_or("");
            match pattern {
                Some(pat) => {
                    let p = pat.to_lowercase();
                    path.to_lowercase().contains(&p)
                        || handler.to_lowercase().contains(&p)
                        || framework.to_lowercase().contains(&p)
                }
                None => true,
            }
        })
        .collect();

    let mut lines: Vec<String> =
        vec![format!("# API Endpoints ({} total, showing {})", endpoints.len(), matched.len())];

    for ep in matched {
        let method = ep["method"].as_str().unwrap_or("?");
        let path = ep["path"].as_str().unwrap_or("?");
        let handler = ep["handler"].as_str().unwrap_or("?");
        let framework = ep["framework"].as_str().unwrap_or("?");
        let file = ep["file_path"].as_str().unwrap_or("?");
        let line = ep["position"]["line"].as_i64().unwrap_or(0);
        lines.push(format!("  {method} {path} → {handler} ({framework}) at {file}:{line}"));
    }

    lines.join("\n")
}
