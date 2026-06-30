//! Tool definitions (JSON Schemas) and the dispatch function for executing tools.
//!
//! The LLM sees these schemas and can request tool calls. [`dispatch_tool`] routes each call to
//! either the engine (NDJSON) or a local shell command, enforcing access controls and timeouts.

use serde_json::{json, Value};

/// Return the tool definitions for a given backend (shell + backend-specific).
#[allow(clippy::borrowed_box)]
pub fn backend_tool_definitions(backend: &Box<dyn crate::shared::backend::Backend>) -> Vec<Value> {
    let mut tools = non_atom_tool_definitions();
    tools.append(&mut backend.tool_definitions());
    tools
}

/// Combined toolset for an atom that ALSO has a loaded analysis backend (e.g. an
/// APK/JAR analyzed by both atom and blint). Atom is primary; the backend's own
/// tools are appended. The shared shell/BOM tools (already in `all_tool_definitions`)
/// are filtered out of the backend set so they aren't duplicated.
#[allow(clippy::borrowed_box)]
pub fn atom_plus_backend_tool_definitions(backend: &Box<dyn crate::shared::backend::Backend>) -> Vec<Value> {
    let mut tools = all_tool_definitions();
    let shared = non_atom_tool_definitions();
    let shared_names: std::collections::HashSet<&str> =
        shared.iter().filter_map(|t| t["name"].as_str()).collect();
    for t in backend.tool_definitions() {
        let dup = t["name"].as_str().map(|n| shared_names.contains(n)).unwrap_or(false);
        if !dup {
            tools.push(t);
        }
    }
    tools
}

/// Return the full set of tool definitions sent to the LLM on every turn.
pub fn all_tool_definitions() -> Vec<Value> {
    vec![
        atom_traversal_docs(),
        atom_summary(),
        atom_query(),
        atom_dsl_eval(),
        atom_flows(),
        atom_flows_through(),
        atom_callsites(),
        atom_callgraph(),
        atom_controlflow(),
        atom_detail(),
        atom_algorithms(),
        project_memory(),
        bom_query(),
        ripgrep_tool(),
        read_file_tool(),
        git_diff_tool(),
        git_log_tool(),
        git_show_tool(),
    ]
}

/// Return the set of tool definitions for non-atom analysis modes (e.g., rusi).
/// These exclude atom_* engine tools and include tool-specific tools.
pub fn non_atom_tool_definitions() -> Vec<Value> {
    vec![
        project_memory(),
        bom_query(),
        ripgrep_tool(),
        read_file_tool(),
        git_diff_tool(),
        git_log_tool(),
        git_show_tool(),
    ]
}

/// Return the full set of rusi tool definitions (shell tools + rusi-specific tools).
#[allow(dead_code)]
pub fn rusi_tool_definitions() -> Vec<Value> {
    let mut tools = non_atom_tool_definitions();
    tools.append(&mut crate::rusi::rusi_tool_definitions());
    tools
}

/// Return the full set of golem tool definitions (shell tools + golem-specific tools).
#[allow(dead_code)]
pub fn golem_tool_definitions() -> Vec<Value> {
    let mut tools = non_atom_tool_definitions();
    tools.append(&mut crate::golem::golem_tool_definitions());
    tools
}

/// Return the full set of dosai tool definitions (shell tools + dosai-specific tools).
#[allow(dead_code)]
pub fn dosai_tool_definitions() -> Vec<Value> {
    let mut tools = non_atom_tool_definitions();
    tools.append(&mut crate::dosai::dosai_tool_definitions());
    tools
}

/// Return the full set of blint tool definitions (shell tools + blint-specific tools).
#[allow(dead_code)]
pub fn blint_tool_definitions() -> Vec<Value> {
    let mut tools = non_atom_tool_definitions();
    tools.append(&mut crate::blint::blint_tool_definitions());
    tools
}

// Tool definitions for atom (engine) operations.

fn atom_traversal_docs() -> Value {
    json!({
        "name": "atom_traversal_docs",
        "description": "Look up the chen DSL traversal reference: traversal roots, step methods, and generic operations (filter, where, repeat, collect, path tracking, etc.) with examples. CALL THIS FIRST before writing any non-trivial atom_dsl_eval expression, and whenever an atom_dsl_eval call returns a parser error — it is the fastest way to write a correct query instead of guessing. Cheap, always available, and one lookup typically saves several failed eval attempts. Pass 'all' or omit to see the full index.",
        "input_schema": {
            "type": "object",
            "properties": {
                "root": {
                    "type": "string",
                    "description": "Topic to look up. Traversal roots: 'method', 'call', 'tag', 'file', 'literal', 'annotation', 'imports', 'typeDecl', etc. Generic operations: 'filter', 'where', 'repeat', 'transform', 'combine', 'dedup', 'flow', 'path', etc. Use 'all' to list every available topic."
                }
            },
            "required": []
        }
    })
}

fn atom_summary() -> Value {
    json!({
        "name": "atom_summary",
        "description": "Return a summary of the open atom: language, version, and counts of files, methods, calls, tags, etc. Call this once at the start of a session to understand the codebase under analysis.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    })
}

fn atom_query() -> Value {
    json!({
        "name": "atom_query",
        "description": "Query flat tables from the atom: files, methods, calls, tags, imports, literals, config files, namespaces, annotations, overlays. Results are paged; use offset to paginate.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "description": "The kind of entity to list: files, methods, externalMethods, internalMethods, calls, namespaces, annotations, imports, literals, configFiles, overlays, tags",
                    "enum": ["files", "methods", "externalMethods", "internalMethods", "calls", "namespaces", "annotations", "imports", "literals", "configFiles", "overlays", "tags"]
                },
                "pattern": {
                    "type": "string",
                    "description": "Optional tag name regex pattern (only used when kind is 'tags'). Example: 'framework.*', 'crypto.*'"
                },
                "offset": {
                    "type": "integer",
                    "description": "Row offset for pagination (default: 0)",
                    "default": 0
                },
                "limit": {
                    "type": "integer",
                    "description": "Max rows to return (default: 100, max: 5000)",
                    "default": 100,
                    "maximum": 5000
                }
            },
            "required": ["kind"]
        }
    })
}

fn atom_dsl_eval() -> Value {
    json!({
        "name": "atom_dsl_eval",
        "description": "Evaluate an arbitrary chen DSL expression against the open atom. The DSL is based on the Joern/semanticcpg query language. Common patterns:\n  - atom.method.name('foo').caller.toJson\n  - atom.call.name('exec').toJson\n  - atom.tag.name('framework-input').call.toJson\n  - atom.method.name('.*auth.*').callee.toJson\n  - atom.literal.code('.*password.*').toJson\n  - atom.method.isExternal.toJson\n  - atom.imports.toJson\nThe expression must be valid chen DSL. The result is a JSON table with columns and rows.",
        "input_schema": {
            "type": "object",
            "properties": {
                "expr": {
                    "type": "string",
                    "description": "A chen DSL expression (e.g., 'atom.method.name(\"main\").caller.toJson'). The engine auto-appends .toJson if omitted."
                }
            },
            "required": ["expr"]
        }
    })
}

fn atom_flows() -> Value {
    json!({
        "name": "atom_flows",
        "description": "Compute data flows (source-to-sink paths) in the atom. THIS IS THE PRIMARY TOOL for any question about reachability, taint, 'can untrusted input reach X', injection, or whether a sink is exploitable — ripgrep CANNOT answer these, only atom_flows can prove an end-to-end path. Reach for it whenever the user asks about vulnerabilities, exploitability, or how data moves through the app. Each flow is an ordered list of steps (source -> propagation -> ... -> sink).\n\nThe 'dataflows' and 'reachables' presets are PAGINATED and BOUNDED, so they are safe to run on large codebases: path enumeration stops at the 'take' budget (default 100) and you page the result with 'offset'/'limit'. The highest-value flows — untrusted framework/CLI input reaching SQL, command-execution, file-io, and deserialization sinks — are returned FIRST, so the first page is the most useful. The result reports 'capped' (the take budget was hit, so more flows likely exist — raise 'take') and 'nextOffset' (pass it back as 'offset' for the next page). Start with the default 'reachables' or 'dataflows' preset; raise 'take' or scope with 'sourceTags'/'sinkTags' to dig deeper.\n\nFor a SPECIFIC source→sink question, scope precisely with a targeted 'expr' (or 'source'+'sink'). The engine resolves flows with `(sink).reachableByFlows(source)`. Scope both ends to tags (`atom.tag.name(\"<tag>\")`) plus a node kind (`.call`, `.parameter`, `.identifier`, `.literal`). Cheat sheet of targeted between-tags queries (pass as 'expr'):\n  // untrusted framework input -> SQL sink\n  atom.tag.name(\"sql\").call.reachableByFlows(atom.tag.name(\"framework-input\").parameter, atom.tag.name(\"framework-input\").identifier, atom.tag.name(\"framework-input\").call)\n  // any tagged source -> command-execution sink (call args too)\n  atom.tag.name(\"exec\").call.argument.isIdentifier.reachableByFlows(atom.tag.name(\"cli-source\").parameter)\n  // sensitive/PII data -> network/tracker egress (JVM/Android)\n  atom.tag.name(\"(service-egress|tracker)\").call.reachableByFlows(atom.tag.name(\"(sensitive-data|pii)\").identifier, atom.tag.name(\"(sensitive-data|pii)\").parameter)\n  // crypto key/IV generation reachable from a weak algorithm literal\n  atom.tag.name(\"crypto-generate\").call.reachableByFlows(atom.tag.name(\"crypto-algorithm\").literal)\nUse atom_query on tags first (`kind:tags`) to discover which source/sink tags actually exist in THIS atom before composing the query. Use a preset ('reachables', 'dataflows', 'cryptos'), provide a scoped DSL 'expr', or specify explicit 'source'+'sink' expressions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "preset": {
                    "type": "string",
                    "description": "One of the built-in flow presets, all paginated/bounded by 'take': 'reachables' (flows attributable to a known package/dependency — start here), 'dataflows' (all default source→sink flows), 'cryptos' (crypto flows). High-value flows are returned first.",
                    "enum": ["dataflows", "reachables", "cryptos"]
                },
                "take": {
                    "type": "integer",
                    "description": "Cap on the number of source-to-sink paths ENUMERATED for a preset (default 100). This is the responsiveness lever on large atoms. If the result is 'capped', raise this to find more flows.",
                    "default": 100
                },
                "offset": {
                    "type": "integer",
                    "description": "Row offset into the computed flows, for pagination (default 0). Pass the result's 'nextOffset' to get the next page without recomputing.",
                    "default": 0
                },
                "limit": {
                    "type": "integer",
                    "description": "Max flows to return in this page (default 50).",
                    "default": 50
                },
                "sourceTags": {
                    "type": "string",
                    "description": "Override the default source tag set for 'dataflows'/'reachables'. A '|'- or ','-delimited list, e.g. 'framework-input,cli-source'. Use atom_query kind:tags to discover available tags."
                },
                "sinkTags": {
                    "type": "string",
                    "description": "Override the default sink tag set for 'dataflows'/'reachables'. A '|'- or ','-delimited list, e.g. 'sql|code-execution|file-io'."
                },
                "expr": {
                    "type": "string",
                    "description": "Arbitrary dataflow DSL expression to evaluate. E.g., '(sink).reachableByFlows(source)' where source and sink are chen DSL traversals."
                },
                "source": {
                    "type": "string",
                    "description": "Source expression for a custom source-to-sink flow query (must be paired with 'sink')."
                },
                "sink": {
                    "type": "string",
                    "description": "Sink expression for a custom source-to-sink flow query (must be paired with 'source')."
                }
            }
        }
    })
}

fn atom_flows_through() -> Value {
    json!({
        "name": "atom_flows_through",
        "description": "Find data flows that pass through (or exclude) specific method calls, files, or code patterns. Returns only flows where at least one step matches the 'passesThrough' pattern and no step matches 'doesNotPassThrough'. Use this whenever you have a suspect method/sink (e.g. from atom_query or ripgrep) and need to confirm it is actually on a tainted path — it turns a name match into proven reachability, and 'doesNotPassThrough' lets you rule out sanitized flows. Prefer this over re-running ripgrep to 'check' a finding.",
        "input_schema": {
            "type": "object",
            "properties": {
                "passesThrough": {
                    "type": "string",
                    "description": "Case-insensitive substring match: only keep flows where at least one step's method name, code snippet, or file path contains this string. Example: 'executeQuery', 'sql'."
                },
                "doesNotPassThrough": {
                    "type": "string",
                    "description": "Case-insensitive substring match: exclude flows where any step's method name, code snippet, or file path contains this string. Use to filter out sanitizer methods. Example: 'escape', 'encode'."
                },
                "preset": {
                    "type": "string",
                    "description": "Optional base preset to narrow the search space before filtering. Bounded by 'take' (default 100); 'reachables' is a good default on large atoms.",
                    "enum": ["dataflows", "reachables", "cryptos"]
                },
                "take": {
                    "type": "integer",
                    "description": "Cap on the number of source-to-sink paths enumerated before filtering (default 100). Raise it if filtering leaves too few flows.",
                    "default": 100
                },
                "offset": {
                    "type": "integer",
                    "description": "Row offset into the filtered flows, for pagination (default 0)."
                },
                "limit": {
                    "type": "integer",
                    "description": "Max flows to return in this page (default 50)."
                }
            }
        }
    })
}

fn atom_callsites() -> Value {
    json!({
        "name": "atom_callsites",
        "description": "Find the CALL SITES of a function/method — every place it is actually INVOKED, not where it is declared. THIS IS THE TOOL TO REACH FOR when you catch yourself wanting 'where is X called'. A plain atom_query/atom_dsl_eval on `atom.method.name(...)` returns the DEFINITION (one node); this returns the call nodes (potentially many, across files) so you can see real usage, count callers, and pick a sink to trace. Works for both app-defined and external/library functions (e.g. os.system, eval, executeQuery) because it matches on the call's callee name and needs no call-graph resolver. Each row is a call site: code, file, line, and resolved methodFullName.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Regex matched against the callee's SHORT name (anchored — wrap partials in .*). Examples: 'system', '(?i).*exec.*', 'executeQuery|query'. This is the common case."
                },
                "fullName": {
                    "type": "string",
                    "description": "Alternative to 'name': regex matched against the call's methodFullName (the fully-qualified target). Use when the short name is ambiguous, e.g. 'java.sql.Statement.execute.*' or '.*os\\.system.*'. If both are given, 'name' wins."
                },
                "limit": {
                    "type": "integer",
                    "description": "Max call sites to return (default 50).",
                    "default": 50
                }
            }
        }
    })
}

fn atom_callgraph() -> Value {
    json!({
        "name": "atom_callgraph",
        "description": "Navigate the CALL GRAPH around a method: its callers (who calls it) or callees (what it calls). Use this for 'what is the blast radius of X', 'who can invoke X', or 'what does X depend on / call into'. The anchor is a method matched by name; results are Method nodes (name, fullName, file, line). The call-graph edges are resolved with NoResolve (fast, no points-to analysis) — this is automatic, you do not write any DSL. For the raw call SITES of a method (Call nodes, not Methods) use atom_callsites instead; for outgoing call sites within the method body use direction 'calls'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Regex matched against the anchor method's name (anchored — wrap partials in .*). Example: 'main', '(?i).*handler.*', 'authenticate'."
                },
                "direction": {
                    "type": "string",
                    "description": "Which edges to follow:\n- 'callers' — methods that CALL the anchor method (incoming). Answers 'who calls X / can reach X'.\n- 'callees' — methods CALLED BY the anchor method (outgoing). Answers 'what does X call'.\n- 'calls' — the outgoing call SITES inside the anchor method's body (Call nodes). Answers 'what calls does X make, with arguments'.",
                    "enum": ["callers", "callees", "calls"]
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results to return (default 50).",
                    "default": 50
                }
            },
            "required": ["name", "direction"]
        }
    })
}

fn atom_controlflow() -> Value {
    json!({
        "name": "atom_controlflow",
        "description": "Inspect intra-procedural CONTROL-FLOW and DOMINANCE relationships around a statement/call. Use this to answer 'is this sink GUARDED by a check', 'what does this condition control', or 'does an auth/validation check always run before this call' — questions about ordering and guarding that data-flow alone does not answer. The anchor is a call matched by its source code (or callee name); results are the related CFG nodes (code, file, line). All relations are computed on the CFG/dominator trees and need no resolver (automatic).",
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Regex matched against the anchor call's source CODE (anchored — wrap partials in .*). Example: '.*strcmp.*', '.*executeQuery.*'. Prefer this for control-flow questions since conditions are usually identified by their code."
                },
                "name": {
                    "type": "string",
                    "description": "Alternative to 'code': regex matched against the anchor call's callee name. If both are given, 'code' wins."
                },
                "relation": {
                    "type": "string",
                    "description": "Which relation to compute from the anchor:\n- 'controls' — nodes whose execution the anchor decides (the anchor is a guard/condition).\n- 'controlledBy' — guard/condition nodes the anchor is control-dependent on (what must be true to reach the anchor; check for missing auth/validation here).\n- 'dominates' / 'dominatedBy' — nodes the anchor must precede / that must precede the anchor on every path.\n- 'postDominates' / 'postDominatedBy' — nodes the anchor must follow / that must follow the anchor on every path.",
                    "enum": ["controls", "controlledBy", "dominates", "dominatedBy", "postDominates", "postDominatedBy"]
                },
                "limit": {
                    "type": "integer",
                    "description": "Max related nodes to return (default 50).",
                    "default": 50
                }
            },
            "required": ["relation"]
        }
    })
}

fn atom_detail() -> Value {
    json!({
        "name": "atom_detail",
        "description": "Retrieve detailed information about a specific node in the atom: properties, children, call tree, and source code. Use this to drill into a method, call, or file returned by atom_query.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "description": "The kind of entity: files, methods, externalMethods, internalMethods, calls",
                    "enum": ["files", "methods", "externalMethods", "internalMethods", "calls"]
                },
                "key": {
                    "type": "string",
                    "description": "The identifier of the entity (file path for files, full name for methods, code for calls)"
                },
                "file": {
                    "type": "string",
                    "description": "Optional file path, required when kind is 'calls'"
                },
                "line": {
                    "type": "integer",
                    "description": "Optional line number, used for calls"
                }
            },
            "required": ["kind", "key"]
        }
    })
}

/// Algorithmic analysis tool: exposes overflowdb2 graph algorithms (pagerank, scc,
/// dominators, toposort, shortest-path, reachable-by) as a callable tool so the LLM
/// can reason about structural properties of the codebase.
fn atom_algorithms() -> Value {
    json!({
        "name": "atom_algorithms",
        "description": "Run graph algorithms on the atom's call graph or dependency graph. Returns a table of results. Reach for this on structural questions that text search cannot answer: 'what are the most important/central methods' (pagerank), 'what is the blast radius / what calls into X' or 'is auth always on the path to this sink' (dominators, shortest-path, reachable-by), recursion/cycles (scc), or build/order analysis (toposort).\n\nAlgorithms:\n- pagerank (scope: callgraph): rank methods by centrality; use to find 'hottest' / most important methods.\n- scc (scope: callgraph): find strongly connected components (recursive call cycles).\n- toposort (scope: callgraph): topological sort of methods; use for build/ordering analysis.\n- dominators (scope: callgraph): compute immediate dominators on the call graph; use to find 'must-pass-through' gates (e.g. is auth a dominator of a sink?).\n- shortest-path: shortest call-chain between two methods; use 'from' (method fullName) and 'to' (method fullName).\n- reachable-by: tag-based reachability via dataflow engine; use 'sourceTag' and 'sinkTag'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Algorithm name: pagerank, scc, dominators, toposort, shortest-path, reachable-by",
                    "enum": ["pagerank", "scc", "dominators", "toposort", "shortest-path", "reachable-by"]
                },
                "scope": {
                    "type": "string",
                    "description": "Graph scope for pagerank/scc/dominators/toposort: 'callgraph' (default) or 'dependency'"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max rows to return (default: 50, max: 500)",
                    "default": 50
                },
                "from": {
                    "type": "string",
                    "description": "Source method fullName for shortest-path"
                },
                "to": {
                    "type": "string",
                    "description": "Target method fullName for shortest-path"
                },
                "sourceTag": {
                    "type": "string",
                    "description": "Source tag pattern for reachable-by (tag-based reachability)"
                },
                "sinkTag": {
                    "type": "string",
                    "description": "Sink tag pattern for reachable-by"
                }
            },
            "required": ["name"]
        }
    })
}

// Tool definitions for shell (local) operations.

fn ripgrep_tool() -> Value {
    json!({
        "name": "ripgrep",
        "description": "FALLBACK text search (regex) over raw source files. Prefer the structured analysis tools first — the atom_* tools (atom mode) or the rusi_*/golem_*/dosai_*/blint_* tools (non-atom mode): they locate calls, methods, and tags structurally, and their flow/dataflow tools prove reachability, whereas a ripgrep match is only a text hit and is weaker evidence. Use ripgrep ONLY when: (1) those tools have been tried and lack the data you need, (2) you need to grep non-code/config/comment text they don't model, or (3) you need a quick literal-string locate before drilling in with a detail tool. Do NOT use ripgrep to 'double-check' a structured-analysis result. Confined to the project source root.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "The regex pattern to search for (rust regex syntax)"
                },
                "glob": {
                    "type": "string",
                    "description": "Optional file glob filter (e.g., '*.py', '*.{js,ts}')"
                },
                "path": {
                    "type": "string",
                    "description": "Optional subdirectory or file path to scope the search to"
                },
                "max_count": {
                    "type": "integer",
                    "description": "Maximum number of matches to return (default: 50)",
                    "default": 50
                }
            },
            "required": ["pattern"]
        }
    })
}

fn read_file_tool() -> Value {
    json!({
        "name": "read_file",
        "description": "Read raw source lines from a file. Use this to pull a short snippet of surrounding context AFTER a structured-analysis tool has located the file:line of interest (e.g. confirming the code around a flow step or a flagged call). Prefer a detail tool (atom_detail, or <backend>_detail) for a node's signature, location, and call-graph neighbors; reach for read_file only when you need adjacent lines those tools don't expose. Path is relative to the project source root; optionally specify start and end line numbers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the file within the source root (e.g., 'src/main.rs', 'lib/utils.js')"
                },
                "start": {
                    "type": "integer",
                    "description": "Optional starting line number (1-indexed, inclusive)"
                },
                "end": {
                    "type": "integer",
                    "description": "Optional ending line number (1-indexed, inclusive)"
                }
            },
            "required": ["path"]
        }
    })
}

fn git_diff_tool() -> Value {
    json!({
        "name": "git_diff",
        "description": "Show uncommitted changes (working tree diff) or changes between revisions in the project's git repository.",
        "input_schema": {
            "type": "object",
            "properties": {
                "rev_range": {
                    "type": "string",
                    "description": "Optional revision range (e.g., 'HEAD~3..HEAD', 'main..feature'). When omitted, shows working tree diff."
                },
                "path": {
                    "type": "string",
                    "description": "Optional file path to scope the diff to"
                }
            }
        }
    })
}

fn git_log_tool() -> Value {
    json!({
        "name": "git_log",
        "description": "Show the git commit log, optionally filtered by revision range and/or file path. Returns commit hashes, authors, dates, and subjects.",
        "input_schema": {
            "type": "object",
            "properties": {
                "rev": {
                    "type": "string",
                    "description": "Optional revision range (default: HEAD~20..HEAD for recent 20 commits)"
                },
                "path": {
                    "type": "string",
                    "description": "Optional file path to filter commits by"
                },
                "max_count": {
                    "type": "integer",
                    "description": "Maximum number of commits to return (default: 20)",
                    "default": 20
                }
            }
        }
    })
}

fn git_show_tool() -> Value {
    json!({
        "name": "git_show",
        "description": "Show the full diff and metadata for a specific git commit or object.",
        "input_schema": {
            "type": "object",
            "properties": {
                "rev": {
                    "type": "string",
                    "description": "The revision/commit to show (e.g., 'abc123', 'HEAD~1')"
                }
            },
            "required": ["rev"]
        }
    })
}

fn bom_query() -> Value {
    json!({
        "name": "bom_query",
        "description": "Query the CycloneDX SBOM (Software Bill of Materials) for project dependencies. Returns components filtered by an optional search term. Use this to identify third-party libraries, their versions, licenses, and PURLs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Optional case-insensitive search term to filter components by name, type, version, PURL, or license. Omit to list all components."
                },
                "type_filter": {
                    "type": "string",
                    "description": "Optional component type filter (e.g., 'library', 'framework', 'container', 'application', 'cryptographic-asset')"
                }
            }
        }
    })
}

/// Tool for persistent per-project memory of durable facts (architecture,
/// entrypoints, auth boundaries, confirmed/refuted findings, user corrections).
/// The index of known facts is injected into the system prompt; this tool is
/// used to read full bodies, search, save new facts, or update existing ones.
fn project_memory() -> Value {
    json!({
        "name": "project_memory",
        "description": "Persistent per-project memory of durable facts (architecture, entrypoints, \
auth boundaries, confirmed/refuted findings, user corrections). The index of known facts is \
ALREADY in your system prompt — call this only to (a) read a full fact body by name \
('recall'), (b) search bodies for a keyword ('search'), or (c) save a NEW durable fact, or \
UPDATE an existing one by reusing its name, that you just learned and verified ('save'). Save \
sparingly and prefer facts grounded in CALLGRAPH or DATAFLOW results (atom_flows / \
atom_algorithms / rusi_flows / golem_dataflow / blint_dataflow) — proven reachability, \
taint paths, entrypoints, auth boundaries. Do NOT save facts grounded only in a ripgrep/text \
match. A recalled fact is a HINT; re-verify it before reporting.",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "The operation to perform: 'recall' (read a fact body), 'search' (keyword search), 'save' (create or update), 'delete' (remove)",
                    "enum": ["recall", "search", "save", "delete"]
                },
                "name": {
                    "type": "string",
                    "description": "Fact slug (required for recall, save, delete)"
                },
                "query": {
                    "type": "string",
                    "description": "Keyword search string (required for search)"
                },
                "description": {
                    "type": "string",
                    "description": "One-line summary of the fact (required for save)"
                },
                "type": {
                    "type": "string",
                    "description": "Fact category: project (structural), finding (confirmed/refuted), reference (external context), feedback (user corrections)",
                    "enum": ["project", "finding", "reference", "feedback"]
                },
                "grounded_by": {
                    "type": "string",
                    "description": "The tool that produced this fact, e.g. atom_flows, golem_dataflow, atom_algorithms, rusi_flows"
                },
                "confidence": {
                    "type": "string",
                    "description": "Confidence level: high, medium, low",
                    "enum": ["high", "medium", "low"]
                },
                "source_refs": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "File:line anchors this fact is grounded in (save)"
                },
                "body": {
                    "type": "string",
                    "description": "The fact text / detailed description (required for save)"
                }
            },
            "required": ["action"]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atom_plus_backend_merges_without_duplicating_shared_tools() {
        let backend: Box<dyn crate::shared::backend::Backend> =
            Box::new(crate::blint::BlintCtx {
                reports: crate::blint::BlintReports {
                    metadata: crate::shared::LoadedReport { report: serde_json::json!({}), report_path: String::new() },
                    findings: None, reviews: None, fuzzables: None, sbom: None,
                    callgraph_path: None, extra_callgraphs: Vec::new(), artifact_type: "apk".into(),
                },
                artifact_path: "app.apk".into(),
            });

        let combined = atom_plus_backend_tool_definitions(&backend);
        let names: Vec<&str> = combined.iter().filter_map(|t| t["name"].as_str()).collect();

        // Atom tools present.
        assert!(names.contains(&"atom_flows"));
        assert!(names.contains(&"atom_dsl_eval"));
        // Call-graph / control-flow convenience tools present.
        assert!(names.contains(&"atom_callsites"));
        assert!(names.contains(&"atom_callgraph"));
        assert!(names.contains(&"atom_controlflow"));
        // Backend-specific tools present.
        assert!(names.contains(&"blint_callgraph"));
        assert!(names.contains(&"blint_disassembly"));
        // Shared tools appear exactly once (not duplicated by the backend set).
        assert_eq!(names.iter().filter(|&&n| n == "ripgrep").count(), 1);
        assert_eq!(names.iter().filter(|&&n| n == "bom_query").count(), 1);
        assert_eq!(names.iter().filter(|&&n| n == "read_file").count(), 1);
    }
}
