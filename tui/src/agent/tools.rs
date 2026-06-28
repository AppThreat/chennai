//! Tool definitions (JSON Schemas) and the dispatch function for executing tools.
//!
//! The LLM sees these schemas and can request tool calls. [`dispatch_tool`] routes each call to
//! either the engine (NDJSON) or a local shell command, enforcing access controls and timeouts.

use serde_json::{json, Value};

/// Return the full set of tool definitions sent to the LLM on every turn.
pub fn all_tool_definitions() -> Vec<Value> {
    vec![
        atom_traversal_docs(),
        atom_summary(),
        atom_query(),
        atom_dsl_eval(),
        atom_flows(),
        atom_flows_through(),
        atom_detail(),
        atom_algorithms(),
        bom_query(),
        ripgrep_tool(),
        read_file_tool(),
        git_diff_tool(),
        git_log_tool(),
        git_show_tool(),
    ]
}

// Tool definitions for atom (engine) operations.

fn atom_traversal_docs() -> Value {
    json!({
        "name": "atom_traversal_docs",
        "description": "Look up the chen DSL traversal reference. Returns traversal roots, step methods, and generic operations (filter, where, repeat, collect, path tracking, etc.) with examples. Use this when you need to know what queries or chain steps are available. Pass 'all' or omit to see the full index.",
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
        "description": "Compute data flows (source-to-sink paths) in the atom. Use a preset ('dataflows', 'reachables', 'cryptos'), provide a DSL expression, or specify explicit source and sink expressions. Each flow is an ordered list of steps (source -> propagation -> ... -> sink).",
        "input_schema": {
            "type": "object",
            "properties": {
                "preset": {
                    "type": "string",
                    "description": "One of the built-in flow presets: 'dataflows' (all flows), 'reachables' (flows attributable to a known package/dependency), 'cryptos' (crypto flows)",
                    "enum": ["dataflows", "reachables", "cryptos"]
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
        "description": "Find data flows that pass through (or exclude) specific method calls, files, or code patterns. Returns only flows where at least one step matches the 'passesThrough' pattern and no step matches 'doesNotPassThrough'. Use this after identifying a potential vulnerability to find all end-to-end paths that go through the suspicious method.",
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
                    "description": "Optional base preset to narrow the search space before filtering. Defaults to 'dataflows'.",
                    "enum": ["dataflows", "reachables", "cryptos"]
                }
            }
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
        "description": "Run graph algorithms on the atom's call graph or dependency graph. Returns a table of results.\n\nAlgorithms:\n- pagerank (scope: callgraph): rank methods by centrality; use to find 'hottest' / most important methods.\n- scc (scope: callgraph): find strongly connected components (recursive call cycles).\n- toposort (scope: callgraph): topological sort of methods; use for build/ordering analysis.\n- dominators (scope: callgraph): compute immediate dominators on the call graph; use to find 'must-pass-through' gates (e.g. is auth a dominator of a sink?).\n- shortest-path: shortest call-chain between two methods; use 'from' (method fullName) and 'to' (method fullName).\n- reachable-by: tag-based reachability via dataflow engine; use 'sourceTag' and 'sinkTag'.",
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
        "description": "Search source code with ripgrep (rg) using a regex pattern. Returns matching file:line matches with surrounding context. Confined to the project source root.",
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
        "description": "Read the contents of a source file from the project. Path is relative to the project source root. Optionally specify start and end line numbers to read a range.",
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
