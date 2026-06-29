//! LLM-powered agent: orchestrates tool-using conversations over code atoms.
//!
//! The agent loop coordinates a provider, tool dispatch, and conversation transcript:
//!
//! 1. Send the conversation transcript (system prompt + tools + messages) to the LLM provider.
//! 2. Stream responses (thinking, text, tool calls) to the UI in real time.
//! 3. If the model requests tool calls, execute them and feed results back.
//! 4. Repeat until the model produces a final answer (end_turn / stop).

pub mod anthropic;
pub mod debug_log;
pub mod openai;
pub mod provider;
pub mod render;
pub mod shell;
pub mod tools;
pub mod memory;
pub mod transcript;
pub use debug_log::DebugLogger;

use crate::config::{Config, ProviderKind};
use crate::engine::Engine;
use crate::shared::backend::Backend;
use provider::{
    AgentEvent, ChannelSink, ContentBlock, EventSink, LlmProvider, ProviderError, TurnRequest,
};
use serde_json::Value;
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use transcript::Transcript;

// Embedded slash-command prompt templates. These are markdown-with-frontmatter files stored
// in `tui/agents/` and compiled into the binary via `include_str!`.
const PROMPT_SECURITY_REVIEW: &str = include_str!("../../agents/security-review.md");
const PROMPT_EXPLAIN: &str = include_str!("../../agents/explain.md");
const PROMPT_TRACE: &str = include_str!("../../agents/trace.md");
const PROMPT_CODE_REVIEW: &str = include_str!("../../agents/code-review.md");

/// Full traversal reference docs, compiled into the binary so the agent can look up
/// any traversal root or step method on demand without bloating the system prompt.
const TRAVERSAL_DOCS: &str = include_str!("../../docs/TRAVERSAL.md");

/// Generic DSL operations reference (filter, where, repeat, collect, path tracking, etc.)
/// that can be chained on any traversal.
const DSL_OPERATIONS: &str = include_str!("../../docs/DSL_OPERATIONS.md");

/// A parsed slash-command template: a prompt body plus an optional toolset
/// allowlist and effort override, sourced from the markdown-with-frontmatter
/// files in `tui/agents/` (or a user override).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SlashCommand {
    /// The prompt body with the YAML frontmatter stripped.
    pub body: String,
    /// Tool-name allowlist (`tools:` frontmatter), or `None` for all tools.
    pub tools: Option<Vec<String>>,
    /// Effort override (`effort:` frontmatter), or `None` to inherit the default.
    pub effort: Option<String>,
}

/// Built-in (compiled-in) prompt text for a known slash command.
fn builtin_prompt(cmd: &str) -> Option<&'static str> {
    match cmd {
        "security-review" | "security_review" => Some(PROMPT_SECURITY_REVIEW),
        "explain" => Some(PROMPT_EXPLAIN),
        "trace" => Some(PROMPT_TRACE),
        "code-review" | "code_review" => Some(PROMPT_CODE_REVIEW),
        _ => None,
    }
}

/// Resolve a slash command to a parsed [`SlashCommand`], preferring a user
/// override at `~/.config/chennai/agents/<cmd>.md` over the built-in. Returns
/// `None` for unknown commands with no override file.
pub fn slash_command(cmd: &str) -> Option<SlashCommand> {
    let raw = user_override_prompt(cmd).or_else(|| builtin_prompt(cmd).map(str::to_string))?;
    Some(parse_frontmatter(&raw))
}

/// Read a user override prompt file if present.
fn user_override_prompt(cmd: &str) -> Option<String> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).ok()?;
    let path = std::path::Path::new(&home)
        .join(".config").join("chennai").join("agents")
        .join(format!("{cmd}.md"));
    std::fs::read_to_string(path).ok()
}

/// Split optional `---`-delimited YAML frontmatter from a markdown prompt using
/// `serde_yaml`. Supports both single-line (`tools: [a, b]`) and multi-line
/// (`tools:\n  - a\n  - b`) YAML lists. Unknown keys are ignored; a malformed or
/// absent header leaves the whole input as the body.
fn parse_frontmatter(raw: &str) -> SlashCommand {
    let trimmed = raw.trim_start_matches('\u{feff}');
    let Some(rest) = trimmed.strip_prefix("---\n").or_else(|| trimmed.strip_prefix("---\r\n")) else {
        return SlashCommand { body: raw.trim().to_string(), tools: None, effort: None };
    };

    // Find the closing `---` delimiter line.
    let closing = rest.find("\n---").or_else(|| rest.find("\r\n---"));
    let Some(end) = closing else {
        return SlashCommand { body: raw.trim().to_string(), tools: None, effort: None };
    };
    let yaml_str = &rest[..end];
    let body_start = end + 4; // skip past "\n---" (or "\r\n---")
    let body = rest[body_start..].trim().to_string();

    // Parse the YAML header with serde_yaml.
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(yaml_str) else {
        return SlashCommand { body, tools: None, effort: None };
    };
    let mapping = match yaml {
        serde_yaml::Value::Mapping(ref m) => m,
        _ => return SlashCommand { body, tools: None, effort: None },
    };

    let tools = mapping.get(serde_yaml::Value::String("tools".into())).and_then(|v| {
        let list: Vec<String> = match v {
            serde_yaml::Value::Sequence(seq) => {
                seq.iter().filter_map(|item| item.as_str().map(|s| s.to_string())).collect()
            }
            serde_yaml::Value::String(s) => {
                // Fallback: parse inline YAML array syntax like "[a, b, c]"
                let inner = s.trim_start_matches('[').trim_end_matches(']');
                inner.split(',').map(|s| s.trim().trim_matches(['"', '\'']).to_string()).filter(|s| !s.is_empty()).collect()
            }
            _ => return None,
        };
        if list.is_empty() { None } else { Some(list) }
    });

    let effort = mapping.get(serde_yaml::Value::String("effort".into())).and_then(|v| {
        v.as_str().map(|s| s.to_string()).filter(|s| !s.is_empty())
    });

    SlashCommand { body, tools, effort }
}

// ---------------------------------------------------------------------------
// Provider factory
// ---------------------------------------------------------------------------

pub fn create_provider(config: &Config) -> Result<Box<dyn LlmProvider + Send + Sync>, ProviderError> {
    let key = config.api_key.as_ref().ok_or_else(|| ProviderError::Config(
        "no API key configured; set ANTHROPIC_API_KEY or OPENAI_API_KEY".into()
    ))?;

    match config.provider {
        ProviderKind::Anthropic => {
            if let Some(base_url) = &config.base_url {
                Ok(Box::new(anthropic::AnthropicProvider::with_base_url(key.clone(), config.model.clone(), base_url.clone())))
            } else {
                Ok(Box::new(anthropic::AnthropicProvider::new(key.clone(), config.model.clone())))
            }
        }
        ProviderKind::OpenAI => {
            Ok(Box::new(openai::OpenAIProvider::new(key.clone(), config.model.clone(), config.base_url.clone())))
        }
    }
}

// ---------------------------------------------------------------------------
// Context for the agent loop
// ---------------------------------------------------------------------------

pub struct AgentCtx {
    pub provider: Box<dyn LlmProvider + Send + Sync>,
    pub engine: Option<Arc<Mutex<Engine>>>,
    /// Optional loaded backend analysis context (rusi/golem/dosai/blint).
    pub backend: Option<Box<dyn Backend>>,
    pub source_root: Option<String>,
    pub system_prompt: String,
    pub max_tokens: u32,
    pub no_thinking: bool,
    /// Anthropic `output_config.effort` (`low`..`max`); empty disables the field.
    pub effort: String,
    /// When set, only these tool names are offered to the model (used by slash
    /// commands to scope the toolset). `None` means all tools.
    pub allowed_tools: Option<Vec<String>>,
    pub cancel: Arc<AtomicBool>,
    /// Optional debug logger that records custom tool calls (atom_, bom_, rusi_,
    /// golem_, dosai_, blint_) to timestamped JSON files under
    /// `<source_root>/.chen/chennai-debug-logs/`.  Enabled via `--debug`.
    pub debug_logger: Option<DebugLogger>,
}

impl AgentCtx {
    pub fn build_system_prompt(
        language: &str,
        version: &str,
        summary_rows: &[crate::model::SummaryRow],
        bom_summary: Option<&str>,
        bom_components: Option<&str>,
        console_history: Option<&str>,
        memory_index: Option<&str>,
    ) -> String {
        let counts: String = summary_rows.iter()
            .map(|r| format!("{}: {}", r.label, r.count))
            .collect::<Vec<_>>()
            .join("\n");

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
            .map(|s| format!("\n## Console output\nBelow are the recent commands the user ran and their results. Use this context to answer questions about what was shown.\n{s}\n"))
            .unwrap_or_default();

        let memory_section = memory_index
            .filter(|s| !s.is_empty() && *s != "none yet")
            .map(|s| format!(
                "\n## Project memory (facts learned in previous sessions — HINTS, re-verify before reporting)\n\
                 {s}\n\
                 Use the project_memory tool (action:\"recall\"/\"search\") to read a fact's full body.\n"
            ))
            .unwrap_or_default();

        let identity_rules = crate::shared::backend::PROJECT_IDENTITY_RULES;
        let red_team = crate::shared::backend::RED_TEAM_MISSION;
        let response_style = crate::shared::backend::RESPONSE_STYLE;

        format!(
            r#"You are chennai, an adversarial, red-team code & security analysis agent. You think
like an attacker and reason over a code property graph (CPG) "atom" for a real codebase —
not over your training prior. Your purpose is to find reachable, exploitable, and
previously-unknown weaknesses, not merely to match known CVEs.

## Open atom
Language: {language}
Version: {version}

## Atom summary (authoritative — do NOT call atom_summary to re-fetch these)
{counts}{console_section}{bom_section}{memory_section}
## Available tools
- atom_traversal_docs — look up DSL traversal roots, step methods, and examples.
- atom_query — flat tables: files, methods, externalMethods, calls, tags, imports, literals, configFiles…
- atom_dsl_eval — arbitrary chen DSL (the power tool). Auto-`.toJson`, paged.
- atom_flows / atom_flows_through — data-flow (source→sink) paths; presets dataflows/reachables/cryptos.
- atom_detail — properties, children, call tree, and real source for a node.
- atom_algorithms — pagerank, scc, dominators, toposort, shortest-path, reachable-by.
- git_diff / git_log / git_show — read-only git history.
- ripgrep / read_file — search and read source (confined to the project root).

## chen DSL quick-start (for atom_dsl_eval — write valid expressions)
Use `atom_traversal_docs` to look up any traversal root, step method, or generic operation (filter, where, repeat, collect, …) — always available.
Discovery patterns (use these first to explore the codebase):
  atom.method.name("executeQuery|execute|query").call.take(20).toJson   (call sites of matching methods — PREFERRED, fastest)
  atom.method.name("executeQuery|execute|query").toJson          (method definitions by name)
  atom.method.isExternal.take(50).toJson                         (external / library method calls)
  atom.call.name("executeQuery|execute|query|prepare").take(20).toJson    (calls by method name — when the method call traversal is too narrow)
  atom.call.code("regex").take(20).toJson                        (calls by raw source text — slowest, last resort)
  atom.tag.name("sql|framework-input|database").take(50).toJson  (tagged nodes)
Security patterns (find source-to-sink flows):
  atom.flows                                                     (all data-flow paths)
  atom.flows.reachableBy                                         (flows reachable from untrusted input)
  atom.tag.name("sql").call.reachableBy(atom.tag.name("framework-input")).toJson   (flow from input to SQL, requires tags)
  atom.method.name("execute|query|exec|eval|open|read|write").call.where(_.tag.name("framework-input")).take(20).toJson   (dangerous calls reachable from input)
When tag-based queries return empty, drop the tag filter:
  atom.method.name("executeQuery|execute|query|SELECT|INSERT|UPDATE|DELETE|DROP").call.take(20).toJson   (SQL-like calls)
  atom.method.name("exec|system|popen|subprocess|shell").call.take(20).toJson                            (command injection calls)
Prefer `.method.name(regex).call` over `.call.code` / `.call.name`: it is indexed by method
and runs far faster than scanning raw call source text. Reach for `.call.code` only when you
must match a literal source substring that has no method name.
Limit data volume: append a slicing step before `.toJson` so you only ship back what you need —
`.take(n)` (first n), `.drop(n).take(n)` (page through), `.dedup` (collapse duplicates),
`.size` / `.count` (just the count when you only need how many). Start narrow (take 10-20),
widen only if the sample is insufficient. Never request a full unbounded result set first.
Always end a traversal you want back with `.toJson` (the engine appends it if omitted).
Names and code are matched with Scala/Java regex syntax (java.util.regex), and the pattern
must match the WHOLE string (it is anchored), so wrap partial matches in `.*`:
  `.*` matches everything                       atom.method.name(".*").take(20).toJson
  `.*query.*` substring match (case-sensitive)  atom.method.name(".*query.*").call.take(20).toJson
  `(?i).*query.*` case-insensitive substring    atom.method.name("(?i).*query.*").call.take(20).toJson
  `\\.` a literal dot (escape with double backslash in the string)   atom.call.code(".*os\\.system.*").take(20).toJson
  `foo|bar` alternation                         atom.method.name("(?i).*(exec|system|popen).*").call.take(20).toJson
Because matching is anchored, a bare `exec` will NOT match `executeQuery`; use `.*exec.*`.
If an expression errors, the engine returns the parser error verbatim as the tool result —
read it and self-correct.

{identity_rules}

{red_team}

## Grounding rules (this is the whole point of chennai)
1. NEVER invent call graphs, taints, sinks, or reachability. Every claim must trace to a
   tool result. If you cannot trace it, say so explicitly.
2. **Tool priority**: Use atom tools FIRST for every query (atom_query, atom_dsl_eval,
   atom_flows, atom_flows_through, atom_detail, atom_algorithms). Only use ripgrep or
   read_file when all atom tools have been exhausted for the information you need or when
   you need a short snippet of surrounding source context. A ripgrep result is weaker
   evidence than an atom tool result.
3. **Security vulnerability analysis**: For specific vulnerability types (SQL injection,
   path traversal, command injection, XSS), use atom_dsl_eval with
   `atom.method.name(regex).call` (preferred — fastest) to find call sites, then chain
   with `.where(_.tag.name("framework-input"))` or use atom_flows to find source-to-sink
   paths. Fall back to `atom.call.name` or `atom.call.code` only when method-name matching
   misses the pattern. Always cap results with `.take(n)` so you pull a sample first rather
   than the full set. Ripgrep can find method names but CANNOT prove reachability, taint
   flow, or whether input reaches a dangerous function.
4. **Do not call ripgrep to confirm atom tool results.** When atom_query returns empty
   results for a tag or category, that is authoritative -- the atom has no nodes with
   that tag. When atom_dsl_eval or atom_flows return a set of paths, those paths are
   the complete answer. Calling ripgrep afterwards to "double-check" wastes turns and
   produces weaker evidence. Wait for atom tool results before reaching for ripgrep.
5. If atom_flows/atom_flows_through/atom_algorithms return NO results, this atom lacks
   usable data-flow / reachability data. Do NOT dress up a ripgrep+reasoning answer as a
   reachability finding. A pure text-pattern answer is not what chennai users want.
   In that case, state plainly that data-flow analysis was unavailable, present only what
   the source text supports, and mark every finding LOW confidence.
6. For each security finding give: file:line, the concrete tainted path (when available),
   sanitizer check, and a confidence grounded in the tool evidence. Refuse to report what
   you could not trace.
7. When available, use the CycloneDX SBOM (Software Bill of Materials) above to understand
   third-party dependencies, their licenses, and known vulnerabilities. Cross-reference
   dependency data with data-flow findings to identify vulnerable packages that are
   reachable from untrusted input.
 8. **Project memory (facts stored under `.chen/facts-memory/`) is a HINT, not evidence.** A
    recalled fact may be stale if the code has changed since it was saved. When a fact's `commit`
    field differs from the current `HEAD`, **re-verify every source ref** with live tools before
    reporting. Confirmed and refuted findings from previous sessions are in memory — check them
    before re-triaging to avoid duplicate work and contradicting an earlier conclusion. **Only
    store facts grounded in custom analysis tools** (`atom_*`, `blint_*`, `rusi_*`, `golem_*`,
    `dosai_*`, `bom_*`). Do NOT store facts based on `read_file`, `ripgrep`, or git tools —
    those produce no structural evidence and are not interesting for long-term memory.
9. **Scope data-flow queries — never run `dataflows` blind on large codebases.** The
   `dataflows` preset enumerates EVERY source-to-sink path and is unbounded; on a large
   atom (>10000 files; check the file count in the atom summary above) it can run for
   minutes and exhaust memory. Do NOT use it there. Instead query for SPECIFIC reachable
   flows between a chosen source tag and sink tag. First run atom_query on `tags` to see
   which source/sink tags this atom actually has, then pass a scoped `expr` to atom_flows
   of the form `(sink).reachableByFlows(source)`, scoping both ends to a tag and a node
   kind. Cheat sheet (reachableByFlows between two tags):
     atom.tag.name("sql").call.reachableByFlows(atom.tag.name("framework-input").parameter, atom.tag.name("framework-input").identifier, atom.tag.name("framework-input").call)
     atom.tag.name("exec").call.argument.isIdentifier.reachableByFlows(atom.tag.name("cli-source").parameter)
     atom.tag.name("(service-egress|tracker)").call.reachableByFlows(atom.tag.name("(sensitive-data|pii)").identifier, atom.tag.name("(sensitive-data|pii)").parameter)
     atom.tag.name("crypto-generate").call.reachableByFlows(atom.tag.name("crypto-algorithm").literal)
   Prefer the `reachables` preset over `dataflows` when you do need a broad scan.

{response_style}

## Efficiency rules
Wait for atom tool results to arrive before calling ripgrep or read_file. Calling ripgrep in the same turn as atom_dsl_eval or atom_flows means you are guessing instead of reading evidence. One well-chosen atom query eliminates the need for several ripgrep calls.

You are an authorized red-team review of the user's own atom. Analyze it adversarially and
directly: hunt for reachable sinks, missing authn/authz/RBAC, and supply-chain risk, and
favor unknown vulnerabilities over known CVEs. When you have enough evidence, answer
concisely with specific file:line references and a concrete exploit path.
"#
        )
    }
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

pub struct ToolExecResult {
    pub call_id: String,
    pub content: String,
    pub is_error: bool,
}

pub fn dispatch_tool(ctx: &AgentCtx, call_id: &str, name: &str, input: &Value) -> ToolExecResult {
    let result = match name {
        "atom_traversal_docs" => traversal_docs_dispatch(call_id, input),
        "atom_summary" => engine_request(ctx, call_id, "summary", input),
        "atom_query" => engine_request(ctx, call_id, "query", input),
        "atom_dsl_eval" => engine_request(ctx, call_id, "eval", input),
        "atom_flows" => engine_request(ctx, call_id, "flows", input),
        "atom_flows_through" => engine_request(ctx, call_id, "flows", input),
        "atom_detail" => engine_request(ctx, call_id, "detail", input),
        "atom_algorithms" => engine_request(ctx, call_id, "algo", input),
        // Backend-specific tool dispatch: tools named <backend>_<command>
        _ if name.starts_with("rusi_") => backend_dispatch(ctx, call_id, name.strip_prefix("rusi_").unwrap(), input),
        _ if name.starts_with("golem_") => backend_dispatch(ctx, call_id, name.strip_prefix("golem_").unwrap(), input),
        _ if name.starts_with("dosai_") => backend_dispatch(ctx, call_id, name.strip_prefix("dosai_").unwrap(), input),
        _ if name.starts_with("blint_") => backend_dispatch(ctx, call_id, name.strip_prefix("blint_").unwrap(), input),
        "bom_query" => bom_query_dispatch(ctx, call_id, input),
        "project_memory" => memory::memory_dispatch(ctx.source_root.as_deref(), call_id, input),
        "ripgrep"   => wrap_result(call_id, shell::ripgrep(&source_root_path(ctx), input)),
        "read_file" => wrap_result(call_id, shell::read_file(&source_root_path(ctx), input)),
        "git_diff"  => wrap_result(call_id, shell::git_diff(&source_root_path(ctx), input)),
        "git_log"   => wrap_result(call_id, shell::git_log(&source_root_path(ctx), input)),
        "git_show"  => wrap_result(call_id, shell::git_show(&source_root_path(ctx), input)),
        other => ToolExecResult {
            call_id: call_id.into(),
            content: format!("unknown tool: {other}"),
            is_error: true,
        },
    };

    if let Some(ref logger) = ctx.debug_logger
        && DebugLogger::is_tracked(name) {
            logger.log(name, input, &result.content, result.is_error);
    }

    result
}

/// Unified dispatch for all backend tool calls via the Backend trait.
fn backend_dispatch(ctx: &AgentCtx, call_id: &str, cmd: &str, input: &Value) -> ToolExecResult {
    let Some(ref backend) = ctx.backend else {
        return ToolExecResult {
            call_id: call_id.into(),
            content: "analysis backend not loaded".into(),
            is_error: true,
        };
    };

    let content = match cmd {
        "summary" => backend.summary(),
        _ => {
            let kind = if cmd == "query" {
                input.get("kind").and_then(Value::as_str).unwrap_or("query")
            } else {
                cmd
            };
            let pattern = input.get("pattern").and_then(Value::as_str);
            let limit = input.get("limit").and_then(Value::as_u64).unwrap_or(50).min(500) as usize;
            // For "detail", use pattern as the name lookup
            let name = input.get("name").and_then(Value::as_str);
            match name {
                Some(n) if kind == "detail" => backend.query("detail", Some(n), limit),
                _ => backend.query(kind, pattern, limit),
            }
        }
    };

    ToolExecResult {
        call_id: call_id.into(),
        content: truncate_content(&content, MAX_TOOL_RESULT_BYTES),
        is_error: false,
    }
}

/// Look up chen DSL traversal documentation from the embedded TRAVERSAL.md.
fn traversal_docs_dispatch(call_id: &str, input: &Value) -> ToolExecResult {
    let root = input.get("root").and_then(Value::as_str).unwrap_or("all");
    let content = get_traversal_docs(root);
    ToolExecResult { call_id: call_id.into(), content, is_error: false }
}

/// Return the relevant documentation section for a given traversal root, step,
/// or generic operation name. Searches both TRAVERSAL.md and DSL_OPERATIONS.md.
/// When `root` is `"all"` (or empty), returns a combined index.
fn get_traversal_docs(root: &str) -> String {
    let lower = root.trim().to_ascii_lowercase();

    if lower.is_empty() || lower == "all" {
        return build_full_index();
    }

    // 1) Search TRAVERSAL.md for a root section.
    let section_header = format!("\n## {} ", lower);
    if let Some(start) = TRAVERSAL_DOCS.find(&section_header) {
        let from_header = &TRAVERSAL_DOCS[start + section_header.len() - 1..];
        let section = if let Some(end) = from_header[1..].find("\n## ") {
            from_header[..=end].trim()
        } else {
            from_header.trim()
        };
        let mut result = section.to_string();
        // Append the helper step methods section if not already included.
        if !result.contains("Helper step")
            && let Some(hs) = TRAVERSAL_DOCS.find("\n## Helper step")
        {
            let helper = &TRAVERSAL_DOCS[hs..];
            let helper = if let Some(e) = helper[1..].find("\n## ") {
                &helper[..=e]
            } else {
                helper
            };
            result.push_str("\n\n");
            result.push_str(helper.trim());
        }
        return result;
    }

    // 2) Search DSL_OPERATIONS.md for a category or specific operation.
    //    First try a category heading match.
    if let Some(start) = DSL_OPERATIONS.find(&section_header) {
        let from_header = &DSL_OPERATIONS[start + section_header.len() - 1..];
        let section = if let Some(end) = from_header[1..].find("\n## ") {
            from_header[..=end].trim()
        } else {
            from_header.trim()
        };
        return section.to_string();
    }
    //    Then try to find a direct operation reference (e.g. "`.where(trav)`").
    let op_pattern = &format!("`{lower}");
    if let Some(start) = DSL_OPERATIONS.find(op_pattern) {
        // Return the containing category section.
        let before = &DSL_OPERATIONS[..start];
        if let Some(cat_start) = before.rfind("\n## ") {
            let cat_end = DSL_OPERATIONS[cat_start + 1..]
                .find("\n## ")
                .map(|e| cat_start + 1 + e)
                .unwrap_or(DSL_OPERATIONS.len());
            return DSL_OPERATIONS[cat_start..cat_end].trim().to_string();
        }
        // Fallback: return a snippet around the match.
        let end = (start + 200).min(DSL_OPERATIONS.len());
        return format!("…{}\n\nUse `atom_traversal_docs` with a category name (e.g. `filter`, `repeat`) for the full reference.", &DSL_OPERATIONS[start..end].trim());
    }

    format!(
        "Unknown root or operation '{root}'. Use `atom_traversal_docs` with `root: \"all\"` for a full index."
    )
}

/// Build a combined index of every available topic from both docs.
fn build_full_index() -> String {
    // Root table from TRAVERSAL.md (lines up to the first "## .* steps" heading).
    let roots = TRAVERSAL_DOCS
        .find("\n## ")
        .map(|end| &TRAVERSAL_DOCS[..end])
        .unwrap_or(TRAVERSAL_DOCS)
        .trim();

    // Category table from DSL_OPERATIONS.md (lines up to the first "## .*" content heading).
    let op_categories = DSL_OPERATIONS
        .find("\n### ")
        .map(|end| &DSL_OPERATIONS[..end])
        .unwrap_or(DSL_OPERATIONS)
        .trim();

    format!(
        "## Traversal roots\n\
         {roots}\n\n\
         ## Generic operations (filter, where, repeat, collect, …)\n\
         {op_categories}\n\n\
         Use `atom_traversal_docs` with a specific root name (e.g. `method`, `call`, `tag`) \
         or operation category (e.g. `filter`, `repeat`, `transform`) to see full details."
    )
}

fn bom_query_dispatch(ctx: &AgentCtx, call_id: &str, input: &Value) -> ToolExecResult {
    let query = input.get("query").and_then(Value::as_str).unwrap_or("");
    let type_filter = input.get("type_filter").and_then(Value::as_str);

    // We need the bom_store from somewhere. Since AgentCtx doesn't have it directly,
    // we try to reconstruct from the source_root.
    let content = match &ctx.source_root {
        Some(src) => {
            let path = std::path::Path::new(src);
            let mut store = crate::bom::BomStore::new();
            let _ = store.load_path(path);
            if type_filter.is_some() {
                store.set_type_filter(type_filter.map(|s| s.to_string()));
            }
            if !query.is_empty() {
                store.search_components(query);
            }
            if store.loaded {
                let mut lines: Vec<String> = Vec::new();
                lines.push(format!("# BOM Components ({} total, {} filtered)", store.total_components, store.filtered_components_count()));
                lines.push(format!("Dependencies: {} | Services: {}", store.total_dependencies, store.total_services));
                lines.push(String::new());
                for idx in &store.filtered_component_indices {
                    if let Some(row) = store.components.get(*idx) {
                        lines.push(format!("| {} | {} | {} | {} | {} |",
                            row.type_display(), row.name_display(), row.version_display(),
                            row.purl_display(), row.license_display()));
                    }
                }
                lines.join("\n")
            } else {
                "No BOM data available. Generate one with cdxgen.".to_string()
            }
        }
        None => "BOM store not available (no source root configured).".to_string(),
    };

    ToolExecResult {
        call_id: call_id.into(),
        content,
        is_error: false,
    }
}

fn wrap_result(call_id: &str, result: Result<String, String>) -> ToolExecResult {
    match result {
        Ok(content) => ToolExecResult { call_id: call_id.into(), content, is_error: false },
        Err(content) => ToolExecResult { call_id: call_id.into(), content, is_error: true },
    }
}

/// Maximum bytes of tool result content sent back to the LLM per tool call.
/// Larger results are truncated to prevent 413 errors and runaway token usage.
const MAX_TOOL_RESULT_BYTES: usize = 48 * 1024; // 48 KiB

fn engine_request(ctx: &AgentCtx, call_id: &str, cmd: &str, input: &Value) -> ToolExecResult {
    let Some(ref engine_mutex) = ctx.engine else {
        return ToolExecResult { call_id: call_id.into(), content: "engine not available".into(), is_error: true };
    };
    let mut engine = engine_mutex.lock().unwrap();
    match engine.request::<Value>(cmd, input.clone()) {
        Ok(data) => {
            // When an analysis-grounded query (data-flow, reachability, call-graph
            // algorithms, or a call tree) comes back empty, the model would
            // otherwise silently fall back to a grep + reasoning answer — exactly
            // the ungrounded output chennai users don't want. Prepend an explicit
            // note so the model flags low confidence instead of fabricating
            // reachability. See the "Grounding rules" in the system prompt.
            let note = analysis_unavailable_note(cmd, &data);
            // Prefer Markdown: LLMs parse tables/lists better than double-escaped
            // JSON and it costs fewer tokens. Fall back to pretty JSON for shapes
            // the renderer doesn't model. The engine still receives `.toJson`
            // expressions; only the agent-facing rendering changes.
            let text = render::render_engine_result(cmd, &data)
                .unwrap_or_else(|| serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string()));
            let mut content = truncate_content(&text, MAX_TOOL_RESULT_BYTES);
            if let Some(n) = note {
                content = format!("{n}\n\n{content}");
            }
            ToolExecResult { call_id: call_id.into(), content, is_error: false }
        }
        Err(e) => {
            let mut content = redact_secrets(&format!("engine error: {e}"));
            // A failed DSL eval is the moment the model most needs the syntax
            // reference. Append a compact chen-DSL cheat-sheet so it can self-
            // correct in the same turn instead of falling back to ripgrep or
            // burning a separate atom_traversal_docs round-trip.
            if cmd == "eval" {
                content.push_str(EVAL_ERROR_CHEATSHEET);
            }
            ToolExecResult { call_id: call_id.into(), content, is_error: true }
        }
    }
}

/// Compact chen-DSL reference appended to `atom_dsl_eval` parser errors. Distilled
/// from `docs/TRAVERSAL.md` + `docs/DSL_OPERATIONS.md` and real query patterns in the
/// atom/chen test suites. Kept short so it doesn't bloat repeated error turns.
const EVAL_ERROR_CHEATSHEET: &str = "\n\n--- chen DSL quick reference (fix the expression above) ---\n\
Every query starts with `atom.<root>` and ends with `.toJson` (auto-appended if omitted).\n\
Roots: method, call, literal, identifier, parameter, local, file, configFile, tag, imports, annotation, typeDecl, member, ret.\n\
String args are REGEX, anchored with neither ^ nor $ (substring match). Use `Exact` for literal: `.nameExact(\"main\")`, `.fullNameExact(...)`.\n\
Common steps:\n\
  atom.method.name(\"regex\")            method defs by name (also .fullName, .filename, .signature)\n\
  atom.method.internal / .external      app-defined vs library methods (NOT .isExternal as a step)\n\
  atom.method.name(\"x\").caller / .callee / .call / .parameter / .literal\n\
  atom.call.code(\"regex\")              call sites by source text (prefer over .name for real patterns)\n\
  atom.call.name(\"regex\") / .methodFullName(\"regex\") / .argument\n\
  atom.literal.code(\"regex\") / atom.identifier.typeFullName(\"regex\")\n\
  atom.tag.name(\"sql|framework-input\") tagged nodes\n\
Generic ops: .where(_.tag.name(\"x\")) .whereNot(...) .filter(_.isExternal==false) .dedup .take(n) .drop(n) .repeat(_.caller).times(3)\n\
Data flow (use atom_flows, but the DSL form is): sink.reachableByFlows(source) / sink.reachableBy(source)\n\
  where source/sink are traversals, e.g. atom.call.code(\"executeQuery\").reachableByFlows(atom.tag.name(\"framework-input\").call).toJson\n\
If still unsure of an exact step name, call atom_traversal_docs with the root (e.g. root=\"method\") for the full list.\n";

/// Returns an advisory note when an analysis-grounded engine result is empty, so
/// the model treats the absence of data-flow/reachability evidence honestly
/// rather than substituting a pattern-matched guess.
fn analysis_unavailable_note(cmd: &str, data: &Value) -> Option<&'static str> {
    let empty_array = |v: &Value| v.as_array().map(|a| a.is_empty()).unwrap_or(false);
    let is_empty = match cmd {
        "flows" => {
            empty_array(&data["flows"]) || empty_array(&data["rows"])
                || data.get("flows").is_none() && empty_array(&data["rows"])
        }
        "algo" => empty_array(&data["rows"]),
        // A node's call tree (atom_detail) — no callers/callees recorded.
        "detail" => {
            (data.get("callTree").is_some() && empty_array(&data["callTree"]))
                || (data.get("children").is_some() && empty_array(&data["children"]))
        }
        _ => false,
    };
    if !is_empty {
        return None;
    }
    Some(match cmd {
        "flows" => "NOTE: No data-flow / reachability paths were found for this query. \
This atom may lack data-flow analysis. Do NOT claim reachability you cannot trace — \
present only source-text evidence and mark findings LOW confidence.",
        "algo" => "NOTE: The graph algorithm returned no results (the relevant graph \
projection appears empty). Do NOT infer structural/reachability properties from this.",
        _ => "NOTE: No call-tree data is available for this node. Do NOT infer call \
relationships you cannot ground in another tool result.",
    })
}

/// Remove secrets from a string before it is shown to the user or written to a report.
///
/// Redacts:
/// 1. Any `sk-` prefixed token (e.g. API keys like `sk-4cb8be...`).
/// 2. Values of environment variables whose name ends with common secret suffixes
///    (token, key, pass, cred, secret, etc.), so config/error output is sanitised.
///
/// Conservative and dependency-free.
pub fn redact_secrets(s: &str) -> String {
    let secret_values = load_secret_env_values();
    let mut result = s.to_string();
    // Redact env-var-derived secrets first (wider matches).
    for val in &secret_values {
        if val.len() < 8 {
            continue;
        }
        result = result.replace(val, "***redacted***");
    }
    // Then redact sk-… tokens (which may appear inline without an env-var trigger).
    result = redact_sk_tokens(&result);
    result
}

/// Collect values from environment variables whose name ends with a known
/// secret suffix.  The check is case-insensitive.
fn load_secret_env_values() -> Vec<String> {
    let suffixes = [
        "token", "tokens",
        "key", "keys", "api_key", "api_key_secret", "apikey",
        "pass", "password", "passwd", "secret", "secrets",
        "cred", "creds", "credential", "credentials",
        "signing_key", "private_key", "access_key", "secret_key",
    ];
    let mut values = Vec::new();
    for (name, val) in std::env::vars() {
        let lower = name.to_ascii_lowercase();
        if suffixes.iter().any(|s| lower.ends_with(s)) && !val.is_empty() {
            values.push(val);
        }
    }
    values
}

/// Redact inline `sk-<token>` patterns (e.g. OpenAI-style API keys).
fn redact_sk_tokens(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"sk-") {
            let mut j = i + 3;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'-')
            {
                j += 1;
            }
            if j - i >= 12 {
                out.push_str("sk-***redacted***");
                i = j;
                continue;
            }
        }
        let ch_len = s[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        out.push_str(&s[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn truncate_content(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    // Reserve room for the marker, then cut on a UTF-8 char boundary so the
    // budget is filled cleanly without splitting a multi-byte character.
    const MARKER_BUDGET: usize = 96;
    let cut = floor_char_boundary(text, max_bytes.saturating_sub(MARKER_BUDGET));
    format!(
        "{}\n--- OUTPUT TRUNCATED at {} KiB (original: {} KiB). Use offset/limit to paginate. ---",
        &text[..cut],
        max_bytes / 1024,
        text.len() / 1024,
    )
}

/// Largest byte index `<= max` that lands on a UTF-8 char boundary.
/// (`str::floor_char_boundary` is still unstable, so we do it by hand.)
fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    let mut idx = max;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn source_root_path(ctx: &AgentCtx) -> std::path::PathBuf {
    ctx.source_root.as_ref().map(std::path::PathBuf::from).unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Keep only the tool definitions whose `name` is in `allowed` (used by slash
/// commands to scope the toolset). `None` keeps every tool.
fn filter_tools(defs: Vec<Value>, allowed: Option<&[String]>) -> Vec<Value> {
    match allowed {
        None => defs,
        Some(allow) => defs
            .into_iter()
            .filter(|d| {
                d.get("name")
                    .and_then(Value::as_str)
                    .map(|n| allow.iter().any(|a| a == n))
                    .unwrap_or(false)
            })
            .collect(),
    }
}

/// Turn a transport/API error into a concise, user-facing message with secrets
/// scrubbed. Network failures get an explicit "offline" hint.
fn friendly_provider_error(e: &ProviderError) -> String {
    let raw = redact_secrets(&e.to_string());
    match e {
        ProviderError::Http(_) => format!(
            "Network error talking to the LLM provider — check your connection / base URL. ({raw})"
        ),
        ProviderError::Stream(m) if m == "cancelled" => "Cancelled.".into(),
        _ => raw,
    }
}

// ---------------------------------------------------------------------------
// Agent loop (background-thread entry point)
// ---------------------------------------------------------------------------

pub fn run_agent(ctx: &AgentCtx, user_input: &str, tx: mpsc::Sender<AgentEvent>) {
    let mut transcript = Transcript::new();
    transcript.push_user(user_input);

    // Select the appropriate tool definitions based on the analysis mode.
    let base_tools = match (ctx.engine.is_some(), ctx.backend.as_ref()) {
        // Atom + backend (e.g. APK/JAR with both atom and blint): atom-primary, both toolsets.
        (true, Some(backend)) => tools::atom_plus_backend_tool_definitions(backend),
        (false, Some(backend)) => tools::backend_tool_definitions(backend),
        (true, None) => tools::all_tool_definitions(),
        (false, None) => tools::non_atom_tool_definitions(),
    };
    let tool_defs = filter_tools(base_tools, ctx.allowed_tools.as_deref());

    loop {
        if ctx.cancel.load(Ordering::Relaxed) {
            tx.send(AgentEvent::Done).ok();
            return;
        }

        let mut sink = ChannelSink(tx.clone());
        let cancel: &AtomicBool = &ctx.cancel;
        let result = match ctx.provider.stream_turn(
            &TurnRequest {
                system: &ctx.system_prompt,
                tools: &tool_defs,
                messages: transcript.messages(),
                max_tokens: ctx.max_tokens,
                no_thinking: ctx.no_thinking,
                effort: &ctx.effort,
                cancel,
            },
            &mut sink,
        ) {
            Ok(r) => r,
            Err(e) => {
                tx.send(AgentEvent::Error(friendly_provider_error(&e))).ok();
                tx.send(AgentEvent::Done).ok();
                return;
            }
        };

        transcript.push_assistant(result.content);

        match result.stop_reason.as_str() {
            "end_turn" | "stop" => {
                tx.send(AgentEvent::Done).ok();
                return;
            }
            // The model declined (safety classifier). Non-fatal: surface a clean
            // message and leave the session usable so the user can rephrase.
            "refusal" => {
                tx.send(AgentEvent::Error(
                    "The model declined this request. Security-adjacent prompts can trip a \
safety classifier even for legitimate review — try rephrasing, e.g. frame it as an \
authorized review of your own code.".into(),
                )).ok();
                tx.send(AgentEvent::Done).ok();
                return;
            }
            "tool_use" | "tool_calls" => {
                let tool_calls = transcript.last_tool_calls();
                if tool_calls.is_empty() {
                    tx.send(AgentEvent::Error("model requested tools but none found".into())).ok();
                    tx.send(AgentEvent::Done).ok();
                    return;
                }

                // Execute tool calls in parallel — all tools are read-only, so there is no
                // risk of side-effect conflicts. Engine access serialises through the mutex
                // but shell tools (ripgrep, read_file, git) run fully concurrently.
                let results: Vec<ToolExecResult> = std::thread::scope(|scope| {
                    tool_calls.iter()
                        .filter(|_| !ctx.cancel.load(Ordering::Relaxed))
                        .map(|(call_id, name, input)| {
                            scope.spawn(|| dispatch_tool(ctx, call_id, name, input))
                        })
                        .collect::<Vec<_>>()
                        .into_iter()
                        .map(|h| h.join().unwrap())
                        .collect()
                });

                for result in &results {
                    transcript.push_tool_result(&result.call_id, &result.content, result.is_error);
                    // Surface the result to the UI so tool cards become inspectable.
                    tx.send(AgentEvent::ToolResult {
                        id: result.call_id.clone(),
                        content: result.content.clone(),
                        is_error: result.is_error,
                    }).ok();
                }
            }
            _ => {
                tx.send(AgentEvent::Done).ok();
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Headless mode (for --ask)
// ---------------------------------------------------------------------------

struct HeadlessSink;
impl EventSink for HeadlessSink {
    fn emit(&mut self, event: AgentEvent) {
        match &event {
            AgentEvent::TextDelta(t) => {
                print!("{}", t);
                use std::io::Write;
                std::io::stdout().flush().ok();
            }
            AgentEvent::ThinkingDelta(t) => {
                eprint!("[thinking: {}]", t);
            }
            AgentEvent::ToolCall { name, input, .. } => {
                let input_str = serde_json::to_string(input).unwrap_or_default();
                eprintln!("\n[TOOL CALL: {}({})]", name, input_str);
            }
            AgentEvent::Usage { input_tokens, output_tokens, cache_read_tokens } => {
                eprintln!("\n[Usage: {} in / {} out / {:?} cache]", input_tokens, output_tokens, cache_read_tokens);
            }
            AgentEvent::StopReason(r) => {
                eprintln!("\n[Stop reason: {}]", r);
            }
            _ => {}
        }
    }
}

pub fn run_headless(ctx: &AgentCtx, input: &str) -> Result<String, Box<dyn std::error::Error>> {
    let base_tools = match (ctx.engine.is_some(), ctx.backend.as_ref()) {
        // Atom + backend (e.g. APK/JAR with both atom and blint): atom-primary, both toolsets.
        (true, Some(backend)) => tools::atom_plus_backend_tool_definitions(backend),
        (false, Some(backend)) => tools::backend_tool_definitions(backend),
        (true, None) => tools::all_tool_definitions(),
        (false, None) => tools::non_atom_tool_definitions(),
    };
    let tool_defs = filter_tools(base_tools, ctx.allowed_tools.as_deref());
    let mut transcript = Transcript::new();
    transcript.push_user(input);
    let mut final_text = String::new();
    let mut sink = HeadlessSink;
    let cancel: &AtomicBool = &ctx.cancel;

    loop {
        let result = match ctx.provider.stream_turn(
            &TurnRequest {
                system: &ctx.system_prompt,
                tools: &tool_defs,
                messages: transcript.messages(),
                max_tokens: ctx.max_tokens,
                no_thinking: ctx.no_thinking,
                effort: &ctx.effort,
                cancel,
            }, &mut sink,
        ) {
            Ok(r) => r,
            Err(e) => { eprintln!("\n[Error: {e}]"); return Err(e.into()); }
        };

        for block in &result.content {
            if let ContentBlock::Text(t) = block { final_text.push_str(t); }
        }
        transcript.push_assistant(result.content);

        match result.stop_reason.as_str() {
            "end_turn" | "stop" => break,
            "tool_use" | "tool_calls" => {
                let calls = transcript.last_tool_calls();
                for (call_id, name, input) in &calls {
                    eprintln!("\n  → executing {name}...");
                    let r = dispatch_tool(ctx, call_id, name, input);
                    transcript.push_tool_result(&r.call_id, &r.content, r.is_error);
                    let preview: String = r.content.chars().take(200).collect();
                    eprintln!("  → result ({} bytes): {}", r.content.len(), preview);
                }
            }
            _ => break,
        }
    }
    Ok(final_text)
}

/// One-shot, no-tools LLM call that proposes a few context-aware starter questions for
/// the empty-state UI. Returns `(label, command)` pairs, or an empty vec on any failure,
/// cancellation, or unparseable output — callers fall back to the template questions.
pub fn refine_starter_questions(
    provider: &(dyn LlmProvider + Send + Sync),
    context: &str,
    cancel: &AtomicBool,
) -> Vec<(String, String)> {
    let system = "You suggest starter questions for an interactive code & security analysis TUI. \
Given a factual digest of an analyzed project (language, code metrics, SBOM components), propose \
3-4 short, concrete questions a security engineer would find interesting FOR THIS SPECIFIC PROJECT. \
Prefer specifics (named components, notable counts, likely risk areas) over generic phrasing. \
Each question must be a full, specific sentence (not a 4-word label). \
Be fast. Respond with ONLY a JSON array of objects {\"label\": button text <=80 chars, \
\"command\": the full question sent to the agent}. No prose, no markdown fences.";

    let mut transcript = Transcript::new();
    transcript.push_user(&format!("Project digest:\n{context}"));

    struct CollectSink(String);
    impl EventSink for CollectSink {
        fn emit(&mut self, event: AgentEvent) {
            if let AgentEvent::TextDelta(t) = event { self.0.push_str(&t); }
        }
    }
    let mut sink = CollectSink(String::new());

    let result = provider.stream_turn(
        &TurnRequest {
            system,
            tools: &[],
            messages: transcript.messages(),
            max_tokens: 600,
            no_thinking: true,
            effort: "",
            cancel,
        },
        &mut sink,
    );
    if result.is_err() || cancel.load(Ordering::Relaxed) {
        return Vec::new();
    }
    parse_starter_questions(&sink.0)
}

/// Extract `(label, command)` pairs from a JSON array embedded in the model's reply,
/// tolerating surrounding prose or markdown fences.
fn parse_starter_questions(text: &str) -> Vec<(String, String)> {
    let (start, end) = match (text.find('['), text.rfind(']')) {
        (Some(s), Some(e)) if e > s => (s, e),
        _ => return Vec::new(),
    };
    let arr: Vec<Value> = match serde_json::from_str(&text[start..=end]) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    arr.iter()
        .take(4)
        .filter_map(|item| {
            let label = item.get("label").and_then(Value::as_str).unwrap_or("").trim();
            let command = item.get("command").and_then(Value::as_str).unwrap_or("").trim();
            (!label.is_empty() && !command.is_empty())
                .then(|| (label.to_string(), command.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SummaryRow;

    #[test]
    fn parse_starter_questions_extracts_pairs_amid_prose() {
        let text = "Here you go:\n```json\n[{\"label\":\"Audit requests\",\"command\":\"Is requests 2.31.0 vulnerable?\"},{\"label\":\"\",\"command\":\"skip me\"}]\n```";
        let pairs = parse_starter_questions(text);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "Audit requests");
        assert!(pairs[0].1.contains("requests 2.31.0"));
    }

    #[test]
    fn parse_starter_questions_handles_garbage() {
        assert!(parse_starter_questions("no json here").is_empty());
        assert!(parse_starter_questions("[not valid json").is_empty());
    }

    #[test]
    fn system_prompt_includes_summary_counts() {
        let rows = vec![SummaryRow { label: "Files".into(), count: 42 }];
        let prompt = AgentCtx::build_system_prompt("C", "1.0", &rows, None, None, None, None);
        assert!(prompt.contains("Language: C"));
        assert!(prompt.contains("Files: 42"));
        assert!(prompt.contains("Grounding rule"));
    }

    #[test]
    fn system_prompt_includes_bom_context() {
        let rows = vec![SummaryRow { label: "Files".into(), count: 42 }];
        let prompt = AgentCtx::build_system_prompt(
            "Python", "3.12", &rows,
            Some("components: 15 · dependencies: 42"),
            Some("  - library requests (2.31.0) pkg:pip/requests@2.31.0"),
            None, None,
        );
        assert!(prompt.contains("components: 15"));
        assert!(prompt.contains("Software Bill of Materials"));
        assert!(prompt.contains("pkg:pip/requests@2.31.0"));
    }

    #[test]
    fn system_prompt_includes_memory_section_when_provided() {
        let rows = vec![SummaryRow { label: "Files".into(), count: 42 }];
        let memory_index = "- [auth-boundary](auth-boundary.md) — auth in requireAuth\n- [sql-injection](sql-injection.md) — SQLi in search";
        let prompt = AgentCtx::build_system_prompt(
            "Go", "1.21", &rows, None, None, None, Some(memory_index),
        );
        assert!(prompt.contains("Project memory"));
        assert!(prompt.contains("auth-boundary"));
        assert!(prompt.contains("sql-injection"));
        assert!(prompt.contains("project_memory tool"));
    }

    #[test]
    fn system_prompt_omits_memory_section_when_none() {
        let rows = vec![SummaryRow { label: "Files".into(), count: 42 }];
        let prompt = AgentCtx::build_system_prompt(
            "Go", "1.21", &rows, None, None, None, None,
        );
        // The grounding rule mentions project memory but the section header should not appear.
        assert!(!prompt.contains("## Project memory (facts learned"));
    }

    #[test]
    fn system_prompt_includes_memory_grounding_rule() {
        let rows = vec![SummaryRow { label: "Files".into(), count: 42 }];
        let prompt = AgentCtx::build_system_prompt("Rust", "1.75", &rows, None, None, None, None);
        assert!(prompt.contains("Project memory (facts stored under"));
        assert!(prompt.contains("re-verify every source ref"));
    }

    #[test]
    fn dispatch_tool_unknown_tool_returns_error() {
        let ctx = AgentCtx {
            provider: Box::new(crate::agent::anthropic::AnthropicProvider::new("test".into(), "test".into())),
            engine: None,
            backend: None,
            source_root: None,
            system_prompt: "test".into(),
            max_tokens: 1000,
            no_thinking: false,
            effort: "high".into(),
            allowed_tools: None,
            cancel: Arc::new(AtomicBool::new(false)),
            debug_logger: None,
        };
        let result = dispatch_tool(&ctx, "id1", "nonexistent_tool", &serde_json::json!({}));
        assert!(result.is_error);
        assert!(result.content.contains("unknown tool"));
    }

    #[test]
    fn dispatch_tool_bom_query_without_source_returns_message() {
        let ctx = AgentCtx {
            provider: Box::new(crate::agent::anthropic::AnthropicProvider::new("test".into(), "test".into())),
            engine: None,
            backend: None,
            source_root: None,
            system_prompt: "test".into(),
            max_tokens: 1000,
            no_thinking: false,
            effort: "high".into(),
            allowed_tools: None,
            cancel: Arc::new(AtomicBool::new(false)),
            debug_logger: None,
        };
        let result = dispatch_tool(&ctx, "id1", "bom_query", &serde_json::json!({"query": "express"}));
        assert!(!result.is_error);
        assert!(result.content.contains("BOM store not available"));
    }

    #[test]
    fn frontmatter_parsed_into_tools_and_effort() {
        let raw = "---\nname: security-review\ntools: [atom_summary, atom_flows, ripgrep]\neffort: xhigh\n---\n\n## Objective\nReview it.";
        let sc = parse_frontmatter(raw);
        assert_eq!(sc.tools.as_deref(), Some(&["atom_summary".to_string(), "atom_flows".to_string(), "ripgrep".to_string()][..]));
        assert_eq!(sc.effort.as_deref(), Some("xhigh"));
        assert!(sc.body.starts_with("## Objective"));
        assert!(!sc.body.contains("name:"));
    }

    #[test]
    fn frontmatter_absent_keeps_whole_body() {
        let sc = parse_frontmatter("just a prompt, no header");
        assert_eq!(sc.body, "just a prompt, no header");
        assert!(sc.tools.is_none());
        assert!(sc.effort.is_none());
    }

    #[test]
    fn frontmatter_supports_multi_line_yaml_lists() {
        let raw = "---\nname: security-review\ntools:\n  - atom_summary\n  - atom_flows\n  - ripgrep\neffort: xhigh\n---\n\n## Objective\nReview it.";
        let sc = parse_frontmatter(raw);
        assert_eq!(sc.tools.as_deref(), Some(&["atom_summary".to_string(), "atom_flows".to_string(), "ripgrep".to_string()][..]));
        assert_eq!(sc.effort.as_deref(), Some("xhigh"));
        assert!(sc.body.starts_with("## Objective"));
    }

    #[test]
    fn frontmatter_supports_yaml_inline_array_on_next_line() {
        // Format: tools:\n  [a, b, c] (inline array indented on next line)
        let raw = "---\ntools:\n  [atom_summary, atom_flows]\neffort: medium\n---\n\nBody.";
        let sc = parse_frontmatter(raw);
        assert_eq!(sc.tools.as_deref(), Some(&["atom_summary".to_string(), "atom_flows".to_string()][..]));
        assert_eq!(sc.effort.as_deref(), Some("medium"));
    }

    #[test]
    fn builtin_slash_commands_parse() {
        // The compiled-in templates must have valid frontmatter.
        let sc = slash_command("security-review").expect("security-review exists");
        assert!(sc.tools.as_ref().map(|t| t.contains(&"atom_flows".to_string())).unwrap_or(false));
        assert!(!sc.body.is_empty());
    }

    #[test]
    fn filter_tools_keeps_only_allowed() {
        let defs = tools::all_tool_definitions();
        let allow = vec!["atom_summary".to_string(), "ripgrep".to_string()];
        let filtered = filter_tools(defs.clone(), Some(&allow));
        assert_eq!(filtered.len(), 2);
        assert!(filter_tools(defs, None).len() > 2);
    }

    #[test]
    fn empty_flows_get_unavailable_note() {
        let note = analysis_unavailable_note("flows", &serde_json::json!({"flows": []}));
        assert!(note.unwrap().contains("data-flow"));
        let none = analysis_unavailable_note("flows", &serde_json::json!({"flows": [{"id": 1}]}));
        assert!(none.is_none());
    }

    #[test]
    fn redact_secrets_scrubs_api_keys() {
        let s = "error with key sk-abcdefghij in body";
        let r = redact_secrets(s);
        assert!(!r.contains("abcdefghij"));
        assert!(r.contains("sk-***redacted***"));
        assert_eq!(redact_secrets("sk-ab"), "sk-ab");
    }

    #[test]
    fn redact_secrets_scrubs_env_var_values() {
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe { std::env::set_var("_CHENNAI_CHENNAI_TOKEN", "s3cr3t-t0k3n-value") };
        unsafe { std::env::set_var("_CHENNAI_CHENNAI_PASS", "hunter2-pass") };
        unsafe { std::env::set_var("_CHENNAI_CHENNAI_API_KEY", "a1b2c3d4e5f6-key") };
        unsafe { std::env::set_var("_CHENNAI_CHENNAI_NOTE", "abc") };

        let s = "connect with s3cr3t-t0k3n-value and hunter2-pass and key a1b2c3d4e5f6-key and abc";
        let r = redact_secrets(s);
        assert!(!r.contains("s3cr3t-t0k3n-value"), "token leaked: {r}");
        assert!(!r.contains("hunter2-pass"), "password leaked: {r}");
        assert!(!r.contains("a1b2c3d4e5f6-key"), "api key leaked: {r}");
        // Short values (< 8 chars) are skipped.
        assert!(r.contains("abc"), "short value should not be redacted: {r}");
        assert!(r.contains("***redacted***"));

        unsafe { std::env::remove_var("_CHENNAI_CHENNAI_TOKEN") };
        unsafe { std::env::remove_var("_CHENNAI_CHENNAI_PASS") };
        unsafe { std::env::remove_var("_CHENNAI_CHENNAI_API_KEY") };
        unsafe { std::env::remove_var("_CHENNAI_CHENNAI_NOTE") };
    }

    #[test]
    fn redact_secrets_normal_text_unaffected() {
        let s = "the quick brown fox jumps over the lazy dog";
        assert_eq!(redact_secrets(s), s);
    }

    #[test]
    fn truncate_content_is_utf8_safe() {
        // A string of multi-byte chars truncated to an odd byte budget must not panic
        // and must remain valid UTF-8.
        let s = "café_".repeat(20_000); // 'é' is 2 bytes
        let out = truncate_content(&s, 1000);
        assert!(out.len() <= 1000 + 128);
        assert!(out.contains("TRUNCATED"));
        // Valid UTF-8 by construction (String), and no char was split.
        assert!(out.starts_with("café"));
    }
}
