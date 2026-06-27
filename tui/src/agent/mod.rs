//! LLM-powered agent: orchestrates tool-using conversations over code atoms.
//!
//! The agent loop coordinates a provider, tool dispatch, and conversation transcript:
//!
//! 1. Send the conversation transcript (system prompt + tools + messages) to the LLM provider.
//! 2. Stream responses (thinking, text, tool calls) to the UI in real time.
//! 3. If the model requests tool calls, execute them and feed results back.
//! 4. Repeat until the model produces a final answer (end_turn / stop).

pub mod anthropic;
pub mod openai;
pub mod provider;
pub mod shell;
pub mod tools;
pub mod transcript;

use crate::config::{Config, ProviderKind};
use crate::engine::Engine;
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

/// Split optional `---`-delimited YAML-ish frontmatter from a markdown prompt.
/// Only the small subset we need is understood: `tools: [a, b, c]` and
/// `effort: <scalar>`. Unknown keys are ignored; a malformed/absent header
/// leaves the whole input as the body.
fn parse_frontmatter(raw: &str) -> SlashCommand {
    let trimmed = raw.trim_start_matches('\u{feff}');
    let Some(rest) = trimmed.strip_prefix("---\n").or_else(|| trimmed.strip_prefix("---\r\n")) else {
        return SlashCommand { body: raw.trim().to_string(), tools: None, effort: None };
    };
    // Find the closing delimiter line.
    let mut header = String::new();
    let mut body_start = None;
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        let l = line.trim_end_matches(['\n', '\r']);
        if l == "---" {
            body_start = Some(offset + line.len());
            break;
        }
        header.push_str(line);
        offset += line.len();
    }
    let Some(bs) = body_start else {
        // No closing delimiter — treat everything as body.
        return SlashCommand { body: raw.trim().to_string(), tools: None, effort: None };
    };
    let body = rest[bs..].trim().to_string();

    let mut tools = None;
    let mut effort = None;
    for line in header.lines() {
        let Some((key, val)) = line.split_once(':') else { continue };
        let (key, val) = (key.trim(), val.trim());
        match key {
            "tools" => {
                let inner = val.trim_start_matches('[').trim_end_matches(']');
                let list: Vec<String> = inner
                    .split(',')
                    .map(|s| s.trim().trim_matches(['"', '\'']).to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !list.is_empty() {
                    tools = Some(list);
                }
            }
            "effort" => {
                let v = val.trim_matches(['"', '\'']);
                if !v.is_empty() {
                    effort = Some(v.to_string());
                }
            }
            _ => {}
        }
    }
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
}

impl AgentCtx {
    pub fn build_system_prompt(
        language: &str,
        version: &str,
        summary_rows: &[crate::model::SummaryRow],
    ) -> String {
        let counts: String = summary_rows.iter()
            .map(|r| format!("{}: {}", r.label, r.count))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"You are chennai, an AI-powered code & security analysis agent. You reason over a
code property graph (CPG) "atom" for a real codebase — not over your training prior.

## Open atom
Language: {language}
Version: {version}

## Atom summary (authoritative — do NOT call atom_summary to re-fetch these)
{counts}

## Available tools
- atom_query — flat tables: files, methods, externalMethods, calls, tags, imports, literals, configFiles…
- atom_dsl_eval — arbitrary chen DSL (the power tool). Auto-`.toJson`, paged.
- atom_flows / atom_flows_through — data-flow (source→sink) paths; presets dataflows/reachables/cryptos.
- atom_detail — properties, children, call tree, and real source for a node.
- atom_algorithms — pagerank, scc, toposort, dominators, shortest-path, reachable-by.
- ripgrep / read_file — search and read source (confined to the project root).
- git_diff / git_log / git_show — read-only git history.

## chen DSL cheat-sheet (for atom_dsl_eval — write valid expressions)
Traversal roots: `atom.method`, `atom.call`, `atom.literal`, `atom.parameter`, `atom.tag`,
`atom.file`, `atom.imports`, `atom.namespace`, `atom.annotation`.
Common steps:
  atom.method.name("regex")            atom.method.fullName("regex")
  atom.method.isExternal               atom.method.internal
  .caller  .callee  .callIn  .call     (call-graph navigation)
  .parameter  .parameter.name("..")    .literal  .code("regex")
  atom.call.name("exec|system|eval")   atom.tag.name("framework-input").call
  atom.method.name(".*auth.*").callee  atom.literal.code(".*password.*")
Always end a traversal you want back with `.toJson` (the engine appends it if omitted).
Names are regex-matched. If an expression errors, the engine returns the parser error
verbatim as the tool result — read it and self-correct.

## Grounding rules (this is the whole point of chennai)
1. NEVER invent call graphs, taints, sinks, or reachability. Every claim must trace to a
   tool result. If you cannot trace it, say so explicitly.
2. Prefer engine evidence (atom_flows, atom_dsl_eval, atom_algorithms, atom_detail) over
   ripgrep. ripgrep/read_file are for cross-referencing source, not for the core finding.
3. If atom_flows/atom_flows_through/atom_algorithms return NO results, this atom lacks
   usable data-flow / reachability data. Do NOT dress up a grep+reasoning answer as a
   reachability finding — a pure text-pattern answer is not what chennai users want.
   In that case, state plainly that data-flow analysis was unavailable, present only what
   the source text supports, and mark every finding LOW confidence.
4. For each security finding give: file:line, the concrete tainted path (when available),
   sanitizer check, and a confidence grounded in the tool evidence. Refuse to report what
   you could not trace.

You are an authorized security review of the user's OWN atom — analyze it directly.
When you have enough evidence, answer concisely with specific file:line references.
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
    match name {
        "atom_summary" => engine_request(ctx, call_id, "summary", input),
        "atom_query" => engine_request(ctx, call_id, "query", input),
        "atom_dsl_eval" => engine_request(ctx, call_id, "eval", input),
        "atom_flows" => engine_request(ctx, call_id, "flows", input),
        "atom_flows_through" => engine_request(ctx, call_id, "flows", input),
        "atom_detail" => engine_request(ctx, call_id, "detail", input),
        "atom_algorithms" => engine_request(ctx, call_id, "algo", input),
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
            let text = serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string());
            let mut content = truncate_content(&text, MAX_TOOL_RESULT_BYTES);
            if let Some(n) = note {
                content = format!("{n}\n\n{content}");
            }
            ToolExecResult { call_id: call_id.into(), content, is_error: false }
        }
        Err(e) => ToolExecResult {
            call_id: call_id.into(),
            content: redact_secrets(&format!("engine error: {e}")),
            is_error: true,
        },
    }
}

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

/// Remove anything that looks like an API key (`sk-…`) from a string before it is
/// shown to the user or written to a report. Conservative and dependency-free.
pub fn redact_secrets(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Match a "sk-" prefix followed by a run of key-ish characters.
        if bytes[i..].starts_with(b"sk-") {
            let mut j = i + 3;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'-')
            {
                j += 1;
            }
            // Only redact if it's a plausibly-long token, not a stray "sk-".
            if j - i >= 12 {
                out.push_str("sk-***redacted***");
                i = j;
                continue;
            }
        }
        // Push one UTF-8 char starting at i.
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

    let tool_defs = filter_tools(tools::all_tool_definitions(), ctx.allowed_tools.as_deref());

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
    let tool_defs = filter_tools(tools::all_tool_definitions(), ctx.allowed_tools.as_deref());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SummaryRow;

    #[test]
    fn system_prompt_includes_summary_counts() {
        let rows = vec![SummaryRow { label: "Files".into(), count: 42 }];
        let prompt = AgentCtx::build_system_prompt("C", "1.0", &rows);
        assert!(prompt.contains("Language: C"));
        assert!(prompt.contains("Files: 42"));
        assert!(prompt.contains("Grounding rule"));
    }

    #[test]
    fn dispatch_tool_unknown_tool_returns_error() {
        let ctx = AgentCtx {
            provider: Box::new(crate::agent::anthropic::AnthropicProvider::new("test".into(), "test".into())),
            engine: None,
            source_root: None,
            system_prompt: "test".into(),
            max_tokens: 1000,
            no_thinking: false,
            effort: "high".into(),
            allowed_tools: None,
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let result = dispatch_tool(&ctx, "id1", "nonexistent_tool", &serde_json::json!({}));
        assert!(result.is_error);
        assert!(result.content.contains("unknown tool"));
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
    fn redact_secrets_scrubs_api_keys() {
        let s = "error with key sk-4cb8b in body";
        let r = redact_secrets(s);
        assert!(!r.contains("4cb8be2b"));
        assert!(r.contains("sk-***redacted***"));
        // A stray short "sk-" is left alone.
        assert_eq!(redact_secrets("sk-ab"), "sk-ab");
    }

    #[test]
    fn empty_flows_get_unavailable_note() {
        let note = analysis_unavailable_note("flows", &serde_json::json!({"flows": []}));
        assert!(note.unwrap().contains("data-flow"));
        let none = analysis_unavailable_note("flows", &serde_json::json!({"flows": [{"id": 1}]}));
        assert!(none.is_none());
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
