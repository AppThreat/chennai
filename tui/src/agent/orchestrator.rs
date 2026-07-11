//! Orchestrator loop and sub-agent runner for the chennai agent.
//!
//! When `AgentCtx.orchestrate` is true, `run_agent` and `run_headless` delegate here
//! instead of running the normal monolithic agent loop. The orchestrator spawns
//! focused sub-agents (each with its own transcript and scoped toolset) and
//! synthesizes their results.

use super::finding::TokenLedger;
use super::process_note::ProcessNote;
use super::provider::{
    AgentEvent, ChannelSink, ContentBlock, EventSink, TurnRequest,
};
use super::tools::{self, spawn_subagent_tool};
use super::transcript::Transcript;
use super::{
    dispatch_tool, filter_tools, friendly_provider_error, role, AgentCtx, ToolExecResult,
    TokenLedgerSink,
};
use serde_json::Value;
use std::path::Path;
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The orchestrator system prompt — instructs the meta-controller to plan,
/// delegate to sub-agents, and synthesize results.
const ORCHESTRATOR_PROMPT: &str = include_str!("../../agents/orchestrator.md");

/// Valid sub-agent role names.
const VALID_ROLES: &[&str] = &[
    "recon",
    "sink-hunter",
    "taint-prover",
    "auth-boundary",
    "supply-chain",
    "reporter",
];

/// Hard cap on the number of sub-agents the orchestrator may spawn in a single run.
const MAX_SUBAGENTS: usize = 8;

/// The outcome of a single sub-agent run.
pub struct SubAgentResult {
    /// The sub-agent's closing text (its final synthesis), or its last words if truncated.
    pub summary: String,
    /// How many findings this sub-agent added to the shared pool.
    pub findings_delta: usize,
    /// True if the sub-agent finished on its own (reached end_turn); false if it was
    /// cut off by the `max_turns` budget or a provider error.
    pub completed: bool,
}

/// Run a single sub-agent to completion. The sub-agent shares the same `findings`,
/// `process_note`, and `token_ledger` from `ctx` but uses its own fresh `Transcript`
/// and scoped toolset.
pub fn run_subagent(
    ctx: &AgentCtx,
    role_name: &str,
    objective: &str,
    max_turns: u32,
) -> SubAgentResult {
    let findings_before = {
        let f = ctx.findings.lock().unwrap();
        f.findings.len()
    };

    let role_def = match role(role_name) {
        Some(r) => r,
        None => return SubAgentResult {
            summary: format!("Unknown role: {role_name}"),
            findings_delta: 0,
            completed: false,
        },
    };

    // Fresh transcript — never shares messages from the orchestrator or other sub-agents.
    // Seed it with the role directive, the objective, and the current shared Process Note so
    // this sub-agent builds on what earlier roles confirmed/ruled out instead of re-discovering
    // it. The note is passed by value (a snapshot); live updates still go through the tool.
    let mut transcript = Transcript::new();
    let note_text = {
        let note = ctx.process_note.lock().unwrap();
        note.render()
    };
    let mut user_msg = format!("{}\n\n## Objective\n{}", role_def.body, objective);
    if !note_text.is_empty() {
        user_msg.push_str("\n\n");
        user_msg.push_str(&note_text);
    }
    transcript.push_user(&user_msg);

    // Build toolset scoped to the role's allowlist.
    let base_tools = tools::all_tool_definitions();
    let tool_defs = filter_tools(base_tools, role_def.tools.as_deref());

    let effort: &str = role_def.effort.as_deref().unwrap_or(&ctx.effort);
    let cancel: &AtomicBool = &ctx.cancel;

    // Silent sink that discards events (sub-agents are invisible to the user).
    // Token usage is still recorded via TokenLedgerSink wrapper.
    struct SilentSink;
    impl EventSink for SilentSink {
        fn emit(&mut self, _event: AgentEvent) {}
    }

    let mut final_text = String::new();
    let mut completed = false;

    for _turn in 0..max_turns {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        // Keep the sub-agent's own context bounded on long runs, same as the top-level loops.
        transcript.compact(2);

        let mut sink = TokenLedgerSink {
            inner: SilentSink,
            ledger: ctx.token_ledger.clone(),
        };

        let result = match ctx.provider.stream_turn(
            &TurnRequest {
                system: &ctx.system_prompt,
                tools: &tool_defs,
                messages: transcript.messages(),
                max_tokens: ctx.max_tokens,
                no_thinking: ctx.no_thinking,
                effort,
                cancel,
            },
            &mut sink,
        ) {
            Ok(r) => r,
            Err(_) => break,
        };

        // The summary is the assistant's LAST text turn (its closing synthesis), not a
        // concatenation of every intermediate turn — reset per turn so only the text that
        // accompanies the final stop reaches the orchestrator.
        final_text.clear();
        for block in &result.content {
            if let ContentBlock::Text(t) = block {
                final_text.push_str(t);
            }
        }
        transcript.push_assistant(result.content);

        match result.stop_reason.as_str() {
            "end_turn" | "stop" => {
                completed = true;
                break;
            }
            "tool_use" | "tool_calls" => {
                let calls = transcript.last_tool_calls();
                if calls.is_empty() {
                    break;
                }
                let env = ctx.tool_env();
                for (call_id, name, input) in &calls {
                    let r = dispatch_tool(&env, call_id, name, input);
                    transcript.push_tool_result(&r.call_id, &r.content, r.is_error);
                }
            }
            _ => break,
        }
    }

    let findings_after = {
        let f = ctx.findings.lock().unwrap();
        f.findings.len()
    };

    SubAgentResult {
        summary: final_text,
        findings_delta: findings_after.saturating_sub(findings_before),
        completed,
    }
}

/// Build the orchestrator's tool definitions: scoped set plus spawn_subagent.
fn orchestrator_tool_definitions() -> Vec<Value> {
    let all = tools::all_tool_definitions();
    // Tools the orchestrator is allowed to use directly.
    let allowed = [
        "atom_summary",
        "atom_query",
        "bom_query",
        "project_memory",
        "process_note",
        "ripgrep",
        "read_file",
        "git_diff",
        "git_log",
        "git_show",
    ];
    let mut defs: Vec<Value> = all
        .into_iter()
        .filter(|d| {
            d.get("name")
                .and_then(Value::as_str)
                .map(|n| allowed.contains(&n))
                .unwrap_or(false)
        })
        .collect();
    // Inject spawn_subagent (not in the standard sets).
    defs.push(spawn_subagent_tool());
    defs
}

// ---------------------------------------------------------------------------
// Headless path
// ---------------------------------------------------------------------------

struct OrchestratorHeadlessSink {
    ledger: Arc<Mutex<TokenLedger>>,
}

impl EventSink for OrchestratorHeadlessSink {
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
                eprintln!("\n[ORCHESTRATOR TOOL CALL: {}({})]", name, input_str);
            }
            AgentEvent::Usage {
                input_tokens,
                output_tokens,
                cache_read_tokens,
            } => {
                if let Ok(mut ledger) = self.ledger.lock() {
                    ledger.record_usage(*input_tokens, *output_tokens, *cache_read_tokens);
                }
                eprintln!(
                    "\n[Usage: {} in / {} out / {:?} cache]",
                    input_tokens, output_tokens, cache_read_tokens
                );
            }
            AgentEvent::StopReason(r) => {
                eprintln!("\n[Stop reason: {}]", r);
            }
            _ => {}
        }
    }
}

/// Headless orchestrator runner. Reports progress to stderr, writes final
/// reports to `reports_dir`, and returns the synthesised final text.
pub fn run_orchestrator(
    ctx: &AgentCtx,
    input: &str,
    reports_dir: Option<&Path>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Load persisted Process Note so interrupted runs resume with working memory.
    {
        let persisted = ProcessNote::load(ctx.source_root.as_deref());
        if !persisted.is_empty() {
            let mut note = ctx.process_note.lock().unwrap();
            *note = persisted;
        }
    }

    let tool_defs = orchestrator_tool_definitions();
    let mut transcript = Transcript::new();
    transcript.push_user(input);
    let mut final_text = String::new();
    let mut sink = OrchestratorHeadlessSink {
        ledger: ctx.token_ledger.clone(),
    };
    let cancel: &AtomicBool = &ctx.cancel;
    let mut subagent_count = 0;

    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        transcript.compact(2);

        // Inject the Process Note as a user message updated in place.
        let note_text = {
            let note = ctx.process_note.lock().unwrap();
            note.render()
        };
        if !note_text.is_empty() {
            transcript.remove_user_messages_starting_with(Transcript::PROCESS_NOTE_PREFIX);
            transcript.push_user(&note_text);
        }

        let result = match ctx.provider.stream_turn(
            &TurnRequest {
                system: ORCHESTRATOR_PROMPT,
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
                eprintln!("\n[Error: {e}]");
                return Err(e.into());
            }
        };

        for block in &result.content {
            if let ContentBlock::Text(t) = block {
                final_text.push_str(t);
            }
        }
        transcript.push_assistant(result.content);

        match result.stop_reason.as_str() {
            "end_turn" | "stop" => break,
            "tool_use" | "tool_calls" => {
                let calls = transcript.last_tool_calls();
                if calls.is_empty() {
                    break;
                }
                let env = ctx.tool_env();
                for (call_id, name, input) in &calls {
                    if name == "spawn_subagent" {
                        let result = handle_spawn_subagent(
                            ctx, call_id, input, &mut subagent_count,
                        );
                        transcript.push_tool_result(&result.call_id, &result.content, result.is_error);
                        let preview: String = result.content.chars().take(200).collect();
                        eprintln!(
                            "\n  → spawn_subagent result ({} bytes): {}",
                            result.content.len(),
                            preview
                        );
                    } else {
                        eprintln!("\n  → executing {name}...");
                        let r = dispatch_tool(&env, call_id, name, input);
                        transcript.push_tool_result(&r.call_id, &r.content, r.is_error);
                        let preview: String = r.content.chars().take(200).collect();
                        eprintln!("  → result ({} bytes): {}", r.content.len(), preview);
                    }
                }
            }
            _ => break,
        }
    }

    // --- Post-run: write reports and print ledger summary ---
    let findings = ctx.findings.lock().unwrap();
    let total = findings.findings.len();
    let confirmed = findings.confirmed_count();

    if let Some(dir) = reports_dir
        && !findings.findings.is_empty()
    {
        let _ = std::fs::create_dir_all(dir);
        let md = findings.render_markdown();
        let _ = std::fs::write(dir.join("report.md"), &md);
        let jv = findings.render_json();
        if let Ok(json_str) = serde_json::to_string_pretty(&jv) {
            let _ = std::fs::write(dir.join("report.json"), &json_str);
        }
    }
    drop(findings);

    // --- Persist agent state for resumability ---
    {
        let note = ctx.process_note.lock().unwrap();
        let _ = note.save(ctx.source_root.as_deref());
    }
    let findings = ctx.findings.lock().unwrap();
    let _ = ProcessNote::save_findings(ctx.source_root.as_deref(), &findings);
    drop(findings);

    let ledger = ctx.token_ledger.lock().unwrap();
    eprintln!(
        "\n[{} | {} findings: {} confirmed]",
        ledger.summary(),
        total,
        confirmed
    );

    Ok(final_text)
}

// ---------------------------------------------------------------------------
// Interactive / async path
// ---------------------------------------------------------------------------

/// Async orchestrator runner for the interactive (TUI) path. Sends events through
/// the channel, mirrors the post-run lifecycle of `run_agent`.
pub fn run_orchestrator_async(
    ctx: &AgentCtx,
    user_input: &str,
    history: Vec<super::provider::Message>,
    tx: mpsc::Sender<AgentEvent>,
) {
    // Load persisted Process Note so interrupted runs resume with working memory.
    {
        let persisted = ProcessNote::load(ctx.source_root.as_deref());
        if !persisted.is_empty() {
            let mut note = ctx.process_note.lock().unwrap();
            *note = persisted;
        }
    }

    let tool_defs = orchestrator_tool_definitions();
    let mut transcript = Transcript::with_initial(history);
    transcript.push_user(user_input);
    let mut final_text = String::new();
    let mut subagent_count = 0;

    loop {
        if ctx.cancel.load(Ordering::Relaxed) {
            break;
        }

        transcript.compact(2);

        // Inject the Process Note as a user message updated in place.
        let note_text = {
            let note = ctx.process_note.lock().unwrap();
            note.render()
        };
        if !note_text.is_empty() {
            transcript.remove_user_messages_starting_with(Transcript::PROCESS_NOTE_PREFIX);
            transcript.push_user(&note_text);
        }

        let mut sink = TokenLedgerSink {
            inner: ChannelSink(tx.clone()),
            ledger: ctx.token_ledger.clone(),
        };
        let result = match ctx.provider.stream_turn(
            &TurnRequest {
                system: ORCHESTRATOR_PROMPT,
                tools: &tool_defs,
                messages: transcript.messages(),
                max_tokens: ctx.max_tokens,
                no_thinking: ctx.no_thinking,
                effort: &ctx.effort,
                cancel: &ctx.cancel,
            },
            &mut sink,
        ) {
            Ok(r) => r,
            Err(e) => {
                tx.send(AgentEvent::Error(friendly_provider_error(&e))).ok();
                break;
            }
        };

        for block in &result.content {
            if let ContentBlock::Text(t) = block {
                final_text.push_str(t);
            }
        }
        transcript.push_assistant(result.content);

        match result.stop_reason.as_str() {
            "end_turn" | "stop" => {
                break;
            }
            "refusal" => {
                tx.send(AgentEvent::Error(
                    "The model declined this request. Security-adjacent prompts can trip a \
                     safety classifier even for legitimate review — try rephrasing."
                        .into(),
                ))
                .ok();
                break;
            }
            "tool_use" | "tool_calls" => {
                let tool_calls = transcript.last_tool_calls();
                if tool_calls.is_empty() {
                    tx.send(AgentEvent::Error("model requested tools but none found".into()))
                        .ok();
                    break;
                }

                // Execute tool calls.
                let env = ctx.tool_env();
                let mut results: Vec<ToolExecResult> = Vec::new();

                // spawn_subagent must be handled sequentially (it runs a full sub-agent loop).
                // Other tools can be dispatched sequentially too (simpler, and engine serializes
                // anyway).
                for (call_id, name, input) in &tool_calls {
                    if name == "spawn_subagent" {
                        tx.send(AgentEvent::ToolCall {
                            id: call_id.clone(),
                            name: name.clone(),
                            input: input.clone(),
                        })
                        .ok();
                        let result = handle_spawn_subagent(
                            ctx, call_id, input, &mut subagent_count,
                        );
                        tx.send(AgentEvent::ToolResult {
                            id: result.call_id.clone(),
                            content: result.content.clone(),
                            is_error: result.is_error,
                        })
                        .ok();
                        results.push(result);
                    } else {
                        let r = dispatch_tool(&env, call_id, name, input);
                        tx.send(AgentEvent::ToolResult {
                            id: r.call_id.clone(),
                            content: r.content.clone(),
                            is_error: r.is_error,
                        })
                        .ok();
                        results.push(r);
                    }
                }

                for result in &results {
                    transcript.push_tool_result(&result.call_id, &result.content, result.is_error);
                }
            }
            _ => break,
        }
    }

    // Persist agent state for resumability.
    {
        let note = ctx.process_note.lock().unwrap();
        let _ = note.save(ctx.source_root.as_deref());
    }
    {
        let findings = ctx.findings.lock().unwrap();
        let _ = ProcessNote::save_findings(ctx.source_root.as_deref(), &findings);
    }

    tx.send(AgentEvent::History(transcript.messages().to_vec())).ok();
    tx.send(AgentEvent::Done).ok();
}

// ---------------------------------------------------------------------------
// spawn_subagent handler (shared between headless and async paths)
// ---------------------------------------------------------------------------

/// Handle a `spawn_subagent` tool call. Validates the role, enforces the
/// sub-agent cap, calls `run_subagent`, and returns a `ToolExecResult` with
/// the summary and findings delta.
fn handle_spawn_subagent(
    ctx: &AgentCtx,
    call_id: &str,
    input: &Value,
    subagent_count: &mut usize,
) -> ToolExecResult {
    let role = input.get("role").and_then(Value::as_str).unwrap_or("");
    let objective = input.get("objective").and_then(Value::as_str).unwrap_or("");
    let max_turns = input
        .get("max_turns")
        .and_then(Value::as_u64)
        .unwrap_or(10) as u32;

    // Validate role.
    if !VALID_ROLES.contains(&role) {
        let valid = VALID_ROLES.join(", ");
        return ToolExecResult {
            call_id: call_id.into(),
            content: format!(
                "Unknown role '{role}'. Valid roles: {valid}. Use a recognized role name."
            ),
            is_error: true,
        };
    }

    // Enforce sub-agent cap.
    if *subagent_count >= MAX_SUBAGENTS {
        return ToolExecResult {
            call_id: call_id.into(),
            content: format!(
                "Sub-agent cap ({MAX_SUBAGENTS}) reached. Cannot spawn another."
            ),
            is_error: true,
        };
    }

    *subagent_count += 1;
    let SubAgentResult { summary, findings_delta, completed } =
        run_subagent(ctx, role, objective, max_turns);
    // Tell the orchestrator whether this was a real conclusion or a truncated run, so it does
    // not mistake a dangling mid-investigation sentence for a finished summary. Either way the
    // sub-agent's work is preserved in the shared Process Note and findings pool.
    let status = if completed {
        format!("[Sub-agent '{role}' completed — {findings_delta} findings added]")
    } else {
        format!(
            "[Sub-agent '{role}' ran out of its {max_turns}-turn budget before concluding — \
             {findings_delta} findings added. Its progress is in the shared Process Note; \
             spawn it again with a narrower objective to continue.]"
        )
    };
    let content = if summary.trim().is_empty() {
        status
    } else {
        format!("{summary}\n\n{status}")
    };
    ToolExecResult {
        call_id: call_id.into(),
        content,
        is_error: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::finding::{FindingSet, TokenLedger};
    use crate::agent::process_note::ProcessNote;
    use crate::agent::provider::{LlmProvider, TurnResult};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // Mock provider that returns a fixed sequence of responses.
    // -----------------------------------------------------------------------
    struct MockProvider {
        /// Sequence of (stop_reason, content_text_or_tool_calls) to return.
        turns: Vec<(String, Vec<crate::agent::provider::ContentBlock>)>,
        index: std::sync::Mutex<usize>,
    }

    impl MockProvider {
        fn new(turns: Vec<(&str, Vec<crate::agent::provider::ContentBlock>)>) -> Self {
            MockProvider {
                turns: turns
                    .into_iter()
                    .map(|(s, c)| (s.to_string(), c))
                    .collect(),
                index: std::sync::Mutex::new(0),
            }
        }
    }

    impl super::super::provider::LlmProvider for MockProvider {
        fn stream_turn(
            &self,
            _req: &TurnRequest,
            sink: &mut dyn EventSink,
        ) -> Result<TurnResult, super::super::provider::ProviderError> {
            let mut idx = self.index.lock().unwrap();
            if *idx >= self.turns.len() {
                // Return end_turn if we've exhausted the sequence.
                return Ok(TurnResult {
                    content: vec![],
                    stop_reason: "end_turn".into(),
                    usage: None,
                });
            }
            let (stop_reason, blocks) = self.turns[*idx].clone();
            *idx += 1;
            // Emit text delta events for text blocks.
            for block in &blocks {
                if let ContentBlock::Text(t) = block {
                    sink.emit(AgentEvent::TextDelta(t.clone()));
                }
                if let ContentBlock::ToolUse { id, name, input } = block {
                    sink.emit(AgentEvent::ToolCall {
                        id: id.clone(),
                        name: name.clone(),
                        input: input.clone(),
                    });
                }
            }
            Ok(TurnResult {
                content: blocks,
                stop_reason,
                usage: Some((100, 50)),
            })
        }
    }

    fn make_ctx(provider: Box<dyn LlmProvider + Send + Sync>) -> AgentCtx {
        AgentCtx {
            provider,
            engine: None,
            backend: None,
            source_root: None,
            system_prompt: "You are chennai, a security analysis agent.".into(),
            max_tokens: 1000,
            no_thinking: true,
            effort: "high".into(),
            allowed_tools: None,
            orchestrate: false,
            cancel: Arc::new(AtomicBool::new(false)),
            debug_logger: None,
            findings: Arc::new(Mutex::new(FindingSet::new())),
            token_ledger: Arc::new(Mutex::new(TokenLedger::default())),
            process_note: Arc::new(Mutex::new(ProcessNote::default())),
        }
    }

    // -----------------------------------------------------------------------
    // run_subagent max_turns test
    // -----------------------------------------------------------------------

    #[test]
    fn subagent_obeys_max_turns() {
        // Each turn returns a tool_use (the sub-agent keeps calling tools).
        let provider = MockProvider::new(vec![
            ("tool_use", vec![ContentBlock::ToolUse {
                id: "tu_1".into(), name: "atom_query".into(), input: serde_json::json!({"kind": "files"}),
            }]),
            ("tool_use", vec![ContentBlock::ToolUse {
                id: "tu_2".into(), name: "process_note".into(), input: serde_json::json!({"action": "get"}),
            }]),
            ("tool_use", vec![ContentBlock::ToolUse {
                id: "tu_3".into(), name: "atom_summary".into(), input: serde_json::json!({}),
            }]),
        ]);
        let ctx = make_ctx(Box::new(provider));

        // max_turns=2 → should only run 2 turns, then stop.
        let res = run_subagent(&ctx, "recon", "Map the codebase", 2);
        // The third turn never runs, so the sub-agent returns what it has (empty in this test).
        assert_eq!(res.findings_delta, 0);
        // The summary should be empty since no end_turn was reached.
        assert!(res.summary.is_empty());
        // It was cut off by the budget, not a natural conclusion.
        assert!(!res.completed, "hitting max_turns must be reported as not completed");
    }

    #[test]
    fn subagent_stops_on_end_turn() {
        let provider = MockProvider::new(vec![
            ("end_turn", vec![ContentBlock::Text("Summary: found 3 entrypoints".into())]),
        ]);
        let ctx = make_ctx(Box::new(provider));
        let res = run_subagent(&ctx, "recon", "Recon", 10);
        assert!(res.summary.contains("found 3 entrypoints"));
        assert_eq!(res.findings_delta, 0);
        assert!(res.completed, "reaching end_turn must be reported as completed");
    }

    // -----------------------------------------------------------------------
    // Unknown role and subagent cap
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_role_rejected_with_helpful_error() {
        let input = serde_json::json!({"role": "nonexistent", "objective": "test"});
        let ctx = make_ctx(Box::new(MockProvider::new(vec![])));
        let mut count = 0;
        let result = handle_spawn_subagent(&ctx, "call_1", &input, &mut count);
        assert!(result.is_error);
        assert!(result.content.contains("Unknown role"));
        assert!(result.content.contains("Valid roles"));
        // Count should not increment for unknown roles.
        assert_eq!(count, 0);
    }

    #[test]
    fn subagent_cap_enforced() {
        let ctx = make_ctx(Box::new(MockProvider::new(vec![
            ("end_turn", vec![ContentBlock::Text("done".into())]),
        ])));
        let mut count = 8; // already at cap
        let input = serde_json::json!({"role": "recon", "objective": "test"});
        let result = handle_spawn_subagent(&ctx, "call_1", &input, &mut count);
        assert!(result.is_error);
        assert!(result.content.contains("cap"));
        assert_eq!(count, 8); // unchanged
    }

    // -----------------------------------------------------------------------
    // Thinking-signature isolation assertion
    // -----------------------------------------------------------------------

    #[test]
    fn orchestrator_transcript_never_contains_subagent_thinking() {
        // The orchestrator calls spawn_subagent; the sub-agent returns a summary
        // as a ToolResult (text). No Thinking/RedactedThinking blocks from the
        // sub-agent's transcript should ever appear in the orchestrator's transcript.
        //
        // We simulate an orchestrator that:
        // 1. Calls spawn_subagent
        // 2. Gets back the result
        // 3. Ends
        let provider = MockProvider::new(vec![
            // Orchestrator turn: calls spawn_subagent
            ("tool_use", vec![ContentBlock::ToolUse {
                id: "tu_1".into(),
                name: "spawn_subagent".into(),
                input: serde_json::json!({"role": "recon", "objective": "map it"}),
            }]),
            // Orchestrator second turn: ends
            ("end_turn", vec![ContentBlock::Text("Synthesis: done.".into())]),
        ]);
        let ctx = make_ctx(Box::new(provider));

        // Run the async path (collect events).
        let (tx, rx) = mpsc::channel();
        run_orchestrator_async(&ctx, "Analyze this code.", vec![], tx);

        // After the run, the orchestrator transcript should have been sent as History.
        // Verify contents: only user input, spawn_subagent tool call/result, and
        // final synthesis. NO Thinking/RedactedThinking blocks.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let events: Vec<AgentEvent> = rx.try_iter().collect();
        let history = events.iter().find_map(|e| {
            if let AgentEvent::History(h) = e {
                Some(h.clone())
            } else {
                None
            }
        });
        assert!(history.is_some(), "History event should have been sent");
        let history = history.unwrap();

        // No message in the orchestrator transcript should have Thinking or RedactedThinking.
        for msg in &history {
            for block in &msg.content {
                match block {
                    ContentBlock::Thinking { .. } => {
                        panic!("Orchestrator transcript contains a Thinking block from a sub-agent!")
                    }
                    ContentBlock::RedactedThinking { .. } => {
                        panic!("Orchestrator transcript contains a RedactedThinking block from a sub-agent!")
                    }
                    _ => {}
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Orchestrator with spawn_subagent returns summary
    // -----------------------------------------------------------------------

    #[test]
    fn orchestrator_gets_subagent_summary_not_transcript() {
        // The orchestrator calls spawn_subagent. The sub-agent runs and produces
        // a text summary. The orchestrator receives only that summary (plain text),
        // never the sub-agent's internal transcript.
        let provider = MockProvider::new(vec![
            // Turn 1: orchestrator calls spawn_subagent with role "recon"
            ("tool_use", vec![ContentBlock::ToolUse {
                id: "tu_spawn".into(),
                name: "spawn_subagent".into(),
                input: serde_json::json!({"role": "recon", "objective": "map entrypoints"}),
            }]),
            // Turn 2: orchestrator ends
            ("end_turn", vec![ContentBlock::Text("Analysis complete.".into())]),
        ]);
        let ctx = make_ctx(Box::new(provider));
        let (tx, rx) = mpsc::channel();
        run_orchestrator_async(&ctx, "Security audit", vec![], tx);

        // The orchestrator should receive the sub-agent's plain-text summary (plus the findings
        // tally), never its internal transcript. The recon sub-agent here ends immediately with
        // no text, so the result is just the completion tally — assert on that exact shape.
        let events: Vec<AgentEvent> = rx.try_iter().collect();
        let spawn_result = events.iter().find_map(|e| match e {
            AgentEvent::ToolResult { id, content, is_error } if id == "tu_spawn" => {
                Some((content.clone(), *is_error))
            }
            _ => None,
        });
        let (content, is_error) = spawn_result.expect("spawn_subagent should produce a ToolResult");
        assert!(!is_error, "recon sub-agent should complete without error");
        assert!(
            content.contains("Sub-agent 'recon' completed"),
            "orchestrator should receive the summary/tally, got: {content}"
        );
        // The orchestrator must never see sub-agent tool-call plumbing in its result.
        assert!(!content.contains("atom_query"), "sub-agent transcript leaked into result");
    }
}
