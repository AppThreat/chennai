//! Orchestrator loop and sub-agent runner for the chennai agent.
//!
//! When `AgentCtx.orchestrate` is true, `run_agent` and `run_headless` delegate here
//! instead of running the normal monolithic agent loop. The orchestrator spawns
//! focused sub-agents (each with its own transcript and scoped toolset) and
//! synthesizes their results.
//!
//! Each sub-agent run is timed and profiled: token deltas and wall-clock durations
//! are recorded in the shared [`RunProfile`] for visibility during and after the run.

use super::finding::{format_duration, LedgerDelta, ProfileSegment, TokenLedger};
use super::process_note::ProcessNote;
use super::provider::{
    AgentEvent, ChannelSink, ContentBlock, EventSink, TurnRequest,
};
use super::roles::{self, OrchestrateManifest};
use super::tools::{self, spawn_subagent_tool};
use super::transcript::Transcript;
use super::{
    dispatch_tool, filter_tools, friendly_provider_error, resolve_turn_budget, AgentCtx,
    ToolExecResult, TokenLedgerSink,
};
use serde_json::Value;
use std::path::Path;
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The built-in orchestrator system prompt (used when no project-local or
/// manifest override exists). The `{{ROLES_SECTION}}` placeholder is replaced
/// at runtime with the dynamically discovered role menu.
const ORCHESTRATOR_PROMPT_TEMPLATE: &str = include_str!("../../agents/orchestrator.md");

/// Resolve the effective orchestrator system prompt for a given project.
///
/// Precedence: manifest `orchestrator_prompt` file → built-in template with
/// dynamic role substitution. The `{{ROLES_SECTION}}` placeholder in the
/// built-in template is replaced with the discovered roles section.
fn build_orchestrator_prompt(base: &Path, manifest: &OrchestrateManifest, discovered_names: &[String]) -> String {
    // Check for a project-specific orchestrator prompt override. The path comes
    // from the repo-local manifest (attacker-influenceable), so it must stay
    // within the project tree — reject absolute paths and `..` traversal.
    if let Some(ref prompt_path) = manifest.orchestrator_prompt {
        let rel = Path::new(prompt_path);
        let safe = !rel.is_absolute()
            && !rel.components().any(|c| matches!(c, std::path::Component::ParentDir));
        if safe {
            let full_path = base.join(rel);
            if let Ok(content) = std::fs::read_to_string(&full_path) {
                // Substitute the roles section even in custom prompts.
                let roles_section = roles::build_roles_section(base, Some(discovered_names));
                return content.replace("{{ROLES_SECTION}}", &roles_section);
            }
        }
    }

    // Built-in template with dynamic role substitution.
    let roles_section = roles::build_roles_section(base, Some(discovered_names));
    ORCHESTRATOR_PROMPT_TEMPLATE.replace("{{ROLES_SECTION}}", &roles_section)
}

/// Effective orchestration budgets after applying the project manifest.
///
/// The manifest may only *tighten* the caps supplied on the command line / env
/// (via `min`), never loosen them — a repo-local file must not be able to raise
/// your sub-agent count or token spend. The token budget is additionally
/// clamped to [`roles::TOKEN_BUDGET_CEILING`].
struct EffectiveBudgets {
    max_subagents: usize,
    turn_budget: u64,
    token_budget: u64,
}

/// Resolve the effective budgets from the ctx (CLI/env) and the project manifest.
fn effective_budgets(ctx: &AgentCtx, manifest: &OrchestrateManifest) -> EffectiveBudgets {
    let max_subagents = manifest
        .max_subagents
        .map_or(ctx.max_subagents, |m| m.min(ctx.max_subagents));
    let turn_budget = manifest
        .turn_budget
        .map_or(ctx.turn_budget, |m| m.min(ctx.turn_budget));
    let token_budget = manifest
        .token_budget
        .map_or(ctx.token_budget, |m| m.min(ctx.token_budget))
        .min(roles::TOKEN_BUDGET_CEILING);
    EffectiveBudgets { max_subagents, turn_budget, token_budget }
}

/// The outcome of a single sub-agent run.
pub struct SubAgentResult {
    /// The sub-agent's closing text (its final synthesis), or its last words if truncated.
    pub summary: String,
    /// How many findings this sub-agent added to the shared pool.
    pub findings_delta: usize,
    /// True if the sub-agent finished on its own (reached end_turn); false if it was
    /// cut off by the `max_turns` budget or a provider error.
    pub completed: bool,
    /// Token and turn difference consumed by this sub-agent.
    pub tokens: LedgerDelta,
    /// Wall-clock time spent on this sub-agent.
    pub elapsed: std::time::Duration,
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
    let base = ctx.source_root.as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let findings_before = {
        let f = ctx.findings.lock().unwrap();
        f.findings.len()
    };

    // Snapshot the shared token ledger before this sub-agent runs so we can
    // attribute the token consumption to this segment.
    let ledger_before = {
        let ledger = ctx.token_ledger.lock().unwrap();
        ledger.snapshot()
    };

    let start = Instant::now();

    let role_def = match roles::resolve_role(&base, role_name) {
        Some(r) => r,
        None => return SubAgentResult {
            summary: format!("Unknown role: {role_name}"),
            findings_delta: 0,
            completed: false,
            tokens: LedgerDelta::default(),
            elapsed: start.elapsed(),
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

    let elapsed = start.elapsed();

    // Compute the token delta for this sub-agent segment.
    let tokens = {
        let ledger = ctx.token_ledger.lock().unwrap();
        ledger.delta_since(&ledger_before)
    };

    SubAgentResult {
        summary: final_text,
        findings_delta: findings_after.saturating_sub(findings_before),
        completed,
        tokens,
        elapsed,
    }
}

/// Record a synthetic driver segment capturing the coordinator's own token
/// and wall-clock usage: the whole-run totals minus the sum of the sub-agent
/// segments already recorded. This reconciles the profile's TOTAL row with the
/// token ledger summary — without it, the orchestrator's own planning/synthesis
/// turns would be invisible in the profile. No-op when the coordinator consumed
/// nothing.
///
/// `label` names the segment (e.g. `"orchestrator"`, `"audit-driver"`).
fn record_orchestrator_segment(ctx: &AgentCtx, run_start: Instant, label: &str) {
    let (total_input, total_output, total_cache, total_turns) = {
        let l = ctx.token_ledger.lock().unwrap();
        (l.input, l.output, l.cache_read, l.turns)
    };
    let mut profile = ctx.run_profile.lock().unwrap();
    let sub_input: u64 = profile.segments.iter().map(|s| s.tokens.input).sum();
    let sub_output: u64 = profile.segments.iter().map(|s| s.tokens.output).sum();
    let sub_cache: u64 = profile.segments.iter().map(|s| s.tokens.cache_read).sum();
    let sub_turns: u64 = profile.segments.iter().map(|s| s.turns).sum();
    let sub_elapsed = profile.total_elapsed();

    let tokens = LedgerDelta {
        input: total_input.saturating_sub(sub_input),
        output: total_output.saturating_sub(sub_output),
        cache_read: total_cache.saturating_sub(sub_cache),
        turns: total_turns.saturating_sub(sub_turns),
    };
    if tokens.turns == 0 && tokens.total_tokens() == 0 {
        return;
    }
    // Sub-agents run sequentially while the orchestrator blocks, so its own
    // wall-clock time is the run duration minus time spent inside sub-agents.
    let elapsed = run_start.elapsed().saturating_sub(sub_elapsed);
    profile.push_segment(ProfileSegment {
        label: label.into(),
        tokens,
        elapsed,
        turns: tokens.turns,
        findings_delta: 0,
        completed: true,
    });
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

    // Build the orchestrator prompt with the dynamically discovered role menu.
    let base = ctx.source_root.as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let manifest = roles::load_manifest(&base);
    let discovered_names: Vec<String> = if let Some(ref subset) = manifest.roles {
        subset.clone()
    } else {
        roles::discover_roles(&base).keys().cloned().collect()
    };
    let system_prompt = build_orchestrator_prompt(&base, &manifest, &discovered_names);

    let tool_defs = orchestrator_tool_definitions();
    let mut transcript = Transcript::new();
    transcript.push_user(input);
    let mut final_text = String::new();
    let mut sink = OrchestratorHeadlessSink {
        ledger: ctx.token_ledger.clone(),
    };
    let cancel: &AtomicBool = &ctx.cancel;
    let mut subagent_count = 0;
    let run_start = Instant::now();
    // On a mid-run provider error we still persist whatever was gathered (Process
    // Note, findings, profile) so an interrupted run stays resumable, then surface
    // the error to the caller after the post-run bookkeeping below.
    let mut run_error: Option<Box<dyn std::error::Error>> = None;

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
                system: &system_prompt,
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
                run_error = Some(e.into());
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
                            ctx, call_id, input, &mut subagent_count, None,
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

    // --- Post-run: write reports, persist state, reconcile profile ---
    // (Extracted into finalize_run so the headless single-agent path and the
    // audit subcommand share the same deadlock-safe bookkeeping sequence.)
    finalize_run(ctx, run_start, reports_dir, Some("orchestrator"));

    // Surface a mid-run error only after state has been persisted above.
    if let Some(e) = run_error {
        return Err(e);
    }
    Ok(final_text)
}

/// Shared post-run bookkeeping: write reports, persist agent state, print the
/// ledger summary, record the synthetic driver/orchestrator segment, and save
/// the run profile. Called from `run_orchestrator`, `run_headless` (single-agent),
/// and `audit::run_audit`.
///
/// `driver_label` is the label for the synthetic segment that captures overhead
/// not attributable to any sub-agent (e.g. `"orchestrator"`, `"audit-driver"`,
/// `None` for flat single-agent runs where no segment is needed).
///
/// All mutex scopes are kept narrow and released before the next lock is
/// acquired — std Mutex is not reentrant and a prior version deadlocked the
/// headless path exactly this way.
pub fn finalize_run(
    ctx: &AgentCtx,
    run_start: Instant,
    reports_dir: Option<&Path>,
    driver_label: Option<&str>,
) {
    finalize_run_with_options(ctx, run_start, reports_dir, driver_label, false)
}

/// Like [`finalize_run`] but exposes the `include_low_value` toggle that
/// controls whether low-confidence/unreachable findings appear in report.md.
/// `report.json` always includes ALL findings regardless.
pub fn finalize_run_with_options(
    ctx: &AgentCtx,
    run_start: Instant,
    reports_dir: Option<&Path>,
    driver_label: Option<&str>,
    include_low_value: bool,
) {
    // --- Write reports ---
    let (total, confirmed) = {
        let findings = ctx.findings.lock().unwrap();
        let t = findings.findings.len();
        let c = findings.confirmed_count();

        if let Some(dir) = reports_dir
            && !findings.findings.is_empty()
        {
            let _ = std::fs::create_dir_all(dir);
            let md = findings.render_markdown_filtered(include_low_value);
            let _ = std::fs::write(dir.join("report.md"), &md);
            let jv = findings.render_json();
            if let Ok(json_str) = serde_json::to_string_pretty(&jv) {
                let _ = std::fs::write(dir.join("report.json"), &json_str);
            }
        }
        (t, c)
    }; // findings lock released here

    // --- Persist Process Note ---
    {
        let note = ctx.process_note.lock().unwrap();
        let _ = note.save(ctx.source_root.as_deref());
    } // note lock released here

    // --- Persist findings ---
    {
        let findings = ctx.findings.lock().unwrap();
        let _ = ProcessNote::save_findings(ctx.source_root.as_deref(), &findings);
    } // findings lock released here

    // --- Print ledger summary ---
    {
        let ledger = ctx.token_ledger.lock().unwrap();
        eprintln!(
            "\n[{} | {} findings: {} confirmed]",
            ledger.summary(),
            total,
            confirmed
        );
    } // ledger lock released here

    // --- Record synthetic driver segment + persist profile ---
    // (The ledger lock above MUST be released first: the segment recorder
    // re-locks the ledger, and std Mutex is not reentrant.)
    if let Some(label) = driver_label {
        record_orchestrator_segment(ctx, run_start, label);
    }

    {
        let profile = ctx.run_profile.lock().unwrap();
        let report = profile.render_report();
        if !report.is_empty() {
            eprintln!("{report}");
        }
        let _ = profile.save(ctx.source_root.as_deref());
    } // profile lock released here
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

    // Build the orchestrator prompt with the dynamically discovered role menu.
    let base = ctx.source_root.as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let manifest = roles::load_manifest(&base);
    let discovered_names: Vec<String> = if let Some(ref subset) = manifest.roles {
        subset.clone()
    } else {
        roles::discover_roles(&base).keys().cloned().collect()
    };
    let system_prompt = build_orchestrator_prompt(&base, &manifest, &discovered_names);

    let tool_defs = orchestrator_tool_definitions();
    let mut transcript = Transcript::with_initial(history);
    transcript.push_user(user_input);
    let mut final_text = String::new();
    let mut subagent_count = 0;
    let run_start = Instant::now();

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
                system: &system_prompt,
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
                            ctx, call_id, input, &mut subagent_count, Some(&tx),
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
    record_orchestrator_segment(ctx, run_start, "orchestrator");
    {
        let profile = ctx.run_profile.lock().unwrap();
        let _ = profile.save(ctx.source_root.as_deref());
    }

    tx.send(AgentEvent::History(transcript.messages().to_vec())).ok();
    tx.send(AgentEvent::Done).ok();
}

// ---------------------------------------------------------------------------
// spawn_subagent handler (shared between headless and async paths)
// ---------------------------------------------------------------------------

/// Handle a `spawn_subagent` tool call. Validates the role, enforces the
/// sub-agent cap, resolves the effective turn budget, calls `run_subagent`,
/// records the segment in the shared `RunProfile`, checks global advisory budgets,
/// and returns a `ToolExecResult` with the summary, findings delta, and any
/// budget advisories.
///
/// `profile_tx` is an optional event sender for live profile updates in the
/// interactive TUI path. In headless mode, pass `None` (profile lines are
/// returned in the `ToolExecResult` for the caller to print).
fn handle_spawn_subagent(
    ctx: &AgentCtx,
    call_id: &str,
    input: &Value,
    subagent_count: &mut usize,
    profile_tx: Option<&mpsc::Sender<AgentEvent>>,
) -> ToolExecResult {
    let role_name = input.get("role").and_then(Value::as_str).unwrap_or("");
    let objective = input.get("objective").and_then(Value::as_str).unwrap_or("");
    let requested_turns = input.get("max_turns").and_then(Value::as_u64).map(|n| n as u32);

    // Validate role against the dynamically discovered set.
    let base = ctx.source_root.as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let manifest = roles::load_manifest(&base);
    let budgets = effective_budgets(ctx, &manifest);
    let discovered = roles::discover_roles(&base);
    if !discovered.contains_key(role_name) {
        let valid_str: String = discovered.keys().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
        return ToolExecResult {
            call_id: call_id.into(),
            content: format!(
                "Unknown role '{role_name}'. Valid roles: {valid_str}. Use a recognized role name."
            ),
            is_error: true,
        };
    }

    // Enforce hard sub-agent cap.
    if *subagent_count >= budgets.max_subagents {
        return ToolExecResult {
            call_id: call_id.into(),
            content: format!(
                "Sub-agent cap ({}) reached. Cannot spawn another.",
                budgets.max_subagents
            ),
            is_error: true,
        };
    }

    // Resolve the effective turn budget: model request → frontmatter → role default,
    // clamped by HARD_TURN_CEILING.
    let frontmatter_max_turns = roles::resolve_role(&base, role_name).and_then(|r| r.max_turns);
    let effective_turns = resolve_turn_budget(requested_turns, role_name, frontmatter_max_turns);

    // Check global advisory budgets BEFORE spawning. If either soft budget is already
    // exceeded, the sub-agent is still spawned but the orchestrator receives a warning.
    let budget_notice = check_advisory_budgets(ctx, &budgets, role_name, *subagent_count);

    *subagent_count += 1;

    let SubAgentResult {
        summary,
        findings_delta,
        completed,
        tokens,
        elapsed,
    } = run_subagent(ctx, role_name, objective, effective_turns);

    // Build a label with the sub-agent index for disambiguation when the same
    // role is spawned multiple times.
    let label = if *subagent_count > 1 {
        format!("{role_name} #{subagent_count}")
    } else {
        role_name.to_string()
    };

    // Record this segment in the shared RunProfile.
    let profile_line = {
        let mut profile = ctx.run_profile.lock().unwrap();
        profile.push_segment(ProfileSegment {
            label: label.clone(),
            tokens,
            elapsed,
            turns: tokens.turns,
            findings_delta,
            completed,
        });

        // Format a compact live profile line for the console.
        let totals_tok = profile.total_tokens();
        let totals_turns = profile.total_turns();
        let totals_time = profile.total_elapsed();
        format!(
            "[profile] {}: {} · {} · {} | run total: {} tok · {} turns · {}",
            label,
            tokens.token_summary(),
            tokens.turn_summary(),
            format_duration(elapsed),
            LedgerDelta::format_tokens(totals_tok),
            totals_turns,
            format_duration(totals_time),
        )
    };

    // Emit the profile line via AgentEvent::Profile for the interactive TUI path.
    // The headless path prints this directly to stderr below.
    if let Some(tx) = profile_tx {
        let _ = tx.send(AgentEvent::Profile(profile_line.clone()));
    }

    // Tell the orchestrator whether this was a real conclusion or a truncated run.
    let status = if completed {
        format!("[Sub-agent '{role_name}' completed — {findings_delta} findings added]")
    } else {
        format!(
            "[Sub-agent '{role_name}' ran out of its {effective_turns}-turn budget before concluding — \
             {findings_delta} findings added. Its progress is in the shared Process Note; \
             spawn it again with a narrower objective to continue.]"
        )
    };

    // Assemble the result content, appending budget notice if applicable.
    let mut content = if summary.trim().is_empty() {
        status
    } else {
        format!("{summary}\n\n{status}")
    };
    if let Some(notice) = &budget_notice {
        content.push_str("\n\n");
        content.push_str(notice);
    }

    ToolExecResult {
        call_id: call_id.into(),
        content,
        is_error: false,
    }
}

/// Check global advisory (soft) budgets against the shared token ledger totals.
/// Returns a warning message if either the turn budget or token budget has been
/// exceeded, or `None` if both are within limits. The sub-agent is always spawned
/// regardless — these budgets are advisory only.
fn check_advisory_budgets(ctx: &AgentCtx, budgets: &EffectiveBudgets, role_name: &str, subagent_count: usize) -> Option<String> {
    let (turns, tokens) = {
        let ledger = ctx.token_ledger.lock().unwrap();
        (ledger.turns, ledger.total_tokens())
    };
    let turn_exceeded = turns >= budgets.turn_budget;
    let token_exceeded = tokens >= budgets.token_budget;

    if turn_exceeded || token_exceeded {
        let mut parts = Vec::new();
        if turn_exceeded {
            parts.push(format!("{}/{} turns", turns, budgets.turn_budget));
        }
        if token_exceeded {
            parts.push(format!(
                "{} tokens",
                LedgerDelta::format_tokens(tokens)
            ));
        }
        let message = format!(
            "[budget notice: run has used {} and is over the advisory budget — \
             consider spawning the reporter to wrap up]",
            parts.join(" and "),
        );
        // Record the warning in the profile for the end-of-run summary.
        {
            let mut profile = ctx.run_profile.lock().unwrap();
            profile.push_budget_warning(format!("before spawning '{}' (sub-agent #{}): {}", role_name, subagent_count + 1, message.trim_start_matches('[').trim_end_matches(']')));
        }
        Some(message)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::finding::{FindingSet, RunProfile, TokenLedger};
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
            // Emit text delta and tool call events.
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
            // Emit a Usage event so TokenLedgerSink records the token count.
            sink.emit(AgentEvent::Usage {
                input_tokens: 100,
                output_tokens: 50,
                cache_read_tokens: Some(10),
            });
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
            run_profile: Arc::new(Mutex::new(RunProfile::new())),
            max_subagents: 8,
            turn_budget: 80,
            token_budget: 256_000,
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
        let result = handle_spawn_subagent(&ctx, "call_1", &input, &mut count, None);
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
        let result = handle_spawn_subagent(&ctx, "call_1", &input, &mut count, None);
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

    // -----------------------------------------------------------------------
    // SubAgentResult includes timing and token delta
    // -----------------------------------------------------------------------

    #[test]
    fn subagent_result_includes_token_delta_and_elapsed() {
        let provider = MockProvider::new(vec![
            ("end_turn", vec![ContentBlock::Text("Done.".into())]),
        ]);
        let ctx = make_ctx(Box::new(provider));
        let res = run_subagent(&ctx, "recon", "Recon", 10);
        assert!(res.completed);
        // MockProvider emits usage (100, 50) per turn, so we expect 1 turn recorded.
        assert_eq!(res.tokens.input, 100);
        assert_eq!(res.tokens.output, 50);
        assert_eq!(res.tokens.turns, 1);
        assert!(!res.elapsed.is_zero(), "elapsed time should be non-zero after a run");
    }

    // -----------------------------------------------------------------------
    // Profile segment recording
    // -----------------------------------------------------------------------

    #[test]
    fn handle_spawn_records_profile_segment() {
        let provider = MockProvider::new(vec![
            ("end_turn", vec![ContentBlock::Text("Recon done.".into())]),
        ]);
        let ctx = make_ctx(Box::new(provider));
        let mut count = 0;
        let input = serde_json::json!({"role": "recon", "objective": "map it"});
        let result = handle_spawn_subagent(&ctx, "call_1", &input, &mut count, None);
        assert!(!result.is_error);
        assert_eq!(count, 1);

        // Profile should have one segment for the recon sub-agent.
        let profile = ctx.run_profile.lock().unwrap();
        assert_eq!(profile.segments.len(), 1);
        assert_eq!(profile.segments[0].label, "recon");
        assert_eq!(profile.segments[0].findings_delta, 0);
        assert!(profile.segments[0].completed);
        assert_eq!(profile.segments[0].tokens.total_tokens(), 160);
        assert!(profile.segments[0].tokens.turns > 0);
    }

    // -----------------------------------------------------------------------
    // Effective budgets (manifest can only tighten, never loosen)
    // -----------------------------------------------------------------------

    #[test]
    fn effective_budgets_default_to_ctx_without_manifest() {
        let ctx = make_ctx(Box::new(MockProvider::new(vec![])));
        let b = effective_budgets(&ctx, &OrchestrateManifest::default());
        assert_eq!(b.max_subagents, ctx.max_subagents);
        assert_eq!(b.turn_budget, ctx.turn_budget);
        assert_eq!(b.token_budget, ctx.token_budget);
    }

    #[test]
    fn effective_budgets_manifest_can_only_lower() {
        let ctx = make_ctx(Box::new(MockProvider::new(vec![])));
        // Manifest asks for MORE than the ctx (CLI/env) caps — must be clamped down.
        let loosen = OrchestrateManifest {
            max_subagents: Some(100),
            turn_budget: Some(9_999),
            token_budget: Some(10_000_000),
            ..Default::default()
        };
        let b = effective_budgets(&ctx, &loosen);
        assert_eq!(b.max_subagents, ctx.max_subagents, "cannot exceed ctx cap");
        assert_eq!(b.turn_budget, ctx.turn_budget, "cannot exceed ctx cap");
        assert_eq!(b.token_budget, roles::TOKEN_BUDGET_CEILING, "clamped to hard ceiling");

        // Manifest asks for LESS — the tighter value wins.
        let tighten = OrchestrateManifest {
            max_subagents: Some(2),
            turn_budget: Some(10),
            token_budget: Some(50_000),
            ..Default::default()
        };
        let b = effective_budgets(&ctx, &tighten);
        assert_eq!(b.max_subagents, 2);
        assert_eq!(b.turn_budget, 10);
        assert_eq!(b.token_budget, 50_000);
    }

    // -----------------------------------------------------------------------
    // Advisory budget warnings
    // -----------------------------------------------------------------------

    #[test]
    fn budget_warning_emitted_when_turn_budget_exceeded_but_still_spawns() {
        let provider = MockProvider::new(vec![
            ("end_turn", vec![ContentBlock::Text("done".into())]),
        ]);
        let mut ctx = make_ctx(Box::new(provider));
        // Set a very low turn budget so the first sub-agent triggers the warning.
        ctx.turn_budget = 0;
        let mut count = 0;
        let input = serde_json::json!({"role": "recon", "objective": "test"});

        let result = handle_spawn_subagent(&ctx, "call_1", &input, &mut count, None);
        // The sub-agent should STILL be spawned (advisory only).
        assert!(!result.is_error);
        assert_eq!(count, 1);
        // The result should contain the budget notice.
        assert!(result.content.contains("budget notice"), "should include advisory budget warning, got: {}", result.content);

        // The profile should record the budget warning.
        let profile = ctx.run_profile.lock().unwrap();
        assert!(!profile.budget_warnings.is_empty());
    }

    #[test]
    fn budget_warning_emitted_when_token_budget_exceeded() {
        let provider = MockProvider::new(vec![
            ("end_turn", vec![ContentBlock::Text("done".into())]),
        ]);
        let mut ctx = make_ctx(Box::new(provider));
        ctx.token_budget = 0;
        let mut count = 0;
        let input = serde_json::json!({"role": "recon", "objective": "test"});

        let result = handle_spawn_subagent(&ctx, "call_1", &input, &mut count, None);
        assert!(!result.is_error, "advisory budget must not block spawning");
        assert!(result.content.contains("budget notice"));
    }

    #[test]
    fn no_budget_warning_within_limits() {
        let provider = MockProvider::new(vec![
            ("end_turn", vec![ContentBlock::Text("done".into())]),
        ]);
        let ctx = make_ctx(Box::new(provider));
        // Defaults: turn_budget=80, token_budget=1.5M — well above a single sub-agent.
        let mut count = 0;
        let input = serde_json::json!({"role": "recon", "objective": "test"});

        let result = handle_spawn_subagent(&ctx, "call_1", &input, &mut count, None);
        assert!(!result.is_error);
        assert!(!result.content.contains("budget notice"));
    }

    // -----------------------------------------------------------------------
    // Profile event emission via profile_tx
    // -----------------------------------------------------------------------

    #[test]
    fn profile_event_emitted_via_sender() {
        let provider = MockProvider::new(vec![
            ("end_turn", vec![ContentBlock::Text("done".into())]),
        ]);
        let ctx = make_ctx(Box::new(provider));
        let (tx, rx) = mpsc::channel();
        let mut count = 0;
        let input = serde_json::json!({"role": "recon", "objective": "test"});

        handle_spawn_subagent(&ctx, "call_1", &input, &mut count, Some(&tx));

        // A Profile event should have been sent.
        let events: Vec<AgentEvent> = rx.try_iter().collect();
        let profile_event = events.iter().find(|e| matches!(e, AgentEvent::Profile(_)));
        assert!(profile_event.is_some(), "should emit a Profile event for interactive path");
        if let Some(AgentEvent::Profile(line)) = profile_event {
            assert!(line.contains("[profile]"));
            assert!(line.contains("recon"));
        }
    }

    // -----------------------------------------------------------------------
    // Orchestrator's own usage is captured so the profile reconciles with the ledger
    // -----------------------------------------------------------------------

    #[test]
    fn profile_total_reconciles_with_ledger() {
        // Orchestrator: one turn spawning a sub-agent, then one turn ending.
        // Both orchestrator turns AND the sub-agent turn emit usage into the shared
        // ledger; the profile's TOTAL (sub-agents + synthetic orchestrator segment)
        // must equal the ledger total.
        let provider = MockProvider::new(vec![
            ("tool_use", vec![ContentBlock::ToolUse {
                id: "tu_spawn".into(),
                name: "spawn_subagent".into(),
                input: serde_json::json!({"role": "recon", "objective": "map it"}),
            }]),
            ("end_turn", vec![ContentBlock::Text("done".into())]),
        ]);
        let ctx = make_ctx(Box::new(provider));
        let (tx, _rx) = mpsc::channel();
        run_orchestrator_async(&ctx, "Audit", vec![], tx);

        let ledger_total = {
            let l = ctx.token_ledger.lock().unwrap();
            l.total_tokens()
        };
        let profile = ctx.run_profile.lock().unwrap();
        assert_eq!(
            profile.total_tokens(),
            ledger_total,
            "profile TOTAL must reconcile with the ledger total"
        );
        // There should be an orchestrator segment in addition to the recon sub-agent.
        assert!(profile.segments.iter().any(|s| s.label == "orchestrator"));
        assert!(profile.segments.iter().any(|s| s.label == "recon"));
    }

    // -----------------------------------------------------------------------
    // Headless path runs to completion (regression guard against a ledger
    // double-lock deadlock) and persists profile.json.
    // -----------------------------------------------------------------------

    #[test]
    fn headless_orchestrator_completes_and_writes_profile() {
        let provider = MockProvider::new(vec![
            ("tool_use", vec![ContentBlock::ToolUse {
                id: "tu_spawn".into(),
                name: "spawn_subagent".into(),
                input: serde_json::json!({"role": "recon", "objective": "map it"}),
            }]),
            ("end_turn", vec![ContentBlock::Text("Done.".into())]),
        ]);
        let mut ctx = make_ctx(Box::new(provider));
        let dir = tempfile::tempdir().unwrap();
        ctx.source_root = Some(dir.path().to_str().unwrap().to_string());

        // Must return (not hang): the post-run ledger summary and the profile
        // finalizer both touch the token ledger, so a held lock would deadlock here.
        // Returning at all is the assertion (a held ledger lock would deadlock here).
        run_orchestrator(&ctx, "Audit", None).expect("headless run should succeed");

        let profile_path = dir.path().join(".chen").join("agent-state").join("profile.json");
        assert!(profile_path.exists(), "profile.json should be written on the headless path");
    }

    // -----------------------------------------------------------------------
    // Second sub-agent gets disambiguated label (#2)
    // -----------------------------------------------------------------------

    #[test]
    fn second_subagent_gets_indexed_label() {
        let provider = MockProvider::new(vec![
            ("end_turn", vec![ContentBlock::Text("done".into())]),
        ]);
        let ctx = make_ctx(Box::new(provider));
        let mut count = 0;
        let input1 = serde_json::json!({"role": "recon", "objective": "map it"});
        let input2 = serde_json::json!({"role": "recon", "objective": "map deeper"});

        handle_spawn_subagent(&ctx, "c1", &input1, &mut count, None);
        handle_spawn_subagent(&ctx, "c2", &input2, &mut count, None);

        let profile = ctx.run_profile.lock().unwrap();
        assert_eq!(profile.segments.len(), 2);
        assert_eq!(profile.segments[0].label, "recon");
        assert_eq!(profile.segments[1].label, "recon #2");
    }
}
