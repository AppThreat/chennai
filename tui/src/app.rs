//! Central TUI state: three focusable panels — Summary, REPL, Output.
//! Agent state is managed via `agent_enabled` and `agent_active` flags; the agent loop runs on a
//! background thread and communicates back via an `mpsc` channel.

use crate::agent::provider::AgentEvent;
use crate::bom::BomStore;
use crate::commands;
use crate::engine::Engine;
use crate::model::{Flow, FlowSet, NodeDetail, ResultTable, StarterQuestion, Summary};
use crate::repl::Repl;
use crate::shared::backend::Backend;

use serde_json::Value;

use ratatui::layout::Rect;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

/// Status of a background startup task displayed in the status bar.
#[derive(Debug, Clone, PartialEq)]
pub enum BgStatus {
    Running,
    Done,
    Failed(String),
}

/// A single background task tracked in the status bar.
#[derive(Debug, Clone)]
pub struct BgTaskInfo {
    pub name: String,
    pub status: BgStatus,
}

/// Initialisation phase of the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitPhase {
    /// Background tasks are still running (or not yet started).
    Starting,
    /// All startup tasks completed and the TUI is fully interactive.
    Ready,
}

/// Map a raw tool name to a user-facing label shown in the transcript and footer.
/// Non-custom shell tools (ripgrep, read_file, git_*) are collapsed to `"reading code"`.
/// Custom analysis tools (atom_*, bom_*, rusi_*, golem_*, dosai_*, blint_*) keep their name.
pub fn tool_label(name: &str) -> &str {
    match name {
        "ripgrep" | "read_file" | "git_diff" | "git_log" | "git_show" => "reading code",
        _ => name,
    }
}

/// A single entry in the agent transcript, built from streamed [`AgentEvent`]s for rendering.
#[derive(Debug, Clone)]
pub enum AgentEntry {
    Thinking(String),
    Text(String),
    ToolCall { _id: String, name: String, input: serde_json::Value, result: Option<String>, is_error: bool },
    Error(String),
    Usage { input_tokens: u32, output_tokens: u32 },
    StopReason(String),
    Done,
}

/// A flow query whose (potentially slow) engine call is deferred to the next event-loop iteration,
/// so the REPL can first paint the command + a "running…" status.
pub struct PendingFlow {
    pub args: serde_json::Value,
    /// Index of the REPL scrollback entry to update once the result arrives.
    pub entry_idx: usize,
}

/// The three stacked panels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Summary,
    Repl,
    Output,
}

impl Panel {
    pub fn next(self, non_atom: bool) -> Panel {
        if non_atom {
            return match self {
                Panel::Repl => Panel::Output,
                _ => Panel::Repl,
            };
        }
        match self {
            Panel::Summary => Panel::Output,
            Panel::Output => Panel::Repl,
            Panel::Repl => Panel::Summary,
        }
    }

    pub fn prev(self, non_atom: bool) -> Panel {
        if non_atom {
            return match self {
                Panel::Output => Panel::Repl,
                _ => Panel::Output,
            };
        }
        match self {
            Panel::Summary => Panel::Repl,
            Panel::Repl => Panel::Output,
            Panel::Output => Panel::Summary,
        }
    }
}

/// Per-panel selection + scroll bookkeeping (used by the Summary and Output tables).
#[derive(Default)]
pub struct ListState {
    pub selected: usize,
    pub scroll: usize,
    pub visible: usize,
}

impl ListState {
    pub fn up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
        self.follow();
    }

    pub fn down(&mut self, len: usize) {
        if len > 0 && self.selected + 1 < len {
            self.selected += 1;
        }
        self.follow();
    }

    pub fn page_up(&mut self, page: usize) {
        self.selected = self.selected.saturating_sub(page);
        self.follow();
    }

    pub fn page_down(&mut self, page: usize, len: usize) {
        if len > 0 {
            self.selected = (self.selected + page).min(len - 1);
        }
        self.follow();
    }

    pub fn home(&mut self) {
        self.selected = 0;
        self.follow();
    }

    pub fn end(&mut self, len: usize) {
        if len > 0 {
            self.selected = len - 1;
        }
        self.follow();
    }

    pub fn select(&mut self, idx: usize, len: usize) {
        if len > 0 {
            self.selected = idx.min(len - 1);
            self.follow();
        }
    }

    /// Keep `selected` within the visible window by adjusting `scroll`.
    fn follow(&mut self) {
        let v = self.visible.max(1);
        if self.selected < self.scroll {
            self.scroll = self.selected;
        } else if self.selected >= self.scroll + v {
            self.scroll = self.selected + 1 - v;
        }
    }
}

/// Time window within which two clicks on the same row count as a double-click.
const DOUBLE_CLICK_MS: u128 = 400;

pub struct App {
    /// Shared engine access. The agent loop also holds a clone of this Arc.
    pub engine: Option<Arc<Mutex<Engine>>>,
    pub atom_path: String,
    pub summary: Summary,
    pub output: Option<ResultTable>,
    /// Data-flow result; when present the Output panel renders a master/detail flow view instead
    /// of the generic table.
    pub flows: Option<FlowSet>,
    pub repl: Repl,

    /// Case-insensitive substring filter applied to the Output table.
    pub table_filter: String,
    /// Whether the table filter is currently being edited (captures text input).
    pub table_filter_edit: bool,
    /// Active sort: (column index, ascending).
    pub table_sort: Option<(usize, bool)>,
    /// Row indices into `output.rows` after filter + sort (cdxui-style index vector).
    pub table_visible: Vec<usize>,

    pub focus: Panel,
    pub summary_state: ListState,
    pub output_state: ListState,
    /// Selection in the flow master list (indexes [`flow_visible`], not the raw flow vector).
    pub flow_state: ListState,
    /// Indices into `flows.flows` currently visible, after sub-flow / mitigation filtering.
    pub flow_visible: Vec<usize>,
    /// Show flows marked as sub-paths of longer flows (toggled with `s`).
    pub show_subflows: bool,
    /// Hide flows that contain a validation/sanitisation step (toggled with `m`).
    pub hide_mitigated: bool,
    /// A deferred flow query awaiting execution (gives the UI a chance to paint "running…").
    pub pending: Option<PendingFlow>,
    /// `(file, line)` groups expanded in the detail pane (consecutive same-line steps collapse by
    /// default; clicking a group header expands it).
    pub expanded_lines: HashSet<(String, i64)>,
    /// The flow id whose detail is currently shown, so `expanded_lines` resets on flow change.
    pub flow_detail_id: Option<i64>,

    pub should_quit: bool,
    pub status: String,

    // Hit-testing data populated during rendering.
    pub summary_rows_area: Option<Rect>,
    pub flow_rows_area: Option<Rect>,
    /// Detail-pane area and the screen-y of each collapsible `(file, line)` group header, for
    /// click-to-expand hit-testing.
    pub flow_detail_area: Option<Rect>,
    /// Screen rectangle of the agent transcript content area, for mouse scroll hit-testing.
    pub agent_transcript_area: Option<Rect>,
    pub flow_detail_groups: Vec<(u16, (String, i64))>,
    /// Header-cell rects of the Output table, for click-to-sort hit-testing.
    pub table_header_cells: Vec<Rect>,
    pub panel_rects: Vec<(Panel, Rect)>,
    /// Screen position of the REPL caret, recorded during render so the completion popup can be
    /// anchored to it.
    pub repl_caret: Option<(u16, u16)>,
    last_click: Option<(Instant, usize)>,

    // Node detail panel state.
    pub detail: Option<NodeDetail>,
    pub detail_focused: bool,
    pub detail_child_scroll: usize,
    pub detail_code_scroll: usize,
    pub detail_query_kind: Option<String>,
    pub detail_child_visible: usize,
    pub detail_code_visible: usize,
    /// Hit-test rect for the child table inside the node-detail pane.
    pub detail_child_area: Option<Rect>,
    /// Hit-test rect for the code pane inside the node-detail pane.
    pub detail_code_area: Option<Rect>,

    // Flow detail (step list) scroll state.
    pub flow_detail_scroll: usize,
    pub flow_detail_total: usize,
    pub flow_detail_visible: usize,

    // Agent state.
    pub agent_enabled: bool,
    pub agent_active: bool,
    pub agent_rx: Option<mpsc::Receiver<AgentEvent>>,
    pub agent_cancel: Option<Arc<AtomicBool>>,
    /// Rendered transcript entries for the agent view.
    pub agent_transcript: Vec<AgentEntry>,
    /// Scroll position in the agent transcript, measured in rendered lines (the
    /// index of the top visible line).
    pub agent_scroll: usize,
    /// Total rendered line count and viewport height of the transcript, recorded
    /// during render so the scroll handlers can clamp without re-rendering.
    pub agent_total_lines: usize,
    pub agent_viewport: usize,
    /// Whether to auto-scroll to the bottom as new content arrives.
    pub agent_auto_scroll: bool,
    /// Accumulated text for the current assistant turn (streamed via TextDelta).
    agent_current_text: String,
    /// Accumulated thinking for the current assistant turn.
    agent_current_thinking: String,
    /// Pending tool call waiting for a result to arrive.
    agent_pending_tool: Option<(String, String, serde_json::Value)>,
    /// The agent's last recorded query text (for scrollback entry update).
    pub agent_query_text: String,
    /// Override prompt body loaded from a slash-command template, if any. It is
    /// appended to the base system prompt rather than replacing it, so the atom
    /// summary and grounding rules are always present.
    pub agent_slash_prompt: Option<String>,
    /// Tool allowlist for the active slash command (`tools:` frontmatter).
    pub agent_slash_tools: Option<Vec<String>>,
    /// Effort override for the active slash command (`effort:` frontmatter).
    pub agent_slash_effort: Option<String>,
    /// Whether the report has been saved for the current agent run.
    pub agent_report_saved: bool,
    /// When true, thinking blocks are shown in full (not collapsed to 120-char preview).
    pub agent_thinking_expanded: bool,
    /// Cumulative token usage across the current agent run (for the usage meter).
    pub agent_total_in: u32,
    pub agent_total_out: u32,
    /// Animation frame for the running spinner.
    pub agent_spinner: usize,
    /// Name of the most recently invoked tool (shown in the progress footer).
    pub agent_last_tool: Option<String>,

    // BOM (CycloneDX SBOM) state.
    pub bom_store: Option<BomStore>,
    pub bom_generated: bool,

    // Loaded analysis backend (rusi/golem/dosai/blint).
    pub backend: Option<Box<dyn Backend>>,

    // Non-atom mode flag (rust/go/dotnet/binary). Hides the summary panel,
    // leaving only the REPL and Output panels, with REPL at the bottom.
    pub non_atom: bool,
    /// Human-readable project language name, set for non-atom mode (e.g. "Rust", "Go", ".NET").
    pub project_language: Option<String>,
    /// Starter questions shown in the Output panel's empty state.
    pub starter_questions: Vec<StarterQuestion>,
    /// Hit-test rect for the starter questions list during render.
    pub starter_questions_area: Option<Rect>,
    /// Set when template starter questions are ready and the agent is enabled, asking
    /// main.rs to spawn a one-shot LLM call that refines them into context-aware ones.
    pub starter_refine_pending: bool,
    /// True once an LLM refinement has been requested, so it only fires once per session.
    pub starter_refined: bool,
    /// Channel delivering LLM-refined starter questions from the background thread.
    pub starter_rx: Option<mpsc::Receiver<Vec<StarterQuestion>>>,
    /// Cancel flag for the refinement thread (flipped when the deadline passes).
    pub starter_cancel: Option<Arc<AtomicBool>>,
    /// Deadline after which a slow refinement is abandoned and templates are kept.
    pub starter_deadline: Option<std::time::Instant>,

    // Background startup tasks (cdxgen, atom, rusi) and initialisation phase.
    pub bg_progress: Arc<Mutex<Vec<BgTaskInfo>>>,
    pub init_phase: InitPhase,
    /// Atom path to use once deferred init completes (set by main.rs before run_app).
    pub deferred_atom_path: Option<String>,
    /// Engine command path for deferred init.
    pub deferred_engine_cmd: Option<String>,
    /// Reports directory for deferred init.
    pub deferred_reports_dir: Option<String>,
    /// Project source root directory (used by the `:memory` command and other
    /// paths that need the real project root, not the atom file path).
    pub source_root: Option<String>,
}

impl App {
    #[allow(dead_code)]
    pub fn new(engine: Option<Arc<Mutex<Engine>>>, atom_path: String, summary: Summary, source_root: Option<String>) -> Self {
        App {
            engine,
            atom_path,
            summary,
            output: None,
            flows: None,
            table_filter: String::new(),
            table_filter_edit: false,
            table_sort: None,
            table_visible: Vec::new(),
            repl: Repl::default(),
            focus: Panel::Summary,
            summary_state: ListState::default(),
            output_state: ListState::default(),
            flow_state: ListState::default(),
            flow_visible: Vec::new(),
            show_subflows: false,
            hide_mitigated: false,
            pending: None,
            expanded_lines: HashSet::new(),
            flow_detail_id: None,
            should_quit: false,
            status: String::new(),
            summary_rows_area: None,
            flow_rows_area: None,
            flow_detail_area: None,
            flow_detail_groups: Vec::new(),
            agent_transcript_area: None,
            table_header_cells: Vec::new(),
            panel_rects: Vec::new(),
            repl_caret: None,
            last_click: None,
            detail: None,
            detail_focused: false,
            detail_child_scroll: 0,
            detail_code_scroll: 0,
            detail_query_kind: None,
            detail_child_visible: 0,
            detail_code_visible: 0,
            detail_child_area: None,
            detail_code_area: None,
            flow_detail_scroll: 0,
            flow_detail_total: 0,
            flow_detail_visible: 0,
            non_atom: false,
            project_language: None,
            starter_questions: Vec::new(),
            starter_questions_area: None,
            starter_refine_pending: false,
            starter_refined: false,
            starter_rx: None,
            starter_cancel: None,
            starter_deadline: None,
            agent_enabled: false,
            agent_active: false,
            agent_rx: None,
            agent_cancel: None,
            agent_transcript: Vec::new(),
            agent_scroll: 0,
            agent_total_lines: 0,
            agent_viewport: 0,
            agent_auto_scroll: true,
            agent_current_text: String::new(),
            agent_current_thinking: String::new(),
            agent_pending_tool: None,
            agent_query_text: String::new(),
            agent_slash_prompt: None,
            agent_slash_tools: None,
            agent_slash_effort: None,
            agent_report_saved: false,
            agent_thinking_expanded: false,
            agent_total_in: 0,
            agent_total_out: 0,
            agent_spinner: 0,
            agent_last_tool: None,
            bom_store: None,
            bom_generated: false,
            backend: None,
            bg_progress: Arc::new(Mutex::new(Vec::new())),
            init_phase: InitPhase::Ready,
            deferred_atom_path: None,
            deferred_engine_cmd: None,
            deferred_reports_dir: None,
            source_root,
        }
    }

    /// The scroll/selection state for the focused panel, if it is a navigable table.
    pub fn focused_list(&mut self) -> Option<(&mut ListState, usize)> {
        match self.focus {
            Panel::Summary => {
                let len = self.summary.rows.len();
                Some((&mut self.summary_state, len))
            }
            Panel::Output => {
                // When the detail pane is open and focused, arrow keys scroll it instead.
                if self.detail_focused && self.detail.is_some() {
                    return None;
                }
                // When the agent view is showing, navigate the agent transcript.
                if self.agent_active || (!self.agent_transcript.is_empty() && self.output.is_none() && self.flows.is_none()) {
                    let len = self.agent_transcript.len().max(1);
                    Some((&mut self.output_state, len))
                // When a flow result is showing, Output navigation drives the master flow list.
                } else if self.flows.is_some() {
                    let len = self.flow_visible.len();
                    Some((&mut self.flow_state, len))
                // Starter questions in the empty Output panel (atom and non-atom alike).
                } else if self.output.is_none() && !self.starter_questions.is_empty() {
                    let len = self.starter_questions.len();
                    Some((&mut self.output_state, len))
                } else {
                    Some((&mut self.output_state, self.table_visible.len()))
                }
            }
            Panel::Repl => None,
        }
    }

    /// Enter pressed: behaviour depends on the focused panel.
    pub fn on_enter(&mut self) {
        match self.focus {
            Panel::Summary => self.run_summary_row(self.summary_state.selected, true),
            Panel::Repl => self.submit_repl(),
            Panel::Output => {
                if self.agent_active || (!self.agent_transcript.is_empty() && self.output.is_none() && self.flows.is_none()) {
                    // In agent view, Enter is a no-op (or could select a tool result).
                    return;
                }
                // Starter questions: execute the selected question on Enter.
                if self.output.is_none() && self.flows.is_none() && !self.starter_questions.is_empty() {
                    self.run_starter_question(self.output_state.selected);
                    return;
                }
                if !self.detail_focused {
                    self.open_detail_for_selected();
                }
            }
        }
    }

    /// Submit the current REPL line: execute it and clear the input.
    pub fn submit_repl(&mut self) {
        let text = self.repl.text();
        self.execute(&text);
        self.repl.clear();
    }

    /// Run the query for a summary row, echoing the command into the REPL first.
    pub fn run_summary_row(&mut self, idx: usize, focus_output: bool) {
        let repl_text = self
            .summary
            .rows
            .get(idx)
            .and_then(|r| commands::by_label(&r.label))
            .map(|c| c.repl.to_string());
        if let Some(text) = repl_text {
            self.repl.set_text(&text);
            self.execute(&text);
            if focus_output && self.output.is_some() {
                self.focus = Panel::Output;
            }
        }
    }

    /// Parse and execute a command line, recording it in the REPL scrollback.
    ///
    /// Routing priority:
    /// 1. Empty input → no-op.
    /// 2. `/slash` commands → start agent with the slash-command template.
    /// 3. Free-text (when agent is enabled and input is not recognised DSL) → start agent.
    /// 4. Flow expressions → deferred to `pending` (dataflows/reachables/cryptos).
    /// 5. Recognised structured queries → `query` command.
    /// 6. Everything else → `eval` (arbitrary chen DSL).
    ///
    /// NOTE: For the agent to start, [`App::start_agent`] must be called after recording the REPL
    /// entry. The agent thread spawning is done by `main.rs` after the `AgentCtx` is constructed.
    /// This method records the intent; the caller (the event loop) must check `agent_pending_start`.
    pub fn execute(&mut self, text: &str) {
        let t = text.trim().to_string();
        if t.is_empty() {
            return;
        }

        // Slash commands: /security-review, /code-review, /explain, /trace, /help
        if let Some(slash_cmd) = t.strip_prefix('/') {
            if self.agent_enabled && !self.agent_active {
                let cmd = slash_cmd.to_string();
                if cmd == "help" {
                    self.repl.record(&t, "available commands: /security-review, /code-review, /explain, /trace, /help".into(), true);
                    self.status = "agent commands listed".into();
                    return;
                }
                self.repl.record(&t, "agent thinking...".into(), true);
                self.status = format!("agent: /{cmd}");
                self.agent_query_text = t.clone();
                // Use a curated template (prompt body + tool allowlist + effort)
                // for known slash commands; unknown ones fall back to free-text.
                    match crate::agent::slash_command(&cmd) {
                        Some(sc) => {
                            self.agent_slash_prompt = Some(sc.body);
                            // Map atom_* tool names to backend-specific equivalents.
                            let backend_name = self.backend.as_ref().map(|b| b.backend_name()).unwrap_or("");
                            self.agent_slash_tools = sc.tools.map(|tools| {
                                if !backend_name.is_empty() {
                                    tools.into_iter().map(|t| map_atom_to_backend_tool(&t, backend_name)).collect()
                                } else {
                                    tools
                                }
                            });
                            self.agent_slash_effort = sc.effort;
                        }
                        None => {
                            self.agent_slash_prompt = None;
                            self.agent_slash_tools = None;
                            self.agent_slash_effort = None;
                        }
                    }
                // Signal to main that we want to start the agent.
                // The actual thread is spawned in the event loop when it sees this flag.
                self.agent_active = true;
                self.agent_rx = None;
                self.agent_transcript.clear();
                self.agent_total_in = 0;
                self.agent_total_out = 0;
                self.agent_last_tool = None;
                self.agent_scroll = 0;
                self.agent_auto_scroll = true;
                self.agent_report_saved = false;
                self.output = None;
                self.flows = None;
                self.detail = None;
                if let Some(c) = self.agent_cancel.as_ref() { c.store(false, AtomicOrdering::SeqCst) }
                return;
            } else if !self.agent_enabled {
                self.repl.record(&t, "AI agent not enabled; set ANTHROPIC_API_KEY or OPENAI_API_KEY".into(), false);
            } else {
                self.repl.record(&t, "agent already running".into(), false);
            }
            return;
        }

        // BOM command: show the software bill of materials as a table.
        let lower = t.to_ascii_lowercase();
        if lower == "bom" || lower == ":bom" || lower.starts_with("bom ") || lower.starts_with(":bom ") {
            let filter = t.split_once(' ').map(|(_, rest)| rest.trim().to_string())
                .filter(|s| !s.is_empty());
            self.repl.record(&t, "BOM components loaded".into(), true);
            self.show_bom_table(filter.as_deref());
            self.status = format!("BOM: {} components", self.bom_store.as_ref().map(|s| s.total_components).unwrap_or(0));
            return;
        }

        // Memory command: inspect and manage the per-project fact store.
        if lower.starts_with(":memory") {
            let sub = t.split_once(' ').map(|(_, rest)| rest.trim()).unwrap_or("");
            let store = crate::agent::memory::FactStore::open(self.source_root.as_deref());
            let (status, ok) = match (sub, store) {
                ("", _) | ("list", _) => {
                    match crate::agent::memory::FactStore::open(self.source_root.as_deref()) {
                        Some(s) => {
                            let facts = s.list();
                            if facts.is_empty() {
                                ("no facts stored".into(), true)
                            } else {
                                let lines: Vec<String> = facts.iter()
                                    .map(|f| format!("{} ({}) — {}", f.name, f.fact_type.as_str(), f.description))
                                    .collect();
                                (lines.join("\n"), true)
                            }
                        }
                        None => ("fact store not available".into(), false),
                    }
                }
                ("prune", Some(s)) => {
                    let report = s.prune(&Default::default());
                    let parts = vec![
                        if report.demoted > 0 { Some(format!("{} demoted", report.demoted)) } else { None },
                        if report.evicted > 0 { Some(format!("{} evicted", report.evicted)) } else { None },
                    ];
                    let msg = parts.into_iter().flatten().collect::<Vec<_>>();
                    if msg.is_empty() {
                        ("prune: nothing to do".into(), true)
                    } else {
                        (format!("prune: {}", msg.join(", ")), true)
                    }
                }
                ("prune", None) => ("fact store not available".into(), false),
                (sub, Some(s)) if sub.starts_with("show ") || sub.starts_with("forget ") => {
                    let parts: Vec<&str> = sub.splitn(2, ' ').collect();
                    let action = parts[0];
                    let name = parts.get(1).unwrap_or(&"");
                    if name.is_empty() {
                        (format!(":memory {action} <name> — name is required"), false)
                    } else if action == "show" {
                        match s.load(name) {
                            Some(f) => {
                                let content = crate::agent::memory::FactStore::format_fact_file(
                                    &f.name, &f.description, f.fact_type,
                                    f.grounded_by.as_deref(), f.confidence.as_deref(),
                                    &f.source_refs, &f.created, &f.updated,
                                    f.commit.as_deref(), &f.body,
                                );
                                (content, true)
                            }
                            None => (format!("fact '{name}' not found"), false)
                        }
                    } else {
                        match s.delete(name) {
                            Ok(()) => (format!("fact '{name}' deleted"), true),
                            Err(e) => (format!("failed to delete '{name}': {e}"), false),
                        }
                    }
                }
                (sub, _) if sub.starts_with("show ") || sub.starts_with("forget ") => {
                    ("fact store not available".into(), false)
                }
                (sub, _) => (format!("unknown :memory subcommand '{sub}' — try list, show <name>, forget <name>, prune"), false),
            };
            self.repl.record(&t, status.clone(), ok);
            self.status = status;
            return;
        }

        // Free-text routing: when the agent is enabled and input doesn't look like a DSL command
        // or a flow expression, route to the agent.
        if self.agent_enabled && !self.agent_active && !looks_like_dsl_or_command(&t) {
            self.repl.record(&t, "agent thinking...".into(), true);
            self.status = "agent thinking...".into();
            self.agent_query_text = t.clone();
            self.agent_active = true;
            self.agent_rx = None;
            self.agent_transcript.clear();
            self.agent_total_in = 0;
            self.agent_total_out = 0;
            self.agent_last_tool = None;
            self.agent_scroll = 0;
            self.agent_auto_scroll = true;
            self.agent_report_saved = false;
            self.output = None;
            self.flows = None;
            self.detail = None;
            if let Some(c) = self.agent_cancel.as_ref() { c.store(false, AtomicOrdering::SeqCst) }
            return;
        }

        // Free-text without AI: agent is disabled, so the engine's eval can't handle natural language.
        // Show a helpful message instead of making the user parse a raw Scala error.
        if !self.agent_enabled && !looks_like_dsl_or_command(&t) {
            let msg = "AI agent not enabled; set ANTHROPIC_API_KEY or OPENAI_API_KEY for AI assistance, or use DSL commands like `atom.<query>.toJson`".into();
            self.repl.record(&t, msg, false);
            self.status = "agent not enabled".into();
            return;
        }

        // Data-flow expressions are routed to the structured `flows` command (master/detail view):
        // the bare `reachables`/`cryptos` presets, or any expression invoking the dataflow DSL.
        let flow_args = if t == "dataflows" || t == "reachables" || t == "cryptos" {
            Some(serde_json::json!({ "preset": t }))
        } else if lower.contains("reachablebyflows") || t.contains(".df(") {
            Some(serde_json::json!({ "expr": t }))
        } else {
            None
        };

        if let Some(args) = flow_args {
            // Flows can take seconds. Echo the command with a "running…" status now and defer the
            // engine call to the next loop iteration (see `take_pending`/`run_pending`), so the
            // user sees immediate feedback before the result count replaces it.
            self.repl.record(&t, "running…".into(), true);
            let entry_idx = self.repl.entries.len() - 1;
            self.pending = Some(PendingFlow { args, entry_idx });
            self.status = format!("running {t}…");
            return;
        }

        // Recognised commands map to a structured `query`; anything else is forwarded verbatim to
        // the engine's REPL via `eval` (which appends `.toJson` to make it parseable).
        let (ok, status) = match commands::parse(&t) {
            Some(q) => {
                self.detail_query_kind = Some(q.kind.clone());
                self.detail = None;
                self.detail_focused = false;
                let mut args = serde_json::json!({ "kind": q.kind, "limit": 5000 });
                if let Some(p) = &q.pattern {
                    args["pattern"] = serde_json::Value::String(p.clone());
                }
                self.dispatch("query", args)
            }
            None => self.dispatch("eval", serde_json::json!({ "expr": t })),
        };
        self.status = status.clone();
        self.repl.record(&t, status, ok);
    }

    /// Take any deferred flow query (run by the event loop after a frame has been painted).
    pub fn take_pending(&mut self) -> Option<PendingFlow> {
        self.pending.take()
    }

    /// Execute a deferred flow query and update its REPL scrollback entry with the outcome.
    pub fn run_pending(&mut self, p: PendingFlow) {
        let (ok, status) = self.dispatch_flows(p.args);
        if let Some(e) = self.repl.entries.get_mut(p.entry_idx) {
            e.status = status.clone();
            e.ok = ok;
        }
        self.status = status;
        if ok {
            self.focus = Panel::Output;
        }
    }

    /// Request compiler-driven completions for the current REPL line at the cursor, and open the
    /// popup if any are returned. The token being completed starts after the last non-identifier
    /// character before the cursor.
    pub fn request_completions(&mut self) {
        let chars = self.repl.chars();
        let cursor = self.repl.cursor().min(chars.len());
        let start = chars[..cursor]
            .iter()
            .rposition(|c| !(c.is_alphanumeric() || *c == '_'))
            .map(|i| i + 1)
            .unwrap_or(0);
        let line: String = chars.iter().collect();

        let Some(ref engine) = self.engine else {
            self.status = "engine not available".into();
            return;
        };
        let mut engine = engine.lock().unwrap();
        match engine.request::<crate::model::Completions>(
            "complete",
            serde_json::json!({ "line": line, "cursor": cursor }),
        ) {
            Ok(resp) => {
                let n = resp.completions.len();
                self.repl.open_completion(resp.completions, start);
                self.status = if n == 0 {
                    "no completions".into()
                } else {
                    format!("{n} completion(s)")
                };
            }
            Err(e) => self.status = format!("complete failed: {e}"),
        }
    }

    /// Convenience entry point for the data-flows preset (bound to `d`): all flows.
    pub fn run_dataflows(&mut self) {
        self.repl.set_text("dataflows");
        self.execute("dataflows");
        self.repl.clear();
    }

    /// Convenience entry point for the reachable-flows preset (bound to `r`): only flows
    /// attributable to a package (purl-tagged).
    pub fn run_reachables(&mut self) {
        self.repl.set_text("reachables");
        self.execute("reachables");
        self.repl.clear();
    }

    /// Send a request to the engine and, on success, install the returned table as Output.
    fn dispatch(&mut self, cmd: &str, args: serde_json::Value) -> (bool, String) {
        let result = {
            let Some(ref engine_arc) = self.engine else {
                return (false, "engine not available".into());
            };
            let mut engine = engine_arc.lock().unwrap();
            engine.request::<ResultTable>(cmd, args)
        };
        match result {
            Ok(table) => {
                let status = format!("{}: showing {} of {} row(s)", table.title, table.rows.len(), table.total);
                self.output = Some(table);
                self.flows = None;
                self.output_state = ListState::default();
                self.table_filter.clear();
                self.table_filter_edit = false;
                self.table_sort = None;
                self.recompute_table_view();
                (true, status)
            }
            Err(e) => (false, format!("{cmd} failed: {e}")),
        }
    }

    /// Rebuild the table's visible-row index vector from the current filter + sort.
    pub fn recompute_table_view(&mut self) {
        self.table_visible.clear();
        let Some(t) = self.output.as_ref() else {
            return;
        };
        let needle = self.table_filter.to_lowercase();
        let mut idx: Vec<usize> = (0..t.rows.len())
            .filter(|&i| {
                needle.is_empty()
                    || t.rows[i].iter().any(|c| c.v.to_lowercase().contains(&needle))
            })
            .collect();

        if let Some((col, asc)) = self.table_sort {
            idx.sort_by(|&a, &b| {
                let va = t.rows[a].get(col).map(|c| c.v.as_str()).unwrap_or("");
                let vb = t.rows[b].get(col).map(|c| c.v.as_str()).unwrap_or("");
                // Numeric when both cells parse as numbers, else case-insensitive lexicographic.
                let ord = match (va.parse::<f64>(), vb.parse::<f64>()) {
                    (Ok(x), Ok(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
                    _ => va.to_lowercase().cmp(&vb.to_lowercase()),
                };
                if asc { ord } else { ord.reverse() }
            });
        }

        self.table_visible = idx;
        // Keep the selection within the new visible range.
        self.output_state.select(self.output_state.selected, self.table_visible.len());
    }

    pub fn start_table_filter(&mut self) {
        self.table_filter_edit = true;
    }

    pub fn end_table_filter(&mut self) {
        self.table_filter_edit = false;
    }

    /// Esc while filtering clears the filter and exits edit mode.
    pub fn clear_table_filter(&mut self) {
        self.table_filter.clear();
        self.table_filter_edit = false;
        self.recompute_table_view();
    }

    pub fn table_filter_input(&mut self, c: char) {
        self.table_filter.push(c);
        self.output_state.select(0, self.table_visible.len());
        self.recompute_table_view();
    }

    pub fn table_filter_backspace(&mut self) {
        self.table_filter.pop();
        self.recompute_table_view();
    }

    /// Sort by `col`; sorting by the active column again flips the direction.
    pub fn sort_by_column(&mut self, col: usize) {
        let asc = match self.table_sort {
            Some((c, a)) if c == col => !a,
            _ => true,
        };
        self.table_sort = Some((col, asc));
        self.recompute_table_view();
    }

    /// Number of columns in the current table (for bounding sort-column keys).
    pub fn table_columns(&self) -> usize {
        self.output.as_ref().map(|t| t.columns.len()).unwrap_or(0)
    }

    /// Send a `flows` request and install the returned flow set as the Output master/detail view.
    /// Falls back to the backend query when the atom engine is not available (non-atom mode).
    fn dispatch_flows(&mut self, args: serde_json::Value) -> (bool, String) {
        // Atom engine path.
        if self.engine.is_some() {
            let engine_arc = self.engine.as_ref().unwrap().clone();
            let mut engine = engine_arc.lock().unwrap();
            match engine.request::<FlowSet>("flows", args) {
                Ok(fs) => {
                    let status = format!("{}: {} flow(s)", fs.title, fs.total);
                    self.flows = Some(fs);
                    self.output = None;
                    self.flow_state = ListState::default();
                    self.flow_detail_scroll = 0;
                    self.recompute_flow_visible();
                    return (true, status);
                }
                Err(e) => return (false, format!("flows failed: {e}")),
            }
        }

        // Backend fallback (non-atom mode).
        let (result, title) = {
            let backend = match self.backend.as_ref() {
                Some(b) => b,
                None => return (false, "engine not available".into()),
            };
            let preset = args.get("preset").and_then(Value::as_str).unwrap_or("dataflows");
            let (kind, t) = match preset {
                "dataflows" => ("dataflow", "Data Flows"),
                "reachables" => ("flows", "Reachable Flows"),
                "cryptos" => ("crypto", "Crypto Usage"),
                "callgraph" => ("callgraph", "Call Graph"),
                _ => ("dataflow", "Results"),
            };
            (backend.query(kind, None, 200), t.to_string())
        };
        let rows: Vec<Vec<crate::model::Cell>> = result
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| vec![crate::model::Cell { v: l.to_string(), k: String::new() }])
            .collect();
        let total = rows.len() as i64;
        let status = format!("{}: {} items", title, total);
        let table = ResultTable {
            title,
            columns: vec![String::new()],
            rows,
            total,
            offset: 0,
        };
        self.output = Some(table);
        self.flows = None;
        self.flow_state = ListState::default();
        self.recompute_table_view();
        (true, status)
    }



    /// Recompute which flows are visible after applying the sub-flow / mitigation filters.
    fn recompute_flow_visible(&mut self) {
        self.flow_visible.clear();
        if let Some(fs) = &self.flows {
            for (i, f) in fs.flows.iter().enumerate() {
                if !self.show_subflows && f.sub_flow_of.is_some() {
                    continue;
                }
                if self.hide_mitigated && f.mitigated {
                    continue;
                }
                self.flow_visible.push(i);
            }
        }
        self.flow_state.select(self.flow_state.selected, self.flow_visible.len());
    }

    /// The flow currently selected in the master list, if any.
    pub fn selected_flow(&self) -> Option<&Flow> {
        let fs = self.flows.as_ref()?;
        let idx = *self.flow_visible.get(self.flow_state.selected)?;
        fs.flows.get(idx)
    }

    /// Toggle showing sub-flows (paths contained within a longer flow).
    pub fn toggle_subflows(&mut self) {
        if self.flows.is_none() {
            return;
        }
        self.show_subflows = !self.show_subflows;
        self.recompute_flow_visible();
        self.status = format!(
            "sub-flows {} — {} flow(s) shown",
            if self.show_subflows { "shown" } else { "hidden" },
            self.flow_visible.len()
        );
    }

    /// Toggle hiding mitigated flows (those with a validation/sanitisation step).
    pub fn toggle_mitigated(&mut self) {
        if self.flows.is_none() {
            return;
        }
        self.hide_mitigated = !self.hide_mitigated;
        self.recompute_flow_visible();
        self.status = format!(
            "mitigated flows {} — {} flow(s) shown",
            if self.hide_mitigated { "hidden" } else { "shown" },
            self.flow_visible.len()
        );
    }

    /// Handle a left-button click at a terminal cell. Returns nothing; updates focus/selection and
    /// triggers a query on a double-click within the summary panel.
    pub fn on_click(&mut self, col: u16, row: u16) {
        // Focus whichever panel was clicked.
        if let Some((panel, _)) = self
            .panel_rects
            .iter()
            .find(|(_, r)| contains(r, col, row))
            .copied()
        {
            self.focus = panel;
        }

        // Within the summary data rows, select and detect double-click.
        if let Some(area) = self.summary_rows_area
            && contains(&area, col, row) {
                let idx = self.summary_state.scroll + (row - area.y) as usize;
                if idx < self.summary.rows.len() {
                    let now = Instant::now();
                    let is_double = self
                        .last_click
                        .map(|(t, r)| r == idx && now.duration_since(t).as_millis() < DOUBLE_CLICK_MS)
                        .unwrap_or(false);
                    self.summary_state.select(idx, self.summary.rows.len());
                    self.last_click = Some((now, idx));
                    if is_double {
                        self.run_summary_row(idx, true);
                    }
                }
            }

        // Within the flow master list, select the clicked flow.
        if let Some(area) = self.flow_rows_area
            && contains(&area, col, row) && !self.flow_visible.is_empty() {
                let idx = self.flow_state.scroll + (row - area.y) as usize;
                self.flow_state.select(idx, self.flow_visible.len());
            }

        // Clicking an Output table column header sorts by that column.
        if let Some(i) = self.table_header_cells.iter().position(|c| contains(c, col, row)) {
            self.sort_by_column(i);
        }

        // Within the detail pane, clicking a collapsible group header toggles its expansion.
        if let Some(area) = self.flow_detail_area
            && contains(&area, col, row)
                && let Some((_, key)) =
                    self.flow_detail_groups.iter().find(|(y, _)| *y == row).cloned()
                    && !self.expanded_lines.remove(&key) {
                        self.expanded_lines.insert(key);
                    }

        // Starter questions in the empty Output panel (one line per question).
        if self.output.is_none() && self.flows.is_none()
            && !self.agent_active && self.agent_transcript.is_empty()
            && let Some(area) = self.starter_questions_area
            && contains(&area, col, row)
        {
            let idx = row.saturating_sub(area.y) as usize;
            if idx < self.starter_questions.len() {
                self.output_state.select(idx, self.starter_questions.len());
                self.run_starter_question(idx);
            }
        }
    }

    pub fn open_detail_for_selected(&mut self) {
        let Some(kind) = self.detail_query_kind.clone() else {
            return;
        };
        let Some(table) = self.output.as_ref() else {
            return;
        };
        let sel = self.output_state.selected;
        let Some(&row_idx) = self.table_visible.get(sel) else {
            return;
        };
        let row = &table.rows[row_idx];

        let (key, file, line): (String, Option<String>, Option<i64>) = match kind.as_str() {
            "files" => {
                let key = row.first().map(|c| c.v.clone()).unwrap_or_default();
                (key, None, None)
            }
            "methods" | "externalMethods" | "internalMethods" => {
                let key = row.get(1).map(|c| c.v.clone()).unwrap_or_default();
                (key, None, None)
            }
            "calls" => {
                let key = row.first().map(|c| c.v.clone()).unwrap_or_default();
                let file = row.get(2).map(|c| c.v.clone());
                let line = row.get(3).and_then(|c| c.v.parse::<i64>().ok());
                (key, file, line)
            }
            _ => return,
        };

        if key.is_empty() {
            return;
        }

        let mut args = serde_json::json!({ "kind": kind, "key": key });
        if let Some(f) = file {
            args["file"] = serde_json::Value::String(f);
        }
        if let Some(l) = line {
            args["line"] = serde_json::Value::Number(l.into());
        }

        let Some(ref engine_arc) = self.engine else {
            self.status = "engine not available".into();
            return;
        };
        let mut engine = engine_arc.lock().unwrap();
        match engine.request::<NodeDetail>("detail", args) {
            Ok(d) => {
                self.detail = Some(d);
                self.detail_focused = false;
                self.detail_child_scroll = 0;
                self.detail_code_scroll = 0;
                self.status = "detail loaded — Right/Tab to focus detail pane".into();
            }
            Err(e) => {
                self.status = format!("detail failed: {e}");
            }
        }
    }

    pub fn close_detail(&mut self) {
        self.detail = None;
        self.detail_focused = false;
        self.detail_child_area = None;
        self.detail_code_area = None;
        self.status = String::new();
    }

    pub fn toggle_detail_focus(&mut self) {
        if self.detail.is_some() {
            self.detail_focused = !self.detail_focused;
        }
    }

    pub fn detail_scroll_down(&mut self) {
        if self.detail_focused {
            let child_len = self.detail.as_ref().map(|d| d.child_rows.len()).unwrap_or(0);
            if self.detail_child_scroll + self.detail_child_visible < child_len {
                self.detail_child_scroll += 1;
            } else {
                let code_lines = self.detail.as_ref()
                    .and_then(|d| d.code.as_ref())
                    .map(|c| c.lines().count())
                    .unwrap_or(0);
                if self.detail_code_scroll + self.detail_code_visible < code_lines {
                    self.detail_code_scroll += 1;
                }
            }
        }
    }

    pub fn detail_scroll_up(&mut self) {
        if self.detail_focused {
            if self.detail_child_scroll > 0 {
                self.detail_child_scroll -= 1;
            } else if self.detail_code_scroll > 0 {
                self.detail_code_scroll -= 1;
            }
        }
    }

    /// Position-aware scroll: route a wheel event to whichever pane the pointer is over.
    /// Falls back to the keyboard-focused list when the pointer is not over a specific sub-pane.
    pub fn scroll_at(&mut self, col: u16, row: u16, down: bool) {
        // Agent transcript area (takes priority when showing).
        if let Some(area) = self.agent_transcript_area
            && contains(&area, col, row) {
                // Wheel/touchpad events move several lines per notch for responsiveness.
                self.agent_scroll_lines(if down { 3 } else { -3 });
                return;
            }
        // Node-detail child table.
        if let Some(area) = self.detail_child_area
            && contains(&area, col, row) {
                let len = self.detail.as_ref().map(|d| d.child_rows.len()).unwrap_or(0);
                if down {
                    if self.detail_child_scroll + self.detail_child_visible < len {
                        self.detail_child_scroll += 1;
                    }
                } else {
                    self.detail_child_scroll = self.detail_child_scroll.saturating_sub(1);
                }
                return;
            }
        // Node-detail code pane.
        if let Some(area) = self.detail_code_area
            && contains(&area, col, row) {
                let total = self.detail.as_ref()
                    .and_then(|d| d.code.as_ref())
                    .map(|c| c.lines().count())
                    .unwrap_or(0);
                if down {
                    if self.detail_code_scroll + self.detail_code_visible < total {
                        self.detail_code_scroll += 1;
                    }
                } else {
                    self.detail_code_scroll = self.detail_code_scroll.saturating_sub(1);
                }
                return;
            }
        // Flow step detail pane.
        if let Some(area) = self.flow_detail_area
            && contains(&area, col, row) {
                if down {
                    if self.flow_detail_scroll + self.flow_detail_visible < self.flow_detail_total {
                        self.flow_detail_scroll += 1;
                    }
                } else {
                    self.flow_detail_scroll = self.flow_detail_scroll.saturating_sub(1);
                }
                return;
            }
        // Flow master list.
        if let Some(area) = self.flow_rows_area
            && contains(&area, col, row) {
                let len = self.flow_visible.len();
                if down { self.flow_state.down(len); } else { self.flow_state.up(); }
                return;
            }
        // Summary rows.
        if let Some(area) = self.summary_rows_area
            && contains(&area, col, row) {
                let len = self.summary.rows.len();
                if down { self.summary_state.down(len); } else { self.summary_state.up(); }
                return;
            }
        // Fall back: scroll whichever list has keyboard focus.
        if down {
            if let Some((s, len)) = self.focused_list() { s.down(len); }
        } else {
            if let Some((s, _)) = self.focused_list() { s.up(); }
        }
    }
}

// ---------------------------------------------------------------------------
// Starter questions
// ---------------------------------------------------------------------------

impl App {
    /// Generate contextual starter questions based on the loaded backend, summary, and BOM data.
    /// Only generates questions when the agent is available or in non-atom mode.
    pub fn generate_starter_questions(&mut self) {
        let mut questions: Vec<StarterQuestion> = Vec::new();
        let bom_note = self.bom_store.as_ref().map(|s| s.total_components).filter(|&c| c > 0);

        if let Some(ref backend) = self.backend {
            let lang = self.project_language.as_deref().unwrap_or("the");
            match backend.backend_name() {
                "rusi" => {
                    questions.push(StarterQuestion {
                        label: format!("Summarize this {lang} project"),
                        command: "Provide a high-level summary of this Rust project — its main modules, packages, and architecture.".into(),
                    });
                    questions.push(StarterQuestion {
                        label: "List security signals".into(),
                        command: "What security signals and vulnerabilities were detected? Show me the details.".into(),
                    });
                    if let Some(n) = bom_note {
                        questions.push(StarterQuestion {
                            label: format!("Explore {n} dependencies"),
                            command: format!("Explore the {n} dependencies in this project. Are there any vulnerable components?"),
                        });
                    }
                    questions.push(StarterQuestion {
                        label: "Show data flows".into(),
                        command: "Trace the data flows through this application and highlight injection paths.".into(),
                    });
                }
                "golem" => {
                    questions.push(StarterQuestion {
                        label: format!("Summarize this {lang} project"),
                        command: "Provide a high-level summary of this Go project — its main packages, modules, and architecture.".into(),
                    });
                    questions.push(StarterQuestion {
                        label: "Show vulnerabilities".into(),
                        command: "What vulnerabilities were found in this Go project? Show me the details.".into(),
                    });
                    if let Some(n) = bom_note {
                        questions.push(StarterQuestion {
                            label: format!("Explore {n} dependencies"),
                            command: format!("Explore the {n} dependencies in this project. Are there any vulnerable components?"),
                        });
                    }
                    questions.push(StarterQuestion {
                        label: "Explore call graph".into(),
                        command: "Show me the call graph and function entry points in this project.".into(),
                    });
                }
                "dosai" => {
                    questions.push(StarterQuestion {
                        label: format!("Summarize this {lang} project"),
                        command: "Provide a high-level summary of this .NET application — its main data flows, entry points, and architecture.".into(),
                    });
                    questions.push(StarterQuestion {
                        label: "Trace data flows".into(),
                        command: "Trace the data flows through this .NET application. Show me sources, sinks, and paths.".into(),
                    });
                    if let Some(n) = bom_note {
                        questions.push(StarterQuestion {
                            label: format!("Explore {n} dependencies"),
                            command: format!("Explore the {n} dependencies in this project. Are there any vulnerable components?"),
                        });
                    }
                    questions.push(StarterQuestion {
                        label: "Find weaknesses".into(),
                        command: "What security weaknesses and dangerous API reachability were discovered?".into(),
                    });
                }
                "blint" => {
                    questions.push(StarterQuestion {
                        label: "Summarize this binary".to_string(),
                        command: "Summarize this binary — what type is it and what capabilities does it have?".into(),
                    });
                    questions.push(StarterQuestion {
                        label: "Show findings".into(),
                        command: "What security findings and capabilities were detected in this binary?".into(),
                    });
                    if let Some(n) = bom_note {
                        questions.push(StarterQuestion {
                            label: format!("Explore {n} components"),
                            command: format!("Explore the {n} SBOM components in this binary."),
                        });
                    }
                    questions.push(StarterQuestion {
                        label: "List symbols".into(),
                        command: "List the symbols, imports, and exports in this binary.".into(),
                    });
                }
                _ => {}
            }
        }

        // Atom mode with agent enabled: generate questions based on summary rows.
        if questions.is_empty() && !self.non_atom && self.agent_enabled {
            let lang = if self.summary.language.is_empty() { "the" } else { &self.summary.language };
            questions.push(StarterQuestion {
                label: format!("Summarize this {lang} project"),
                command: format!("Provide a high-level summary of this {lang} project — its main modules, classes, and architecture."),
            });
            // Mention interesting summary figures.
            for row in &self.summary.rows {
                if row.count > 0 && matches!(row.label.as_str(), "classes" | "methods" | "files") {
                    questions.push(StarterQuestion {
                        label: format!("List {label} ({count})", label = row.label.to_lowercase(), count = row.count),
                        command: format!("Show me the {count} {label} in this project.", label = row.label.to_lowercase(), count = row.count),
                    });
                    if questions.len() >= 3 { break; }
                }
            }
            if questions.len() < 2 && let Some(n) = bom_note {
                questions.push(StarterQuestion {
                    label: format!("Explore {n} dependencies"),
                    command: format!("Explore the {n} dependencies in this project."),
                });
            }
            if questions.is_empty() {
                questions.push(StarterQuestion {
                    label: "Explore the codebase".into(),
                    command: "Help me explore and understand this codebase.".into(),
                });
            }
        }

        // Fallback: generic questions if none were generated above.
        if questions.is_empty() {
            let lang = self.project_language.as_deref().unwrap_or("this");
            questions.push(StarterQuestion {
                label: format!("Summarize this {lang} project"),
                command: format!("Provide a high-level summary of this {lang} project — its main modules and architecture."),
            });
            if let Some(n) = bom_note {
                questions.push(StarterQuestion {
                    label: format!("Explore {n} dependencies"),
                    command: format!("Explore the {n} dependencies in this project."),
                });
            }
            questions.push(StarterQuestion {
                label: "Explore the codebase".into(),
                command: "Help me explore and understand this codebase.".into(),
            });
        }

        self.starter_questions = questions;

        // Ask main.rs to refine these into context-aware questions via a one-shot LLM
        // call (best-effort, time-boxed). Templates above show instantly meanwhile.
        if self.agent_enabled && !self.starter_refined {
            self.starter_refine_pending = true;
        }
    }

    /// Compact, factual context for the starter-question refinement prompt: language,
    /// summary counts, backend digest, and the BOM component count + a few names.
    pub fn starter_question_context(&self) -> String {
        let mut out = String::new();
        if let Some(ref backend) = self.backend {
            let lang = self.project_language.as_deref().unwrap_or("unknown");
            out.push_str(&format!("Backend: {} | Language: {lang}\n", backend.backend_name()));
            out.push_str(&backend.summary());
            out.push('\n');
        } else {
            let lang = if self.summary.language.is_empty() { "unknown" } else { &self.summary.language };
            out.push_str(&format!("Language: {lang}\n"));
            for row in &self.summary.rows {
                out.push_str(&format!("{}: {}\n", row.label, row.count));
            }
        }
        if let Some(ref store) = self.bom_store
            && store.total_components > 0 {
                out.push_str(&format!(
                    "\nSBOM: {} components, {} dependencies, {} services\n",
                    store.total_components, store.total_dependencies, store.total_services,
                ));
                let names: Vec<String> = store.components.iter().take(15)
                    .map(|r| format!("{} {}", r.name_display(), r.version_display()))
                    .collect();
                if !names.is_empty() {
                    out.push_str(&format!("Sample components: {}\n", names.join(", ")));
                }
            }
        out
    }

    /// Replace the displayed starter questions with LLM-refined ones, but only while the
    /// empty-state is still showing (no agent run started, no output displacing it).
    pub fn apply_refined_starter_questions(&mut self, questions: Vec<StarterQuestion>) {
        if questions.is_empty() { return; }
        if self.agent_active || !self.agent_transcript.is_empty() { return; }
        self.starter_questions = questions;
    }

    /// Execute a starter question: fill the REPL with its command and submit.
    fn run_starter_question(&mut self, idx: usize) {
        let command = match self.starter_questions.get(idx) {
            Some(q) => q.command.clone(),
            None => return,
        };
        self.repl.set_text(&command);
        self.execute(&command);
        self.repl.clear();
        // Switch focus to Output so the user sees the result.
        self.focus = Panel::Output;
    }
}

// ---------------------------------------------------------------------------
// Agent integration
// ---------------------------------------------------------------------------

impl App {
    /// Enable the agent, storing the channel pair and a cancel flag.
    pub fn enable_agent(&mut self) {
        self.agent_enabled = true;
        self.agent_cancel = Some(Arc::new(AtomicBool::new(false)));
    }

    /// Called after `execute()` sets up the agent state. Resets transcript channels.
    /// The actual thread spawning happens in `main.rs` event loop.
    #[allow(dead_code)]
    pub fn start_agent(&mut self) {
        if self.agent_active { return; }
        let (_tx, rx) = mpsc::channel::<AgentEvent>();
        self.agent_rx = Some(rx);
        self.agent_active = true;
        self.agent_transcript.clear();
        self.agent_total_in = 0;
        self.agent_total_out = 0;
        self.agent_last_tool = None;
        self.agent_scroll = 0;
        self.agent_auto_scroll = true;
        self.agent_current_text = String::new();
        self.agent_current_thinking = String::new();
        self.agent_pending_tool = None;

        if let Some(ref cancel) = self.agent_cancel {
            cancel.store(false, AtomicOrdering::SeqCst);
        }
    }

    /// Build a ResultTable from the BOM store's components and show it in the output panel.
    /// Optionally filter by a search query.
    pub fn show_bom_table(&mut self, filter: Option<&str>) {
        let loaded = self.bom_store.as_ref().map(|s| s.loaded).unwrap_or(false);
        if !loaded {
            self.status = "no BOM data available. Generate one with: cdxgen -o sbom-<lang>-<lifecycle>.cdx.json <source_dir>".into();
            return;
        }

        // Clone the store to avoid borrow conflicts, then apply optional filter.
        let mut cloned = self.bom_store.as_ref().unwrap().clone();
        if let Some(q) = filter {
            cloned.search_components(q);
        }
        self.show_bom_store_table(&cloned);
    }

    fn show_bom_store_table(&mut self, store: &BomStore) {
        let mut rows = Vec::new();
        for idx in &store.filtered_component_indices {
            if let Some(row) = store.components.get(*idx) {
                rows.push(vec![
                    crate::model::Cell { v: row.type_display().to_string(), k: String::new() },
                    crate::model::Cell { v: row.name_display().to_string(), k: String::new() },
                    crate::model::Cell { v: row.version_display().to_string(), k: String::new() },
                    crate::model::Cell { v: row.purl_display().to_string(), k: String::new() },
                    crate::model::Cell { v: row.license_display().to_string(), k: String::new() },
                ]);
            }
        }

        let columns = vec![
            "Type".into(),
            "Name".into(),
            "Version".into(),
            "PURL".into(),
            "License".into(),
        ];

        let table = ResultTable {
            title: format!("BOM Components ({})", store.total_components),
            columns,
            rows,
            total: store.total_components as i64,
            offset: 0,
        };

        self.output = Some(table);
        self.flows = None;
        self.output_state = ListState::default();
        self.table_filter.clear();
        self.table_filter_edit = false;
        self.table_sort = None;
        self.recompute_table_view();
        self.status = format!("BOM: {} components, {} dependencies, {} services",
            store.total_components, store.total_dependencies, store.total_services);
        self.focus = Panel::Output;
    }

    /// Cancel the running agent.
    pub fn cancel_agent(&mut self) {
        if let Some(ref cancel) = self.agent_cancel {
            cancel.store(true, AtomicOrdering::SeqCst);
        }
    }

    /// Drain all available agent events from the channel and update the transcript.
    pub fn drain_agent_events(&mut self) {
        let rx = match self.agent_rx.take() {
            Some(rx) => rx,
            None => return,
        };
        loop {
            let event = match rx.try_recv() {
                Ok(e) => e,
                Err(mpsc::TryRecvError::Empty) => {
                    self.agent_rx = Some(rx);
                    // Sync accumulated thinking to transcript for real-time display.
                    self.sync_thinking_to_transcript();
                    return;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.agent_active = false;
                    return;
                }
            };
            self.apply_agent_event(event);
        }
    }

    /// Apply a single agent event to the transcript state.
    fn apply_agent_event(&mut self, event: AgentEvent) {
        match event {
            AgentEvent::TextDelta(t) => {
                if self.agent_current_text.is_empty() {
                    // Flush any accumulated thinking as a block.
                    if !self.agent_current_thinking.is_empty() {
                        let t = std::mem::take(&mut self.agent_current_thinking);
                        self.agent_transcript.push(AgentEntry::Thinking(t));
                    }
                }
                self.agent_current_text.push_str(&t);
                self.agent_last_tool = Some("thinking".into());
            }
            AgentEvent::ThinkingDelta(t) => {
                self.agent_current_thinking.push_str(&t);
                self.agent_last_tool = Some("thinking".into());
            }
            AgentEvent::ToolCall { id, name, input } => {
                // Flush accumulated text.
                self.flush_current_text();
                self.flush_current_thinking();
                self.agent_last_tool = Some(tool_label(&name).to_string());
                self.agent_transcript.push(AgentEntry::ToolCall {
                    _id: id, name, input, result: None, is_error: false,
                });
                self.agent_pending_tool = None;
            }
            AgentEvent::ToolResult { id, content, is_error } => {
                // Attach the result to the matching tool card (search from the end
                // for the call with this id that has no result yet).
                for entry in self.agent_transcript.iter_mut().rev() {
                    if let AgentEntry::ToolCall { _id, result, is_error: e, .. } = entry
                        && _id == &id && result.is_none() {
                            *result = Some(content);
                            *e = is_error;
                            break;
                        }
                }
                // A flow result may now be available for the master/detail view.
                self.install_pending_flows();
            }
            AgentEvent::Usage { input_tokens, output_tokens, .. } => {
                self.agent_total_in = self.agent_total_in.saturating_add(input_tokens);
                self.agent_total_out = self.agent_total_out.saturating_add(output_tokens);
                self.agent_transcript.push(AgentEntry::Usage { input_tokens, output_tokens });
            }
            AgentEvent::StopReason(reason) => {
                self.flush_current_text();
                self.flush_current_thinking();
                self.agent_transcript.push(AgentEntry::StopReason(reason));
            }
            AgentEvent::Error(msg) => {
                self.flush_current_text();
                self.flush_current_thinking();
                self.agent_transcript.push(AgentEntry::Error(msg));
                self.agent_active = false;
            }
            AgentEvent::Done => {
                self.flush_current_text();
                self.flush_current_thinking();
                self.agent_transcript.push(AgentEntry::Done);
                self.agent_active = false;
                self.agent_rx = None;
                // Install any flow result from the last transcript entry into the flow view.
                self.install_pending_flows();
                // Update the REPL entry status.
                if let Some(entry) = self.repl.entries.last_mut() {
                    entry.status = "agent done".into();
                    entry.ok = true;
                }
            }
            AgentEvent::FlowResult(data) => {
                // Attempt to deserialize the flow result and install it in the output panel.
                // This lets the TUI show the flow master/detail view alongside agent findings.
                if let Ok(fs) = serde_json::from_value::<FlowSet>(data.clone()) {
                    self.flows = Some(fs);
                    self.output = None;
                    self.flow_state = ListState::default();
                    self.flow_detail_scroll = 0;
                }
            }
        }
        // When auto-scroll is on, the renderer pins the view to the bottom; the
        // exact line offset depends on the rendered line count so it is computed
        // there rather than here.
    }

    /// Commit the current TextDelta accumulation as a transcript entry.
    fn flush_current_text(&mut self) {
        let t = std::mem::take(&mut self.agent_current_text);
        if !t.is_empty() {
            self.agent_transcript.push(AgentEntry::Text(t));
        }
    }

    /// Commit the current ThinkingDelta accumulation as a transcript entry.
    fn flush_current_thinking(&mut self) {
        let t = std::mem::take(&mut self.agent_current_thinking);
        if t.is_empty() {
            return;
        }
        if let Some(AgentEntry::Thinking(last)) = self.agent_transcript.last()
            && last == &t {
                return; // Already synced via sync_thinking_to_transcript.
            }
        self.agent_transcript.push(AgentEntry::Thinking(t));
    }

    /// Sync accumulated thinking to the transcript for real-time display.
    /// Updates the last thinking entry in-place if present, or appends a new one.
    fn sync_thinking_to_transcript(&mut self) {
        let thinking = &self.agent_current_thinking;
        if thinking.is_empty() {
            return;
        }
        match self.agent_transcript.last_mut() {
            Some(AgentEntry::Thinking(last)) => {
                if thinking.len() > last.len() {
                    *last = thinking.clone();
                }
            }
            _ => {
                self.agent_transcript.push(AgentEntry::Thinking(thinking.clone()));
            }
        }
    }

    /// Scan the transcript backwards for the last successful flow tool call and install its
    /// result in `self.flows`, switching the output panel to the flow master/detail view.
    fn install_pending_flows(&mut self) {
        for entry in self.agent_transcript.iter().rev() {
            if let AgentEntry::ToolCall { name, result, is_error, .. } = entry {
                if *is_error { continue; }
                // Atom engine flow result — deserialize into FlowSet.
                if name == "atom_flows" || name == "atom_flows_through" {
                    if let Some(res) = result
                        && let Ok(fs) = serde_json::from_str::<FlowSet>(res) {
                            self.flows = Some(fs);
                            self.output = None;
                            self.flow_state = ListState::default();
                            self.flow_detail_scroll = 0;
                        }
                    break;
                }
                // Backend tool results are already visible in the agent transcript.
                // Do not hijack the output panel with a raw table.
            }
        }
    }

    /// Write the current output panel content (agent transcript, table, or flows) to a
    /// timestamped markdown file under `reports_dir`. Returns the file path on success.
    ///
    /// The report includes:
    /// - Agent query and transcript (text, thinking, tool calls, results) when available.
    /// - Query result tables as markdown tables otherwise.
    pub fn save_report(&mut self, reports_dir: &std::path::Path) {
        if self.agent_report_saved {
            return;
        }
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("chennai_report_{}.md", timestamp);
        let path = reports_dir.join(&filename);

        let mut content = String::new();
        content.push_str("# Chennai Report\n\n");
        content.push_str(&format!("_Generated: {}_\n\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));

        if !self.agent_transcript.is_empty() {
            // Agent transcript report.
            for entry in &self.agent_transcript {
                match entry {
                    AgentEntry::Text(t) => content.push_str(&format!("{}\n\n", t)),
                    AgentEntry::Thinking(t) => {
                        let preview: String = t.chars().take(200).collect();
                        content.push_str(&format!("> 💭 {}\n\n", preview));
                    }
                    AgentEntry::ToolCall { name, input, result, is_error, .. } => {
                        let input_str = serde_json::to_string_pretty(input).unwrap_or_default();
                        content.push_str(&format!("### Tool Call: `{}`\n\n", name));
                        content.push_str(&format!("**Input:**\n```json\n{}\n```\n\n", input_str));
                        if let Some(r) = result {
                            let status = if *is_error { "Error" } else { "Result" };
                            content.push_str(&format!("**{}:**\n```\n{}\n```\n\n", status, r));
                        }
                    }
                    AgentEntry::Error(msg) => {
                        content.push_str(&format!("**Error:** {}\n\n", msg));
                    }
                    AgentEntry::Usage { input_tokens, output_tokens } => {
                        content.push_str(&format!("_Usage: {} in / {} out_\n\n", input_tokens, output_tokens));
                    }
                    AgentEntry::StopReason(reason) => {
                        content.push_str(&format!("_Stop reason: {}_\n\n", reason));
                    }
                    AgentEntry::Done => {
                        content.push_str("---\n\n");
                    }
                }
            }
        } else if let Some(table) = &self.output {
            // Result table report.
            content.push_str(&format!("## {}\n\n", table.title));
            if !table.columns.is_empty() {
                content.push_str(&format!("| {} |\n", table.columns.join(" | ")));
                content.push_str(&format!("|{}|\n", table.columns.iter().map(|_| "---".to_string()).collect::<Vec<_>>().join("|")));
                for row in &table.rows {
                    content.push_str(&format!("| {} |\n", row.iter().map(|c| c.v.clone()).collect::<Vec<_>>().join(" | ")));
                }
                content.push('\n');
            }
            content.push_str(&format!("_Total: {} row(s)_\n", table.total));
        } else if let Some(flows) = &self.flows {
            // Flow report.
            content.push_str(&format!("## {}\n\n", flows.title));
            content.push_str(&format!("_Total: {} flow(s)_\n\n", flows.total));
            for f in &flows.flows {
                content.push_str(&format!("### Flow {}: `{}` → `{}`\n\n", f.id, f.source, f.sink));
                if f.mitigated {
                    content.push_str("> ✓ This flow has a sanitisation/validation step.\n\n");
                }
                for step in &f.steps {
                    let icon = match step.kind.as_str() {
                        "source" => "⊙",
                        "sink" => "◎",
                        "sanitizer" => "✓",
                        "external" => "⌘",
                        _ => "·",
                    };
                    content.push_str(&format!(
                        "- {} `{}:{}` `{}` — {}\n",
                        icon, step.file, step.line, step.method, step.code
                    ));
                }
                content.push('\n');
            }
        } else {
            content.push_str("_No output data to report._\n");
        }

        if std::fs::create_dir_all(reports_dir).is_ok() && std::fs::write(&path, &content).is_ok() {
            self.agent_report_saved = true;
            self.status = format!("report saved → {}", path.display());
        }
    }

    /// Largest valid top-line offset for the transcript viewport.
    fn agent_max_scroll(&self) -> usize {
        self.agent_total_lines.saturating_sub(self.agent_viewport)
    }

    /// Scroll the agent transcript up or down by `n` rendered lines.
    pub fn agent_scroll_lines(&mut self, delta: isize) {
        let max = self.agent_max_scroll();
        let new = (self.agent_scroll as isize + delta).clamp(0, max as isize) as usize;
        self.agent_scroll = new;
        // Re-engage auto-scroll only once the user reaches the very bottom.
        self.agent_auto_scroll = new >= max;
    }

    /// Scroll the agent transcript up or down by one line.
    pub fn agent_scroll_up(&mut self) {
        self.agent_scroll_lines(-1);
    }

    pub fn agent_scroll_down(&mut self) {
        self.agent_scroll_lines(1);
    }

    pub fn agent_page_up(&mut self) {
        let page = self.agent_viewport.saturating_sub(1).max(1) as isize;
        self.agent_scroll_lines(-page);
    }

    pub fn agent_page_down(&mut self) {
        let page = self.agent_viewport.saturating_sub(1).max(1) as isize;
        self.agent_scroll_lines(page);
    }

    /// Build a condensed console-history string from recent REPL entries and the current
    /// output/flow result, for inclusion in the agent's system prompt.
    pub fn build_console_history(&self) -> String {
        const MAX_ENTRIES: usize = 5;
        let entries = &self.repl.entries;
        if entries.is_empty() && self.output.is_none() && self.flows.is_none() {
            return String::new();
        }

        let mut lines: Vec<String> = Vec::new();
        let start = entries.len().saturating_sub(MAX_ENTRIES);
        for (i, e) in entries[start..].iter().enumerate() {
            let idx = start + i + 1;
            lines.push(format!("[{idx}] {inp}", inp = e.input));
            if !e.status.is_empty() {
                lines.push(format!("     → {status}", status = e.status));
            }
        }

        // Attach a preview of the current output/flow result if it came from the last entry.
        if let Some(t) = &self.output {
            lines.push(String::new());
            lines.push(format!("Current table — {} ({} / {} rows)", t.title, t.rows.len(), t.total));
            if !t.columns.is_empty() {
                lines.push(format!("  Columns: {}", t.columns.join(", ")));
            }
            let preview_rows = t.rows.iter().take(5);
            for row in preview_rows {
                let vals: Vec<&str> = row.iter().map(|c| c.v.as_str()).collect();
                lines.push(format!("  {}", vals.join(" | ")));
            }
            if t.rows.len() > 5 {
                lines.push(format!("  … ({} more row(s))", t.rows.len() - 5));
            }
        } else if let Some(fs) = &self.flows {
            lines.push(String::new());
            lines.push(format!("Current flow result — {} ({} flow(s))", fs.title, fs.total));
        }

        lines.join("\n")
    }
}

/// Heuristic: does `input` look like a DSL expression or a structured command that should go
/// directly to the engine rather than the AI agent?
///
/// Returns `true` (i.e. "do NOT route to the agent") when the input is recognised as one of:
/// - An `atom.`-prefixed DSL expression
/// - A registered command label or kind
/// - A flow-preset word (`dataflows`, `reachables`, `cryptos`)
/// - A flow expression containing `reachablebyflows` or `.df(`
/// - A `=prefix` that forces raw-DSL mode
/// - The `bom` command
fn looks_like_dsl_or_command(t: &str) -> bool {
    // `=prefix` forces raw-DSL mode.
    if t.starts_with('=') {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    // BOM command.
    if lower == "bom" || lower.starts_with("bom ") || lower == ":bom" || lower.starts_with(":bom ") {
        return true;
    }
    // Memory command (requires : prefix to avoid shadowing natural language).
    if lower == ":memory" || lower.starts_with(":memory ") {
        return true;
    }
    // DSL prefix.
    if t.starts_with("atom.") {
        return true;
    }
    // Flow presets.
    if lower == "dataflows" || lower == "reachables" || lower == "cryptos" {
        return true;
    }
    // Flow DSL markers.
    if lower.contains("reachablebyflows") || t.contains(".df(") {
        return true;
    }
    // Registered commands (by label, kind, or repl string).
    if commands::parse(t).is_some() {
        return true;
    }
    false
}

/// Map atom_* tool names to backend-specific equivalents (rusi/golem/dosai/blint).
/// The `backend` parameter determines which prefix to use.
pub fn map_atom_to_backend_tool(tool: &str, backend: &str) -> String {
    let prefix = match backend {
        "golem" => "golem",
        "dosai" => "dosai",
        "blint" => "blint",
        _ => "rusi", // default to rusi for backward compatibility
    };
    match tool {
        "atom_summary" => format!("{prefix}_summary"),
        "atom_query" => format!("{prefix}_query"),
        "atom_dsl_eval" => format!("{prefix}_query"),
        "atom_flows" | "atom_flows_through" => format!("{prefix}_flows"),
        "atom_detail" => format!("{prefix}_detail"),
        "atom_algorithms" => format!("{prefix}_callgraph"),
        _ => tool.to_string(),
    }
}

/// Legacy wrapper for backward compatibility.
#[allow(dead_code)]
pub fn map_atom_to_rusi_tool(tool: &str) -> String {
    map_atom_to_backend_tool(tool, "rusi")
}

fn contains(r: &Rect, col: u16, row: u16) -> bool {
    col >= r.x && col < r.x + r.width && row >= r.y && row < r.y + r.height
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Summary, SummaryRow};

    fn app_with_labels(labels: &[&str]) -> App {
        let rows = labels
            .iter()
            .map(|l| SummaryRow { label: l.to_string(), count: 1 })
            .collect();
        App::new(
            None,
            "x.atom".into(),
            Summary { language: "C".into(), version: "1".into(), rows },
            None,
        )
    }

    #[allow(dead_code)] // shared fixture for future App-level tests
    fn test_app() -> App {
        App::new(None, "x.atom".into(), Summary::default(), None)
    }

    #[test]
    fn list_state_selection_is_bounded() {
        let mut s = ListState { visible: 3, ..Default::default() };
        s.up();
        assert_eq!(s.selected, 0);
        for _ in 0..10 {
            s.down(3);
        }
        assert_eq!(s.selected, 2);
    }

    #[test]
    fn list_state_scroll_follows_selection() {
        let mut s = ListState { visible: 2, ..Default::default() };
        for _ in 0..5 {
            s.down(10);
        }
        assert_eq!(s.selected, 5);
        assert!(s.scroll <= s.selected && s.selected < s.scroll + 2);
    }

    #[test]
    fn focus_cycles_through_three_panels() {
        let mut app = app_with_labels(&["Files"]);
        assert_eq!(app.focus, Panel::Summary);
        app.focus = app.focus.next(false);
        assert_eq!(app.focus, Panel::Output);
        app.focus = app.focus.next(false);
        assert_eq!(app.focus, Panel::Repl);
        app.focus = app.focus.next(false);
        assert_eq!(app.focus, Panel::Summary);
    }

    #[test]
    fn run_summary_row_echoes_command_into_repl() {
        // No engine, so the query "runs" but reports engine unavailable; the REPL still echoes
        // the command and records the attempt.
        let mut app = app_with_labels(&["External methods"]);
        app.run_summary_row(0, true);
        assert_eq!(app.repl.text(), "atom.method.external");
        assert_eq!(app.repl.entries.len(), 1);
        assert_eq!(app.repl.entries[0].input, "atom.method.external");
        assert!(!app.repl.entries[0].ok); // engine unavailable
    }

    #[test]
    fn submit_repl_executes_and_clears_input() {
        let mut app = app_with_labels(&["Files"]);
        app.focus = Panel::Repl;
        app.repl.set_text("atom.file");
        app.submit_repl();
        assert_eq!(app.repl.text(), "");
        assert_eq!(app.repl.entries.len(), 1);
        assert_eq!(app.repl.entries[0].input, "atom.file");
    }

    #[test]
    fn unrecognised_command_is_forwarded_to_eval() {
        // With no engine, a free-form expression is forwarded to `eval` and fails gracefully,
        // recording the attempt rather than rejecting it outright.
        let mut app = app_with_labels(&["Files"]);
        app.execute("atom.method.foo");
        assert_eq!(app.repl.entries.len(), 1);
        assert_eq!(app.repl.entries[0].input, "atom.method.foo");
        assert!(!app.repl.entries[0].ok);
        assert!(app.status.contains("engine not available"));
    }

    #[test]
    fn click_focuses_the_panel_under_the_cursor() {
        let mut app = app_with_labels(&["Files"]);
        app.panel_rects = vec![
            (Panel::Summary, Rect { x: 0, y: 0, width: 80, height: 10 }),
            (Panel::Repl, Rect { x: 0, y: 10, width: 80, height: 7 }),
            (Panel::Output, Rect { x: 0, y: 17, width: 80, height: 10 }),
        ];
        app.on_click(5, 12); // inside the REPL panel
        assert_eq!(app.focus, Panel::Repl);
        app.on_click(5, 20); // inside the Output panel
        assert_eq!(app.focus, Panel::Output);
    }

    #[test]
    fn double_click_in_summary_runs_row() {
        let mut app = app_with_labels(&["Files", "Methods"]);
        app.summary_state.visible = 10; // as render would set it
        app.summary_rows_area = Some(Rect { x: 0, y: 2, width: 40, height: 10 });
        // First click selects row 1 (y = 2 + 1).
        app.on_click(5, 3);
        assert_eq!(app.summary_state.selected, 1);
        assert!(app.repl.entries.is_empty());
        // Immediate second click on the same row triggers execution.
        app.on_click(5, 3);
        assert_eq!(app.repl.text(), "atom.method");
        assert_eq!(app.repl.entries.len(), 1);
    }

    #[test]
    fn looks_like_dsl_recognises_bom_command() {
        assert!(looks_like_dsl_or_command("bom"));
        assert!(looks_like_dsl_or_command(":bom"));
        assert!(looks_like_dsl_or_command("bom express"));
        assert!(looks_like_dsl_or_command(":bom lodash"));
    }

    #[test]
    fn looks_like_dsl_recognises_atom_prefix() {
        assert!(looks_like_dsl_or_command("atom.method.external"));
        assert!(looks_like_dsl_or_command("atom.call.name(\"exec\").toJson"));
        assert!(looks_like_dsl_or_command("atom.tag.name(\"framework.*\")"));
    }

    #[test]
    fn looks_like_dsl_recognises_flow_presets() {
        assert!(looks_like_dsl_or_command("dataflows"));
        assert!(looks_like_dsl_or_command("reachables"));
        assert!(looks_like_dsl_or_command("cryptos"));
    }

    #[test]
    fn looks_like_dsl_recognises_registered_commands() {
        assert!(looks_like_dsl_or_command("Files"));
        assert!(looks_like_dsl_or_command("methods"));
        assert!(looks_like_dsl_or_command("atom.file"));
    }

    #[test]
    fn looks_like_dsl_rejects_conversational_input() {
        assert!(!looks_like_dsl_or_command("what does this app do?"));
        assert!(!looks_like_dsl_or_command("list all files"));
        assert!(!looks_like_dsl_or_command("find vulnerabilities"));
    }

    #[test]
    fn looks_like_dsl_equals_prefix_forces_raw() {
        assert!(looks_like_dsl_or_command("=custom.expression"));
        assert!(looks_like_dsl_or_command("=anything at all"));
    }
}
