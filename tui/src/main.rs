mod agent;
mod app;
mod bom;
mod commands;
mod config;
mod engine;
mod model;
mod repl;
mod ui;

use agent::AgentCtx;
use app::{App, Panel};
use bom::{find_existing_boms, BomStore};
use config::Config;
use engine::Engine;
use model::{OpenInfo, Summary};
use ui::theme::Theme;

use clap::Parser;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers, MouseButton, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::{Backend, CrosstermBackend};
use serde_json::json;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;

/// Interactive terminal UI for exploring chen atoms, with optional AI agent.
#[derive(Parser, Debug)]
#[command(name = "chennai", version)]
struct Args {
    path: PathBuf,
    #[arg(long)]
    engine: Option<String>,
    #[arg(long, default_value = "dark")]
    theme: String,
    #[arg(long)]
    source: Option<String>,
    #[arg(long)]
    ask: Option<String>,
    #[arg(long)]
    provider: Option<String>,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    api_key: Option<String>,
    /// Base URL for the LLM API (e.g., https://api.deepseek.com for OpenAI-compatible,
    /// or https://api.deepseek.com/anthropic for Anthropic-compatible).
    #[arg(long)]
    base_url: Option<String>,
    /// Directory to write markdown reports into. Defaults to `.chen/chennai-reports/`
    /// under the source root (or atom directory when --source is not set).
    #[arg(long)]
    reports_dir: Option<PathBuf>,
    /// Omit the `thinking` block from the LLM request body. Use with Anthropic-compatible
    /// endpoints (e.g. DeepSeek) that may not support the Anthropic-specific thinking parameter.
    #[arg(long, default_value_t = false)]
    no_thinking: bool,
    /// Reasoning/output effort for Anthropic models (low|medium|high|xhigh|max).
    /// Defaults to `high`. Ignored by providers that don't support it.
    #[arg(long)]
    effort: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = Config::load_with_base_url(args.provider.as_deref(), args.model.as_deref(), args.api_key.as_deref(), args.base_url.as_deref(), args.no_thinking, args.effort.as_deref());
    let theme = match args.theme.as_str() { "light" => Theme::light(), _ => Theme::dark() };

    let atom = engine::resolve_atom(&args.path)?;
    let atom_str = atom.to_string_lossy().to_string();
    let command = Engine::resolve_command(args.engine.as_deref()).ok_or(
        "engine binary not found; build it with `sbt stage` in engine/, or set CHENNAI_ENGINE",
    )?;

    eprintln!("Spawning engine: {}", command.display());
    let mut eng = Engine::spawn(&command)?;

    let source_root = args.source.clone();
    let open_args = match &source_root {
        Some(src) => json!({ "path": atom_str, "sourceRoot": src }),
        None      => json!({ "path": atom_str }),
    };
    let _open: OpenInfo = eng.request("open", open_args)?;
    let summary: Summary = eng.request("summary", json!({}))?;

    if let Some(question) = args.ask {
        return run_headless_agent(config, eng, source_root, summary, question);
    }

    // Wrap engine in Arc<Mutex> so both the TUI and agent can share it.
    let engine_arc = Arc::new(Mutex::new(eng));

    // Load existing .cdx.json BOM files — never auto-generate at startup.
    // cdxgen is invoked on demand if reachables returns empty and no BOM exists.
    let source_path = source_root.as_ref().map(PathBuf::from);
    let reports_dir = args.reports_dir.unwrap_or_else(|| {
        let base = source_root.clone().unwrap_or_else(|| {
            atom.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| ".".into())
        });
        PathBuf::from(base).join(".chen").join("chennai-reports")
    });

    let bom_store = find_existing_boms(reports_dir.as_path());
    let mut bom_store = if bom_store.loaded { bom_store } else {
        find_existing_boms(source_path.as_deref().unwrap_or(Path::new(".")))
    };

    // If no BOM was found via directory scan, check the atom for .cdx.json config
    // files (a cheaper query than directory scanning). If none exist either, try
    // cdxgen on demand. If cdxgen is unavailable, show a reminder.
    let mut bom_tip = String::new();
    if !bom_store.loaded {
        let has_cdx_config = engine_arc.lock().unwrap()
            .request::<serde_json::Value>("eval", json!({"expr": "atom.configFiles.name(\".*cdx\\\\.json\").toJson"}))
            .map(|r| r.get("total").and_then(|v| v.as_i64()).unwrap_or(0) > 0)
            .unwrap_or(false);

        if !has_cdx_config {
            let sdir = source_path.as_deref().unwrap_or(Path::new("."));
            let odir = reports_dir.as_path();
            let language = bom::detect_language(sdir);
            let mut generated = false;
            for lifecycle in bom::LIFECYCLES {
                if let Ok(path) = bom::generate_bom(sdir, odir, lifecycle, language.as_deref()) {
                    // Load the BOM into the Rust store for display.
                    let mut store = BomStore::new();
                    if store.load_path(&path).is_ok() {
                        // Enrich the open atom by running CdxPass + EasyTagsPass.
                        let bom_str = path.to_string_lossy().to_string();
                        match engine_arc.lock().unwrap().request::<serde_json::Value>(
                            "enrich", json!({"bom": bom_str}),
                        ) {
                            Ok(resp) => {
                                if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                                    eprintln!("Atom enriched with SBOM dependency data");
                                }
                            }
                            Err(e) => {
                                eprintln!("Warning: failed to enrich atom with SBOM data: {e}");
                            }
                        }
                        bom_store = store;
                        generated = true;
                        break;
                    }
                }
            }
            if !generated {
                bom_tip = "No SBOM found. Generate one with: cdxgen -o sbom-<lang>-<lifecycle>.cdx.json <source_dir> (npm install -g @cyclonedx/cdxgen)".into();
                eprintln!("Tip: {bom_tip}");
            }
        }
    }

    // Build optional agent context for the TUI.
    let agent_ctx = if config.enabled {
        // Compute BOM summary strings for the system prompt before bom_store is moved.
        let bom_summary = if bom_store.loaded { bom_store.summary() } else { String::new() };
        let bom_components = if bom_store.loaded && !bom_store.components.is_empty() {
            let top: Vec<String> = bom_store.components.iter().take(20).map(|r| {
                format!("  - {} {} ({}) {}", r.type_display(), r.name_display(), r.version_display(), r.purl_display())
            }).collect();
            Some(top.join("\n"))
        } else { None };
        match agent::create_provider(&config) {
            Ok(provider) => {
                let system_prompt = AgentCtx::build_system_prompt(
                    &summary.language, &summary.version, &summary.rows,
                    Some(&bom_summary), bom_components.as_deref(),
                );
                eprintln!("AI agent enabled: {} ({})", config.provider, config.model);
                Some(AgentCtx {
                    provider,
                    engine: Some(engine_arc.clone()),
                    source_root: source_root.clone(),
                    system_prompt,
                    max_tokens: 8192,
                    no_thinking: config.no_thinking,
                    effort: config.effort.clone(),
                    allowed_tools: None,
                    cancel: Arc::new(AtomicBool::new(false)),
                })
            }
            Err(e) => {
                eprintln!("Warning: failed to create LLM provider: {e}. Agent disabled.");
                None
            }
        }
    } else {
        None
    };

    let mut app = App::new(Some(engine_arc), atom_str, summary);
    if agent_ctx.is_some() {
        app.enable_agent();
    }

    if bom_store.loaded {
        app.bom_store = Some(bom_store);
        app.bom_generated = false;
        app.status = format!("BOM loaded ({} components) — type 'bom' to view", app.bom_store.as_ref().map(|s| s.total_components).unwrap_or(0));
        eprintln!("{}", app.status);
    } else if !bom_tip.is_empty() {
        app.status = bom_tip;
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let result = run_app(&mut terminal, &mut app, &theme, agent_ctx, config, source_root, reports_dir);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

fn run_headless_agent(
    config: Config,
    engine: Engine,
    source_root: Option<String>,
    summary: Summary,
    question: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if !config.enabled {
        eprintln!("AI agent is not enabled. Set ANTHROPIC_API_KEY or OPENAI_API_KEY to enable.");
        std::process::exit(1);
    }
    let provider = agent::create_provider(&config).map_err(|e| format!("provider: {e}"))?;
    let system_prompt = AgentCtx::build_system_prompt(&summary.language, &summary.version, &summary.rows, None, None);
    let ctx = AgentCtx {
        provider,
        engine: Some(Arc::new(Mutex::new(engine))),
        source_root,
        system_prompt,
        max_tokens: 8192,
        no_thinking: config.no_thinking,
                    effort: config.effort.clone(),
                    allowed_tools: None,
        cancel: Arc::new(AtomicBool::new(false)),
    };
    eprintln!("Asking: {question}");
    let result = agent::run_headless(&ctx, &question)?;
    println!("\n{}", result);
    Ok(())
}

fn run_app<B: Backend>(
    terminal: &mut ratatui::Terminal<B>,
    app: &mut App,
    theme: &Theme,
    mut agent_ctx: Option<AgentCtx>,
    config: Config,
    source_root: Option<String>,
    reports_dir: PathBuf,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| ui::render(frame, app, theme))?;

        if app.should_quit { return Ok(()); }

        // Drain agent events every frame (non-blocking).
        if app.agent_active && app.agent_rx.is_some() {
            let was_active = app.agent_active;
            app.drain_agent_events();
            // Auto-save report when agent transitions from running to done.
            if was_active && !app.agent_active && !app.agent_report_saved {
                app.save_report(&reports_dir);
            }
        }

        // Check if the agent just asked to start (execute() set agent_active but no rx yet).
        if app.agent_active && app.agent_rx.is_none() {
            // Recreate agent context if it was consumed by a previous run.
            if agent_ctx.is_none() && config.enabled
                && let Ok(provider) = agent::create_provider(&config) {
                    let bom_summary = app.bom_store.as_ref().map(|s| s.summary());
                    let bom_components_summary = app.bom_store.as_ref().and_then(|s| {
                        if s.loaded && !s.components.is_empty() {
                            let top: Vec<String> = s.components.iter().take(20).map(|r| {
                                format!("  - {} {} ({}) {}", r.type_display(), r.name_display(), r.version_display(), r.purl_display())
                            }).collect();
                            Some(top.join("\n"))
                        } else { None }
                    });
                    let system_prompt = AgentCtx::build_system_prompt(
                        &app.summary.language, &app.summary.version, &app.summary.rows,
                        bom_summary.as_deref(), bom_components_summary.as_deref(),
                    );
                    let cancel = Arc::new(AtomicBool::new(false));
                    app.agent_cancel = Some(cancel.clone());
                    agent_ctx = Some(AgentCtx {
                        provider,
                        engine: app.engine.clone(),
                        source_root: source_root.clone(),
                        system_prompt,
                        max_tokens: 8192,
                        no_thinking: config.no_thinking,
                        effort: config.effort.clone(),
                        allowed_tools: None,
                        cancel,
                    });
                }
            if let Some(ctx) = agent_ctx.take() {
                let question = app.agent_query_text.clone();
                let no_thinking = ctx.no_thinking;
                // A slash command appends its task template to the base system
                // prompt (keeping the atom summary + grounding rules) and may
                // scope the toolset and effort. Free text inherits the defaults.
                let system_prompt = match app.agent_slash_prompt.take() {
                    Some(body) => format!("{}\n\n# Task\n{}", ctx.system_prompt, body),
                    None => ctx.system_prompt.clone(),
                };
                let allowed_tools = app.agent_slash_tools.take();
                let effort = app.agent_slash_effort.take().unwrap_or_else(|| ctx.effort.clone());
                let (tx, rx) = std::sync::mpsc::channel::<agent::provider::AgentEvent>();
                app.agent_rx = Some(rx);
                let engine_for_thread = ctx.engine.clone();
                let cancel_for_thread = ctx.cancel.clone();
                let provider = ctx.provider;
                let max_tokens = ctx.max_tokens;
                let source_root_for_thread = ctx.source_root.clone();

                thread::spawn(move || {
                    let thread_ctx = AgentCtx {
                        provider,
                        engine: engine_for_thread,
                        source_root: source_root_for_thread,
                        system_prompt,
                        max_tokens,
                        no_thinking,
                        effort,
                        allowed_tools,
                        cancel: cancel_for_thread,
                    };
                    agent::run_agent(&thread_ctx, &question, tx);
                });
            }
        }

        // Deferred flow query.
        if let Some(pending) = app.take_pending() {
            app.run_pending(pending);
            continue;
        }

        if !event::poll(std::time::Duration::from_millis(50))? {
            continue;
        }

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                // Ctrl+S saves the current report regardless of panel focus.
                if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    app.save_report(&reports_dir);
                } else {
                    handle_key(app, key);
                }
            }
            Event::Mouse(m) => handle_mouse(app, m),
            _ => {}
        }
    }
}

fn handle_key(app: &mut App, key: KeyEvent) {
    if app.focus == Panel::Repl {
        handle_repl_key(app, key);
        return;
    }

    let code = key.code;

    // Agent view: c = cancel, arrow keys scroll.
    if (app.agent_active || (!app.agent_transcript.is_empty() && app.output.is_none() && app.flows.is_none()))
        && app.focus == Panel::Output
    {
        match code {
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if app.agent_active {
                    app.cancel_agent();
                    app.status = "agent cancelled".into();
                }
                return;
            }
            KeyCode::Char('t') | KeyCode::Char('T') => {
                app.agent_thinking_expanded = !app.agent_thinking_expanded;
                app.status = if app.agent_thinking_expanded { "thinking: expanded" } else { "thinking: collapsed" }.into();
                return;
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                // Exit agent transcript view and show normal output panel.
                app.agent_transcript.clear();
                app.agent_scroll = 0;
                app.status = "agent view cleared".into();
                return;
            }
            KeyCode::Up | KeyCode::Char('k') => { app.agent_scroll_up(); return; }
            KeyCode::Down | KeyCode::Char('j') => { app.agent_scroll_down(); return; }
            KeyCode::Esc => {
                if app.agent_active {
                    app.cancel_agent();
                    app.status = "agent cancelled".into();
                } else {
                    // Clear agent transcript and go back to normal view.
                    app.agent_transcript.clear();
                    app.agent_scroll = 0;
                }
                return;
            }
            _ => {}
        }
    }

    // Filter / sort for the focused Output table.
    if app.focus == Panel::Output && app.output.is_some() {
        if app.table_filter_edit {
            match code {
                KeyCode::Esc => app.clear_table_filter(),
                KeyCode::Enter => app.end_table_filter(),
                KeyCode::Backspace => app.table_filter_backspace(),
                KeyCode::Char(c) => app.table_filter_input(c),
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Char('/') => { app.start_table_filter(); return; }
            KeyCode::Char(d @ '1'..='9') => {
                let col = d as usize - '1' as usize;
                if col < app.table_columns() { app.sort_by_column(col); }
                return;
            }
            _ => {}
        }
    }

    if app.focus == Panel::Output && app.detail_focused {
        match code {
            KeyCode::Up | KeyCode::Char('k') => app.detail_scroll_up(),
            KeyCode::Down | KeyCode::Char('j') => app.detail_scroll_down(),
            KeyCode::Left | KeyCode::Char('h') => app.toggle_detail_focus(),
            KeyCode::Esc => app.close_detail(),
            KeyCode::Tab => app.focus = app.focus.next(),
            KeyCode::BackTab => app.focus = app.focus.prev(),
            _ => {}
        }
        return;
    }

    if app.focus == Panel::Output && app.detail.is_some() {
        match code {
            KeyCode::Esc => { app.close_detail(); return; }
            KeyCode::Right | KeyCode::Char('l') => { app.toggle_detail_focus(); return; }
            _ => {}
        }
    }

    let page = 10usize;
    match code {
        KeyCode::Char('q') | KeyCode::Char('Q') => app.should_quit = true,
        KeyCode::Esc => {
            if app.agent_active {
                app.cancel_agent();
                app.status = "agent cancelled".into();
            } else {
                app.should_quit = true;
            }
        }
        KeyCode::Tab => app.focus = app.focus.next(),
        KeyCode::BackTab => app.focus = app.focus.prev(),

        KeyCode::Up | KeyCode::Char('k') => {
            if let Some((s, _)) = app.focused_list() { s.up(); }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if let Some((s, len)) = app.focused_list() { s.down(len); }
        }
        KeyCode::PageUp | KeyCode::Char('b') => {
            if let Some((s, _)) = app.focused_list() { s.page_up(page); }
        }
        KeyCode::PageDown | KeyCode::Char(' ') => {
            if let Some((s, len)) = app.focused_list() { s.page_down(page, len); }
        }
        KeyCode::Home | KeyCode::Char('g') => {
            if let Some((s, _)) = app.focused_list() { s.home(); }
        }
        KeyCode::End | KeyCode::Char('G') => {
            if let Some((s, len)) = app.focused_list() { s.end(len); }
        }
        KeyCode::Enter => app.on_enter(),

        KeyCode::Right | KeyCode::Char('l') if app.focus == Panel::Output => {
            app.toggle_detail_focus();
        }
        KeyCode::Char('s') => app.toggle_subflows(),
        KeyCode::Char('m') => app.toggle_mitigated(),
        KeyCode::Char('d') | KeyCode::Char('D') => app.run_dataflows(),
        KeyCode::Char('r') | KeyCode::Char('R') => app.run_reachables(),
        _ => {}
    }
}

fn handle_repl_key(app: &mut App, key: KeyEvent) {
    let code = key.code;
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    let is_complete_trigger = (ctrl && matches!(code, KeyCode::Char(' ') | KeyCode::Char('@')))
        || code == KeyCode::Null;
    if is_complete_trigger {
        app.request_completions();
        return;
    }

    if app.repl.is_completing() {
        match code {
            KeyCode::Up => app.repl.completion_up(),
            KeyCode::Down => app.repl.completion_down(),
            KeyCode::Tab | KeyCode::Enter => app.repl.accept_completion(),
            KeyCode::Esc => app.repl.close_completion(),
            _ => {
                app.repl.close_completion();
                handle_repl_edit(app, code);
            }
        }
        return;
    }

    match code {
        KeyCode::Esc => app.should_quit = true,
        KeyCode::Tab => app.focus = app.focus.next(),
        KeyCode::BackTab => app.focus = app.focus.prev(),
        KeyCode::Enter => app.on_enter(),
        _ => handle_repl_edit(app, code),
    }
}

fn handle_repl_edit(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char(c) => app.repl.insert(c),
        KeyCode::Backspace => app.repl.backspace(),
        KeyCode::Delete => app.repl.delete(),
        KeyCode::Left => app.repl.left(),
        KeyCode::Right => app.repl.right(),
        KeyCode::Home => app.repl.home(),
        KeyCode::End => app.repl.end(),
        KeyCode::Up => app.repl.recall_prev(),
        KeyCode::Down => app.repl.recall_next(),
        _ => {}
    }
}

fn handle_mouse(app: &mut App, m: crossterm::event::MouseEvent) {
    match m.kind {
        MouseEventKind::Down(MouseButton::Left) => app.on_click(m.column, m.row),
        MouseEventKind::ScrollDown => app.scroll_at(m.column, m.row, true),
        MouseEventKind::ScrollUp   => app.scroll_at(m.column, m.row, false),
        _ => {}
    }
}
