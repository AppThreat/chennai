mod agent;
mod app;
mod bom;
mod commands;
mod config;
mod engine;
mod model;
mod repl;
mod rusi;
mod ui;

use agent::AgentCtx;
use app::{App, Panel};
use bom::{find_existing_boms, BomStore};
use config::Config;
use engine::Engine;
use model::{OpenInfo, Summary};
use rusi::RusiCtx;
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
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;

/// Interactive terminal UI for exploring chen atoms, with optional AI agent.
#[derive(Parser, Debug)]
#[command(name = "chennai", version)]
struct Args {
    /// Project path (directory or .atom file) to analyse.
    /// Omit this to run a subcommand (e.g. `chennai setup`).
    #[arg()]
    path: Option<PathBuf>,
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
    /// Path to a custom system prompt file. Overrides the built-in system prompt entirely.
    #[arg(long)]
    system_prompt: Option<PathBuf>,
    /// Subcommand to run instead of launching the TUI.
    #[command(subcommand)]
    command: Option<CliCommand>,
}

/// Subcommands for auxiliary operations.
#[derive(Parser, Debug)]
enum CliCommand {
    /// Install or reinstall the analysis tools (cdxgen, atom, atom-parsetools) via npm.
    Setup,
    /// Dump the full system prompt as markdown and exit. Optionally write to a file with `-o`.
    #[command(name = "dump-system-prompt")]
    DumpSystemPrompt {
        /// Project path (directory or .atom file) to build the prompt for.
        #[arg()]
        path: Option<PathBuf>,
        /// Source root directory.
        #[arg(long)]
        source: Option<String>,
        /// Override engine binary path.
        #[arg(long)]
        engine: Option<String>,
        /// Output file path (defaults to stdout).
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Check for subcommands before anything else.
    if let Some(cmd) = &args.command {
        return run_subcommand(cmd);
    }

    // Load custom system prompt if provided.
    let custom_system_prompt = match &args.system_prompt {
        Some(p) => {
            let content = std::fs::read_to_string(p)
                .map_err(|e| format!("failed to read system prompt file '{}': {e}", p.display()))?;
            eprintln!("Using custom system prompt from: {}", p.display());
            Some(content)
        }
        None => None,
    };

    // The TUI requires a path; make sure one was provided.
    let path = args.path.as_ref().ok_or(
        "a project path (directory or .atom file) is required — use `chennai setup` to install tools"
    )?;

    let config = Config::load_with_base_url(args.provider.as_deref(), args.model.as_deref(), args.api_key.as_deref(), args.base_url.as_deref(), args.no_thinking, args.effort.as_deref());
    let theme = match args.theme.as_str() { "light" => Theme::light(), _ => Theme::dark() };
    let source_root = args.source.clone();

    // Detect the language to decide the analysis mode.
    let source_dir = source_root.as_ref().map(PathBuf::from).unwrap_or_else(|| path.to_path_buf());
    let language = bom::detect_language(&source_dir);
    let is_non_atom = matches!(language.as_deref(), Some("rust" | "go" | "dotnet"));

    if is_non_atom {
        return run_non_atom_mode(
            path, &source_root, &source_dir, &language, &config, &theme,
            custom_system_prompt, args.ask.clone(), args.reports_dir.clone(),
        );
    }

    // --- Atom mode (existing flow) ---
    let atom = resolve_or_generate_atom(path, &args.source, args.ask.is_some())?;
    let atom_str = atom.to_string_lossy().to_string();
    let command = Engine::resolve_command(args.engine.as_deref()).ok_or(
        "engine binary not found; build it with `sbt stage` in engine/, or set CHENNAI_ENGINE",
    )?;

    eprintln!("Spawning engine: {}", command.display());
    let mut eng = Engine::spawn(&command)?;

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
            let supported = language.as_deref().map(|l| matches!(l, "java" | "js" | "py" | "php" | "rb")).unwrap_or(false);
            let mut generated = false;
            if !supported {
                bom_tip = "Auto SBOM generation is not available for this language. Generate manually with: cdxgen -o sbom.cdx.json <source_dir>".into();
            }
            if supported {
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
            }
            if !generated {
                bom_tip = "No SBOM found. Generate one with: cdxgen -o sbom-<lang>-<lifecycle>.cdx.json <source_dir> (npm install -g @cyclonedx/cdxgen)".into();
                eprintln!("Tip: {bom_tip}");
            }
        }
    }

    // Build optional agent context for the TUI.
    let agent_ctx = if config.enabled {
        let bom_summary = if bom_store.loaded { bom_store.summary() } else { String::new() };
        let bom_components = if bom_store.loaded && !bom_store.components.is_empty() {
            let top: Vec<String> = bom_store.components.iter().take(20).map(|r| {
                format!("  - {} {} ({}) {}", r.type_display(), r.name_display(), r.version_display(), r.purl_display())
            }).collect();
            Some(top.join("\n"))
        } else { None };
        match agent::create_provider(&config) {
            Ok(provider) => {
                let system_prompt = match &custom_system_prompt {
                    Some(sp) => sp.clone(),
                    None => AgentCtx::build_system_prompt(
                        &summary.language, &summary.version, &summary.rows,
                        Some(&bom_summary), bom_components.as_deref(), None,
                    ),
                };
                eprintln!("AI agent enabled: {} ({})", config.provider, config.model);
                Some(AgentCtx {
                    provider,
                    engine: Some(engine_arc.clone()),
                    rusi: None,
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

    let result = run_app(&mut terminal, &mut app, &theme, agent_ctx, config, source_root, reports_dir, custom_system_prompt);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

#[allow(clippy::too_many_arguments)]
fn run_non_atom_mode(
    _path: &Path,
    source_root: &Option<String>,
    source_dir: &Path,
    language: &Option<String>,
    config: &Config,
    theme: &Theme,
    custom_system_prompt: Option<String>,
    ask: Option<String>,
    reports_dir_cli: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let reports_dir = reports_dir_cli.unwrap_or_else(|| {
        PathBuf::from(source_dir).join(".chen").join("chennai-reports")
    });
    let bom_store = find_existing_boms(&reports_dir);
    let mut bom_store = if bom_store.loaded { bom_store } else {
        find_existing_boms(source_dir)
    };

    // Try to generate SBOM if none exists
    if !bom_store.loaded {
        let sdir = source_dir;
        let odir = &reports_dir;
        for lifecycle in bom::LIFECYCLES {
            if let Ok(path) = bom::generate_bom(sdir, odir, lifecycle, language.as_deref()) {
                let mut store = BomStore::new();
                if store.load_path(&path).is_ok() {
                    bom_store = store;
                    break;
                }
            }
        }
    }

    let bom_summary = if bom_store.loaded { bom_store.summary() } else { String::new() };
    let bom_components = if bom_store.loaded && !bom_store.components.is_empty() {
        let top: Vec<String> = bom_store.components.iter().take(20).map(|r| {
            format!("  - {} {} ({}) {}", r.type_display(), r.name_display(), r.version_display(), r.purl_display())
        }).collect();
        Some(top.join("\n"))
    } else { None };

    let source_root_str = source_root.clone().unwrap_or_else(|| source_dir.to_string_lossy().to_string());

    // For Rust, try to load or generate rusi report.
    let headless = ask.is_some();
    let rusi_ctx: Option<Arc<RusiCtx>> = if language.as_deref() == Some("rust") {
        match load_or_generate_rusi(source_dir, headless) {
            Ok(ctx) => {
                eprintln!("Rusi analysis loaded for Rust codebase");
                Some(Arc::new(ctx))
            }
            Err(e) => {
                eprintln!("Warning: rusi analysis unavailable: {e}. Proceeding with shell tools only.");
                None
            }
        }
    } else {
        None
    };

    let summary_text = rusi_ctx.as_ref().map(|r| r.summary()).unwrap_or_else(|| {
        format!("Language: {lang}\nNo structured analysis available. Use ripgrep/read_file to explore the codebase.", lang = language.as_deref().unwrap_or("unknown"))
    });

    // Build the system prompt.
    let system_prompt = match custom_system_prompt {
        Some(sp) => sp,
        None => {
            if rusi_ctx.is_some() {
                crate::rusi::build_rusi_system_prompt(&summary_text, Some(&bom_summary), bom_components.as_deref(), None)
            } else {
                build_agent_only_prompt(language.as_deref().unwrap_or("unknown"), &summary_text, &bom_summary, bom_components.as_deref())
            }
        }
    };

    if let Some(question) = ask {
        return run_headless_agent_non_atom(config, rusi_ctx, source_root_str, system_prompt, question);
    }

    let mut app = App::new(None, source_dir.to_string_lossy().to_string(), Summary::default());
    app.atom_path = source_dir.to_string_lossy().to_string();
    app.rusi = rusi_ctx.clone();

    if bom_store.loaded {
        app.bom_store = Some(bom_store);
        app.bom_generated = false;
        app.status = format!(
            "BOM loaded ({} components). AI agent is your primary interface.",
            app.bom_store.as_ref().map(|s| s.total_components).unwrap_or(0)
        );
        eprintln!("{}", app.status);
    } else {
        app.status = "No SBOM found. Generate with: cdxgen -o sbom.cdx.json <source_dir>".into();
        eprintln!("Tip: {}", app.status);
    }

    let agent_ctx = if config.enabled {
        match agent::create_provider(config) {
            Ok(provider) => {
                eprintln!("AI agent enabled: {} ({})", config.provider, config.model);
                Some(AgentCtx {
                    provider,
                    engine: None,
                    rusi: rusi_ctx.clone(),
                    source_root: Some(source_root_str.clone()),
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

    if agent_ctx.is_some() {
        app.enable_agent();
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let result = run_app(&mut terminal, &mut app, theme, agent_ctx, config.clone(), Some(source_root_str), reports_dir, None);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Try to load an existing rusi report or run rusi to generate one.
/// When `headless` is true, skip interactive prompts and auto-run rusi.
fn load_or_generate_rusi(source_dir: &Path, headless: bool) -> Result<RusiCtx, String> {
    let report_path = rusi::rusi_report_path(source_dir);

    // If report already exists, load it.
    if report_path.is_file() {
        eprintln!("Loading existing rusi report: {}", report_path.display());
        let report = rusi::loader::LoadedReport::from_file(&report_path)?;
        return Ok(RusiCtx {
            report,
            source_root: source_dir.to_string_lossy().to_string(),
            callgraph_path: None,
            dataflow_path: None,
        });
    }

    // In headless mode, auto-run without prompting.
    if headless {
        eprintln!("No rusi report found. Running rusi analysis (headless)...");
        let out_path = rusi::run_rusi(source_dir)?;
        let report = rusi::loader::LoadedReport::from_file(&out_path)?;
        return Ok(RusiCtx {
            report,
            source_root: source_dir.to_string_lossy().to_string(),
            callgraph_path: Some(source_dir.join("callgraph.graphml").to_string_lossy().to_string()),
            dataflow_path: Some(source_dir.join("dataflow.graphml").to_string_lossy().to_string()),
        });
    }

    // Otherwise, prompt the user and run rusi.
    let msg = format!(
        "No rusi analysis found for {d}\n\
         Run rusi to analyze this Rust codebase? This may take a few minutes.",
        d = source_dir.display()
    );
    if !bom::prompt_yes_no(&msg) {
        return Err("rusi analysis cancelled by user".into());
    }

    eprint!("Running rusi analysis... ");
    let _ = std::io::stderr().flush();
    let out_path = rusi::run_rusi(source_dir)?;
    eprintln!("done.");

    let report = rusi::loader::LoadedReport::from_file(&out_path)?;
    Ok(RusiCtx {
        report,
        source_root: source_dir.to_string_lossy().to_string(),
        callgraph_path: Some(source_dir.join("callgraph.graphml").to_string_lossy().to_string()),
        dataflow_path: Some(source_dir.join("dataflow.graphml").to_string_lossy().to_string()),
    })
}

/// Build a minimal system prompt for agent-only mode (no structured analysis data).
fn build_agent_only_prompt(
    language: &str,
    _summary_text: &str,
    bom_summary: &str,
    bom_components: Option<&str>,
) -> String {
    let bom_section = match (bom_summary, bom_components) {
        (s, Some(c)) if !s.is_empty() => format!(
            r#"
## Software Bill of Materials (CycloneDX SBOM)
{s}

Key components:
{c}
"#
        ),
        _ => String::new(),
    };

    format!(
        r#"You are chennai, an AI-powered code & security analysis agent for a {language} codebase.

## Codebase
Language: {language}
No structured analysis data is available for this language. You must explore the codebase using the shell tools available to you.

## Available tools
- ripgrep — Search source code with regex (confined to the project root).
- read_file — Read source files (use line ranges for precise context).
- git_diff / git_log / git_show — Read-only git history.
- bom_query — Query the CycloneDX SBOM for dependency information.{bom_section}

## How to analyze
1. Use ripgrep to find relevant code patterns, imports, and function definitions.
2. Use read_file to inspect source code in detail around points of interest.
3. Trace data flows manually by reading source code and following function calls.
4. Cross-reference your findings with the SBOM to identify vulnerable dependencies.
5. Every finding must cite file:line evidence from source text or ripgrep results.

## Grounding rules
1. NEVER invent call graphs, data flows, taints, sinks, or security findings. Every claim must trace to source text or a tool result.
2. Use ripgrep to search for code patterns; use read_file to verify context.
3. If you cannot trace a claim through tool results, mark it LOW confidence and say so.
4. For each security finding give file:line with concrete evidence.
5. When available, use the SBOM to understand third-party dependencies.

You are an authorized security review of the user's own code — analyze it directly.
"#)
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
    let system_prompt = AgentCtx::build_system_prompt(&summary.language, &summary.version, &summary.rows, None, None, None);
    let ctx = AgentCtx {
        provider,
        engine: Some(Arc::new(Mutex::new(engine))),
        rusi: None,
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

/// Headless agent for non-atom modes (rusi or agent-only).
fn run_headless_agent_non_atom(
    config: &Config,
    rusi_ctx: Option<Arc<RusiCtx>>,
    source_root: String,
    system_prompt: String,
    question: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if !config.enabled {
        eprintln!("AI agent is not enabled. Set ANTHROPIC_API_KEY or OPENAI_API_KEY to enable.");
        std::process::exit(1);
    }
    let provider = agent::create_provider(config).map_err(|e| format!("provider: {e}"))?;
    let ctx = AgentCtx {
        provider,
        engine: None,
        rusi: rusi_ctx,
        source_root: Some(source_root),
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

#[allow(clippy::too_many_arguments)]
fn run_app<B: Backend>(
    terminal: &mut ratatui::Terminal<B>,
    app: &mut App,
    theme: &Theme,
    mut agent_ctx: Option<AgentCtx>,
    config: Config,
    source_root: Option<String>,
    reports_dir: PathBuf,
    custom_system_prompt: Option<String>,
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
                    let rusi_for_app = app.rusi.clone();
                    let system_prompt = match &custom_system_prompt {
                        Some(sp) => sp.clone(),
                        None => {
                            let console_history = app.build_console_history();
                            if app.rusi.is_some() {
                                let rusi_summary = app.rusi.as_ref().map(|r| r.summary()).unwrap_or_default();
                                crate::rusi::build_rusi_system_prompt(
                                    &rusi_summary,
                                    bom_summary.as_deref(),
                                    bom_components_summary.as_deref(),
                                    Some(&console_history),
                                )
                            } else {
                                AgentCtx::build_system_prompt(
                                    &app.summary.language, &app.summary.version, &app.summary.rows,
                                    bom_summary.as_deref(), bom_components_summary.as_deref(),
                                    Some(&console_history),
                                )
                            }
                        }
                    };
                    let cancel = Arc::new(AtomicBool::new(false));
                    app.agent_cancel = Some(cancel.clone());
                    agent_ctx = Some(AgentCtx {
                        provider,
                        engine: app.engine.clone(),
                        rusi: rusi_for_app,
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
                let system_prompt = match app.agent_slash_prompt.take() {
                    Some(body) => format!("{}\n\n# Task\n{}", ctx.system_prompt, body),
                    None => ctx.system_prompt.clone(),
                };
                let allowed_tools = app.agent_slash_tools.take();
                let effort = app.agent_slash_effort.take().unwrap_or_else(|| ctx.effort.clone());
                let (tx, rx) = std::sync::mpsc::channel::<agent::provider::AgentEvent>();
                app.agent_rx = Some(rx);
                let engine_for_thread = ctx.engine.clone();
                let rusi_for_thread = ctx.rusi.clone();
                let cancel_for_thread = ctx.cancel.clone();
                let provider = ctx.provider;
                let max_tokens = ctx.max_tokens;
                let source_root_for_thread = ctx.source_root.clone();

                thread::spawn(move || {
                    let thread_ctx = AgentCtx {
                        provider,
                        engine: engine_for_thread,
                        rusi: rusi_for_thread,
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

/// Resolve an atom file from the user-supplied path.  If the path is a directory that does not
/// contain any `.atom` file, interactively offer to generate one (SBOM + atom CLI).
///
/// The function blocks on stderr/stdin **before** the TUI starts, so it can render a plain-text
/// prompt.  In headless mode (`headless = true`, i.e. `--ask` was passed) it fails immediately
/// instead.
fn resolve_or_generate_atom(
    path: &Path,
    source_root: &Option<String>,
    headless: bool,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Fast path: the path is already an atom file.
    if path.is_file() {
        return Ok(path.to_path_buf());
    }

    // Fast path: there is an atom file inside the directory.
    if let Ok(atoms) = std::fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().map(|e| e == "atom").unwrap_or(false))
                .collect::<Vec<_>>()
        })
        .and_then(|mut v| {
            v.sort();
            if v.is_empty() {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no atom"))
            } else {
                Ok(v.into_iter().next().unwrap())
            }
        })
    {
        return Ok(atoms);
    }

    // Scan first-level subdirectories for .atom files.
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir()
                && let Ok(atom) = std::fs::read_dir(&entry_path)
                    .map(|entries| {
                        entries
                            .filter_map(|e| e.ok().map(|e| e.path()))
                            .filter(|p| p.extension().map(|e| e == "atom").unwrap_or(false))
                            .collect::<Vec<_>>()
                    })
                    .and_then(|mut v| {
                        v.sort();
                        if v.is_empty() {
                            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no atom"))
                        } else {
                            Ok(v.into_iter().next().unwrap())
                        }
                    })
            {
                return Ok(atom);
            }
        }
    }

    // No atom found.  If this is a headless run we cannot prompt — bail out.
    if headless {
        return Err(format!(
            "no .atom file in {} — generate one first with: atom --with-data-deps <source_dir>",
            path.display()
        )
        .into());
    }

    let source_dir = source_root
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| path.to_path_buf());

    // ----- tools availability -----------------------------------------------
    let has_atom = bom::find_atom().is_ok();
    let has_cdxgen = bom::find_cdxgen().is_ok();
    let has_npm = bom::find_npm().is_some();

    // ----- auto-install prompt (both tools missing, but npm is available) ----
    if !has_atom && !has_cdxgen && has_npm {
        let msg = format!(
            "No .atom file found in {d}\n\
             Required tools (cdxgen, atom) are not installed.\n\
             Install them automatically via npm?",
            d = path.display()
        );
        if !bom::prompt_yes_no(&msg) {
            eprintln!("Tip: install manually: npm install -g @cyclonedx/cdxgen @appthreat/atom @appthreat/atom-parsetools");
            return Err("atom generation cancelled by user".into());
        }
        eprint!("Installing cdxgen, atom, and atom-parsetools... ");
        let _ = std::io::stderr().flush();
        bom::auto_install_npm()?;
        eprintln!("done.");
    } else if !has_atom || !has_cdxgen {
        let missing = if !has_atom && !has_cdxgen {
            "cdxgen and atom CLI"
        } else if !has_atom {
            "atom CLI"
        } else {
            "cdxgen"
        };
        eprintln!(
            "Tip: {missing} not found. Install with: npm install -g @cyclonedx/cdxgen @appthreat/atom @appthreat/atom-parsetools"
        );
        return Err(format!(
            "no .atom file in {} and {missing} is required for generation",
            path.display()
        )
        .into());
    }

    // ----- generation prompt ------------------------------------------------
    let msg = format!(
        "No .atom file found in {d}\n\
         Generate one for analysis?  This will:\n\
          └ 1. Run cdxgen to produce a CycloneDX SBOM\n\
          └ 2. Run atom --with-data-deps to build the atom file\n\
         \nSource: {src}",
        d = path.display(),
        src = source_dir.display()
    );
    if !bom::prompt_yes_no(&msg) {
        eprintln!("Tip: generate manually: atom --with-data-deps <source_dir>");
        return Err("atom generation cancelled by user".into());
    }

    // ----- step 1: SBOM -----------------------------------------------------
    // Use atom_gen's language detection since atom supports a smaller set of
    // languages than cdxgen. cdxgen auto-detects internally regardless of the
    // --type flag, so passing a slightly broader tag for the filename is fine.
    let language = bom::atom_gen::detect_language(&source_dir).map(|s| s.to_string());
    let language_for_atom = language.as_deref().unwrap_or("all");
    let mut bom_generated = false;
    for lifecycle in bom::LIFECYCLES {
        eprint!("Generating SBOM ({lifecycle})... ");
        let _ = std::io::stderr().flush();
        match bom::generate_bom(&source_dir, &source_dir, lifecycle, language.as_deref()) {
            Ok(_path) => {
                eprintln!("done.");
                bom_generated = true;
                break;
            }
            Err(e) => {
                eprintln!("failed ({e})");
            }
        }
    }
    if !bom_generated {
        eprintln!("Warning: SBOM generation failed — proceeding with atom generation anyway.");
    }

    // ----- step 2: atom -----------------------------------------------------
    let atom_path = bom::atom_output_path(&source_dir);
    eprintln!("Building atom with data-dependencies...");
    let generated_atom = bom::generate_atom(&source_dir, &atom_path, language_for_atom)?;
    eprintln!("Atom generated: {}", generated_atom.display());

    // Verify the file is valid by reading a few bytes.
    let _metadata = std::fs::metadata(&generated_atom)
        .map_err(|e| format!("generated atom is not readable: {e}"))?;

    Ok(generated_atom)
}

/// Dispatch a subcommand and exit.
fn run_subcommand(cmd: &CliCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        CliCommand::Setup => {
            let npm = bom::find_npm()
                .ok_or_else::<Box<dyn std::error::Error>, _>(|| "npm not found on PATH. Install Node.js first.".into())?;
            eprintln!("Using npm: {}", npm.display());
            eprintln!("Installing cdxgen, atom, and atom-parsetools...");
            let result = bom::auto_install_npm();
            match result {
                Ok(_) => {
                    eprintln!("\nSetup complete. You can now run chennai on a project directory.");
                    eprintln!("  chennai /path/to/project");
                    Ok(())
                }
                Err(e) => Err(format!("npm install failed:\n{e}").into()),
            }
        }
        CliCommand::DumpSystemPrompt { path, source, engine, output } => {
            let prompt = if let Some(p) = path {
                build_dump_prompt(p, source.as_deref(), engine.as_deref())?
            } else {
                build_template_prompt()
            };

            match output {
                Some(out) => {
                    std::fs::write(out, &prompt)
                        .map_err(|e| format!("failed to write system prompt: {e}"))?;
                    eprintln!("System prompt written to: {}", out.display());
                }
                None => {
                    println!("{prompt}");
                }
            }
            Ok(())
        }
    }
}

/// Build the full system prompt for a given project path (dump mode — no BOM enrichment).
fn build_dump_prompt(
    path: &Path,
    source_root: Option<&str>,
    engine_cmd: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Detect language and route to the appropriate analysis mode.
    let source_dir = source_root.map(PathBuf::from).unwrap_or_else(|| path.to_path_buf());
    let language = bom::detect_language(&source_dir);
    let is_non_atom = matches!(language.as_deref(), Some("rust" | "go" | "dotnet"));

    if is_non_atom {
        return build_dump_prompt_non_atom(&source_dir, &language);
    }

    let atom = resolve_or_generate_atom(path, &source_root.map(|s| s.to_string()), true)?;
    let atom_str = atom.to_string_lossy().to_string();
    let command = Engine::resolve_command(engine_cmd).ok_or(
        "engine binary not found; build it with `sbt stage` in engine/, or set CHENNAI_ENGINE",
    )?;
    let mut eng = Engine::spawn(&command)?;
    let open_args = match source_root {
        Some(src) => json!({ "path": atom_str, "sourceRoot": src }),
        None      => json!({ "path": atom_str }),
    };
    let _open: OpenInfo = eng.request("open", open_args)?;
    let summary: Summary = eng.request("summary", json!({}))?;
    let prompt = AgentCtx::build_system_prompt(
        &summary.language, &summary.version, &summary.rows,
        None, None, None,
    );
    Ok(prompt)
}

/// Build the system prompt for a non-atom language project (dump mode).
fn build_dump_prompt_non_atom(
    source_dir: &Path,
    language: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    if language.as_deref() == Some("rust") {
        let rusi_ctx = load_or_generate_rusi(source_dir, true)
            .map_err(|e| format!("rusi: {e}"))?;
        let summary_text = rusi_ctx.summary();
        let prompt = crate::rusi::build_rusi_system_prompt(&summary_text, None, None, None);
        Ok(prompt)
    } else {
        let lang = language.as_deref().unwrap_or("unknown");
        let summary_text = format!("Language: {lang}\nNo structured analysis available.");
        let prompt = build_agent_only_prompt(lang, &summary_text, "", None);
        Ok(prompt)
    }
}

/// Build a template system prompt with placeholder data (no atom required).
fn build_template_prompt() -> String {
    use crate::model::SummaryRow;
    let rows = vec![
        SummaryRow { label: "Files".into(), count: 0 },
        SummaryRow { label: "Methods".into(), count: 0 },
        SummaryRow { label: "Calls".into(), count: 0 },
        SummaryRow { label: "Tags".into(), count: 0 },
    ];
    AgentCtx::build_system_prompt("<language>", "<version>", &rows, None, None, None)
}
