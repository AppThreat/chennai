mod agent;
mod app;
mod blint;
mod bom;
mod commands;
mod config;
mod dosai;
mod engine;
mod golem;
mod model;
mod repl;
mod rusi;
mod shared;
mod ui;

use agent::{AgentCtx, DebugLogger};
use app::{App, BgStatus, BgTaskInfo, InitPhase, Panel};
use bom::{find_existing_boms, BomStore};
use config::Config;
use engine::Engine;
use model::{OpenInfo, Summary};
use crate::shared::backend::Backend as AnalysisBackend;
use blint::{BlintCtx, BlintReports};
#[allow(unused_imports)]
use dosai::{DosaiCtx, DosaiReports};
use golem::GolemCtx;
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
use ratatui::backend::CrosstermBackend;
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
    /// Enable debug logging of custom tool calls (atom_*, bom_*, rusi_*, golem_*,
    /// dosai_*, blint_*) to timestamped JSON files under `.chen/chennai-debug-logs/`.
    #[arg(long, default_value_t = false)]
    debug: bool,
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

    // Default to the current working directory (as an absolute path) when no path is given.
    let path_buf = match args.path.clone() {
        Some(p) => p,
        None => std::env::current_dir()
            .map_err(|e| format!("could not determine the current directory: {e}"))?,
    };
    // Prefer an absolute path over a relative one like "."; fall back to the raw path if
    // canonicalization fails (e.g. the path does not exist yet).
    let path_buf = std::fs::canonicalize(&path_buf).unwrap_or(path_buf);
    let path = &path_buf;

    let mut config = Config::load_with_base_url(args.provider.as_deref(), args.model.as_deref(), args.api_key.as_deref(), args.base_url.as_deref(), args.no_thinking, args.effort.as_deref());
    config.debug = args.debug;
    let theme = match args.theme.as_str() { "light" => Theme::light(), _ => Theme::dark() };
    let source_root = args.source.clone();

    // Detect the language to decide the analysis mode.
    // For file targets, check if it is a binary artifact (APK, IPA, ELF, PE, etc.).
    let source_dir = source_root.as_ref().map(PathBuf::from).unwrap_or_else(|| path.to_path_buf());
    let is_binary_artifact = path.is_file() && is_binary_file(path);
    let language = if is_binary_artifact {
        Some("binary".to_string())
    } else {
        bom::detect_language(&source_dir)
    };
    let is_non_atom = matches!(language.as_deref(), Some("rust" | "go" | "dotnet" | "binary"));

    if is_non_atom {
        return run_non_atom_mode(
            path, &source_root, &source_dir, &language, &config, &theme,
            custom_system_prompt, args.ask.clone(), args.reports_dir.clone(),
        );
    }

    // --- Atom mode ---

    // Fast path: check for an existing .atom file (non-blocking).
    if let Some(existing_atom) = fast_find_atom(path) {
        let atom_str = existing_atom.to_string_lossy().to_string();
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
            // Fall back to the atom's parent directory when --source is not provided,
            // so the memory store and other source-root-dependent features work.
            let atom_dir = existing_atom.parent().unwrap_or(Path::new(".")).to_string_lossy().to_string();
            let agent_source_root = source_root.clone()
                .or(Some(atom_dir));
            return run_headless_agent(config, eng, agent_source_root, summary, question);
        }

        let engine_arc = Arc::new(Mutex::new(eng));

        let source_path = source_root.as_ref().map(PathBuf::from);
        let reports_dir = args.reports_dir.unwrap_or_else(|| {
            let base = source_root.clone().unwrap_or_else(|| {
                existing_atom.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| ".".into())
            });
            PathBuf::from(base).join(".chen").join("chennai-reports")
        });

        let bom_store = find_existing_boms(reports_dir.as_path());
        let mut bom_store = if bom_store.loaded { bom_store } else {
            find_existing_boms(source_path.as_deref().unwrap_or(Path::new(".")))
        };

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
                            let mut store = BomStore::new();
                            if store.load_path(&path).is_ok() {
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

        // The agent's BOM tool reconstructs the SBOM store from `source_root`. Fall back to
        // the project directory when `--source` wasn't passed (matching the non-atom paths),
        // otherwise `bom_query` reports "no source root configured" even when an SBOM exists.
        let agent_source_root = source_root.clone()
            .or_else(|| Some(source_dir.to_string_lossy().to_string()));

        // If this atom (e.g. an APK/JAR) also has a blint report nearby, expose blint_* tools too.
        let atom_dir = existing_atom.parent().unwrap_or(Path::new(".")).to_path_buf();
        let aux_backend: Option<BackendCtx> =
            find_aux_blint_backend(&[atom_dir.as_path(), reports_dir.as_path()]).map(|c| Box::new(c) as BackendCtx);

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
                    let memory_index = crate::agent::memory::FactStore::open(agent_source_root.as_deref())
                        .map(|s| s.index_markdown());
                    let memory_section = memory_index.as_deref().filter(|s| *s != "none yet").map(|idx| {
                        format!(
                            "\n## Project memory (facts learned in previous sessions — HINTS, re-verify before reporting)\n\
                             {idx}\n\
                             Use the project_memory tool (action:\"recall\"/\"search\") to read a fact's full body.\n"
                        )
                    }).unwrap_or_default();
                    let system_prompt = match &custom_system_prompt {
                        Some(sp) => format!("{sp}{memory_section}"),
                        None => {
                            AgentCtx::build_system_prompt(
                                &summary.language, &summary.version, &summary.rows,
                                Some(&bom_summary), bom_components.as_deref(), None,
                                memory_index.as_deref(),
                            )
                        }
                    };
                    eprintln!("AI agent enabled: {} ({})", config.provider, config.model);
                    Some(AgentCtx {
                        provider,
                        engine: Some(engine_arc.clone()),
                        backend: aux_backend.as_ref().map(|b| b.clone_box()),
                        source_root: agent_source_root.clone(),
                        system_prompt,
                        max_tokens: 8192,
                        no_thinking: config.no_thinking,
                        effort: config.effort.clone(),
                        allowed_tools: None,
                        cancel: Arc::new(AtomicBool::new(false)),
                        debug_logger: if config.debug { DebugLogger::new(agent_source_root.as_deref()) } else { None },
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

        let mut app = App::new(Some(engine_arc), atom_str, summary, agent_source_root.clone());
        // Keep the aux blint backend on the app so the agent-context recreation path
        // (which reads app.backend) preserves blint_* tools across runs.
        app.backend = aux_backend;
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
        app.generate_starter_questions();

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = ratatui::Terminal::new(backend)?;

        let result = run_app(&mut terminal, &mut app, &theme, agent_ctx, config, source_root, reports_dir, custom_system_prompt);

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
        terminal.show_cursor()?;

        return result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
    }

    // Slow path: no atom found — generate in background.
    {
        if args.ask.is_some() {
            return Err(format!(
                "no .atom file in {} — generate one first with: atom --with-data-deps <source_dir>",
                path.display()
            ).into());
        }

        let source_dir = source_root.as_ref().map(PathBuf::from).unwrap_or_else(|| path.to_path_buf());

        // Tools availability + auto-install prompt.
        let has_atom = bom::find_atom().is_ok();
        let has_cdxgen = bom::find_cdxgen().is_ok();
        let has_npm = bom::find_npm().is_some();

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
            return Err(format!(
                "no .atom file in {} and {missing} is required for generation",
                path.display()
            ).into());
        }

        // Generation prompt.
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

        let language = bom::atom_gen::detect_language(&source_dir).map(|s| s.to_string());
        let language_for_atom = language.as_deref().unwrap_or("all").to_string();
        let reports_dir = args.reports_dir.unwrap_or_else(|| {
            PathBuf::from(&source_dir).join(".chen").join("chennai-reports")
        });
        let atom_path = bom::atom_output_path(&source_dir);
        let engine_cmd = Engine::resolve_command(args.engine.as_deref()).ok_or(
            "engine binary not found; build it with `sbt stage` in engine/, or set CHENNAI_ENGINE",
        )?;

        // Spawn background generation tasks.
        let bg_progress = Arc::new(Mutex::new(Vec::new()));

        // cdxgen task.
        {
            bg_progress.lock().unwrap().push(BgTaskInfo { name: "cdxgen".into(), status: BgStatus::Running });
            let progress = bg_progress.clone();
            let sdir = source_dir.clone();
            let lang = language.clone();
            let rdir = reports_dir.clone();
            thread::spawn(move || {
                let mut last_err = None;
                for lifecycle in bom::LIFECYCLES {
                    match bom::generate_bom(&sdir, &rdir, lifecycle, lang.as_deref()) {
                        Ok(_) => {
                            let mut tasks = progress.lock().unwrap();
                            if let Some(t) = tasks.iter_mut().find(|t| t.name == "cdxgen") {
                                t.status = BgStatus::Done;
                            }
                            return;
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                let mut tasks = progress.lock().unwrap();
                if let Some(t) = tasks.iter_mut().find(|t| t.name == "cdxgen") {
                    t.status = BgStatus::Failed(last_err.unwrap_or_else(|| "cdxgen failed".into()));
                }
            });
        }

        // atom task (waits for cdxgen to complete).
        {
            bg_progress.lock().unwrap().push(BgTaskInfo { name: "atom".into(), status: BgStatus::Running });
            let progress = bg_progress.clone();
            let sdir = source_dir.clone();
            let apath = atom_path.clone();
            let lang = language_for_atom.clone();
            thread::spawn(move || {
                // Wait for cdxgen.
                loop {
                    let cdxgen_done = {
                        let tasks = progress.lock().unwrap();
                        tasks.iter().find(|t| t.name == "cdxgen")
                            .map(|t| t.status != BgStatus::Running)
                            .unwrap_or(true)
                    };
                    if cdxgen_done {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                match bom::generate_atom(&sdir, &apath, &lang) {
                    Ok(_) => {
                        let mut tasks = progress.lock().unwrap();
                        if let Some(t) = tasks.iter_mut().find(|t| t.name == "atom") {
                            t.status = BgStatus::Done;
                        }
                    }
                    Err(e) => {
                        let mut tasks = progress.lock().unwrap();
                        if let Some(t) = tasks.iter_mut().find(|t| t.name == "atom") {
                            t.status = BgStatus::Failed(e);
                        }
                    }
                }
            });
        }

        // Create App with deferred init.
        let mut app = App::new(None, "generating...".into(), Summary::default(), source_root.clone());
        app.bg_progress = bg_progress;
        app.init_phase = InitPhase::Starting;
        app.deferred_atom_path = Some(atom_path.to_string_lossy().to_string());
        app.deferred_engine_cmd = Some(engine_cmd.to_string_lossy().to_string());
        app.deferred_reports_dir = Some(reports_dir.to_string_lossy().to_string());

        // See the fast-path note: fall back to the project directory so the agent's
        // BOM tool can locate the SBOM when `--source` wasn't passed.
        let agent_source_root = source_root.clone()
            .or_else(|| Some(source_dir.to_string_lossy().to_string()));

        let agent_ctx = if config.enabled {
            match agent::create_provider(&config) {
                Ok(provider) => {
                    eprintln!("AI agent enabled: {} ({})", config.provider, config.model);
                    Some(AgentCtx {
                        provider,
                        engine: None,
                        backend: None,
                        source_root: agent_source_root.clone(),
                        system_prompt: String::new(),
                        max_tokens: 8192,
                        no_thinking: config.no_thinking,
                        effort: config.effort.clone(),
                        allowed_tools: None,
                        cancel: Arc::new(AtomicBool::new(false)),
                        debug_logger: if config.debug { DebugLogger::new(agent_source_root.as_deref()) } else { None },
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
        app.generate_starter_questions();

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = ratatui::Terminal::new(backend)?;

        let result = run_app(&mut terminal, &mut app, &theme, agent_ctx, config, agent_source_root, reports_dir, custom_system_prompt);

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
        terminal.show_cursor()?;

        result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
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

    // Try to load existing report for each backend (fast file check).
    let existing_backend: Option<BackendCtx> = match language.as_deref() {
        Some("rust") => {
            locate_report_dir(rusi::runner::RUSI_REPORT_FILENAME, &reports_dir, source_dir)
                .and_then(|dir| rusi::loader::LoadedReport::from_file(&rusi::rusi_report_path(&dir)).ok())
                .map(|report| {
                    Box::new(RusiCtx {
                        report,
                        source_root: source_dir.to_string_lossy().to_string(),
                        callgraph_path: None,
                        dataflow_path: None,
                    }) as BackendCtx
                })
        }
        Some("go") => {
            locate_report_dir(golem::runner::GOLEM_REPORT_FILENAME, &reports_dir, source_dir)
                .and_then(|dir| golem::loader::LoadedReport::from_file(&golem::golem_report_path(&dir)).ok())
                .map(|report| {
                    Box::new(GolemCtx {
                        report,
                        source_root: source_dir.to_string_lossy().to_string(),
                        callgraph_path: None,
                        dataflow_path: None,
                    }) as BackendCtx
                })
        }
        Some("dotnet") => {
            locate_report_dir(dosai::runner::DOSAI_DATAFLOWS_FILENAME, &reports_dir, source_dir)
                .and_then(|dir| dosai::loader::DosaiReports::load(&dir).ok())
                .map(|reports| {
                    Box::new(DosaiCtx {
                        dataflows: reports.dataflows,
                        methods: reports.methods,
                        crypto: reports.crypto,
                        source_root: source_dir.to_string_lossy().to_string(),
                    }) as BackendCtx
                })
        }
        Some("binary") => {
            load_blint_backend(source_dir, &reports_dir).map(|ctx| Box::new(ctx) as BackendCtx)
        }
        _ => None,
    };

    // Fast path: all data already exists — proceed synchronously as before.
    let bom_ready = bom_store.loaded;
    let backend_ready = existing_backend.is_some() || !matches!(language.as_deref(), Some("rust" | "go" | "dotnet" | "binary"));
    if bom_ready && backend_ready {
        return finish_non_atom_startup(
            source_dir, source_root, language, config, theme,
            custom_system_prompt, ask, reports_dir,
            bom_store, existing_backend,
        );
    }

    // Headless mode: generate synchronously.
    if ask.is_some() {
        if !bom_store.loaded {
            for lifecycle in bom::LIFECYCLES {
                if let Ok(path) = bom::generate_bom(source_dir, &reports_dir, lifecycle, language.as_deref()) {
                    let mut store = BomStore::new();
                    if store.load_path(&path).is_ok() {
                        bom_store = store;
                        break;
                    }
                }
            }
        }
        let backend: Option<BackendCtx> = match language.as_deref() {
            Some("rust") => load_or_generate_rusi(source_dir, &reports_dir, true).ok().map(|ctx| Box::new(ctx) as BackendCtx),
            Some("go") => load_or_generate_golem(source_dir, &reports_dir, true).ok().map(|ctx| Box::new(ctx) as BackendCtx),
            Some("dotnet") => load_or_generate_dosai(source_dir, &reports_dir, true).ok().map(|ctx| Box::new(ctx) as BackendCtx),
            Some("binary") => load_blint_backend(source_dir, &reports_dir).map(|ctx| Box::new(ctx) as BackendCtx),
            _ => None,
        };
        return finish_non_atom_startup(
            source_dir, source_root, language, config, theme,
            custom_system_prompt, ask, reports_dir,
            bom_store, backend,
        );
    }

    // Slow path: spawn background tasks for cdxgen and/or analysis tool.
    let source_root_str = source_root.clone().unwrap_or_else(|| source_dir.to_string_lossy().to_string());
    let bg_progress = Arc::new(Mutex::new(Vec::new()));

    // cdxgen task (if no BOM loaded).
    if !bom_store.loaded {
        bg_progress.lock().unwrap().push(BgTaskInfo { name: "cdxgen".into(), status: BgStatus::Running });
        let progress = bg_progress.clone();
        let sdir = source_dir.to_path_buf();
        let lang = language.clone();
        let rdir = reports_dir.clone();
        thread::spawn(move || {
            let mut last_err = None;
            for lifecycle in bom::LIFECYCLES {
                match bom::generate_bom(&sdir, &rdir, lifecycle, lang.as_deref()) {
                    Ok(_) => {
                        let mut tasks = progress.lock().unwrap();
                        if let Some(t) = tasks.iter_mut().find(|t| t.name == "cdxgen") {
                            t.status = BgStatus::Done;
                        }
                        return;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            let mut tasks = progress.lock().unwrap();
            if let Some(t) = tasks.iter_mut().find(|t| t.name == "cdxgen") {
                t.status = BgStatus::Failed(last_err.unwrap_or_else(|| "cdxgen failed".into()));
            }
        });
    }

    // Backend analysis task (if no existing report).
    if existing_backend.is_none() {
        match language.as_deref() {
            Some("rust") => {
                bg_progress.lock().unwrap().push(BgTaskInfo { name: "rusi".into(), status: BgStatus::Running });
                let progress = bg_progress.clone();
                let sdir = source_dir.to_path_buf();
                let rdir = reports_dir.clone();
                thread::spawn(move || {
                    match rusi::run_rusi(&sdir, &rdir) {
                        Ok(_) => {
                            let mut tasks = progress.lock().unwrap();
                            if let Some(t) = tasks.iter_mut().find(|t| t.name == "rusi") {
                                t.status = BgStatus::Done;
                            }
                        }
                        Err(e) => {
                            let mut tasks = progress.lock().unwrap();
                            if let Some(t) = tasks.iter_mut().find(|t| t.name == "rusi") {
                                t.status = BgStatus::Failed(e);
                            }
                        }
                    }
                });
            }
            Some("go") => {
                bg_progress.lock().unwrap().push(BgTaskInfo { name: "golem".into(), status: BgStatus::Running });
                let progress = bg_progress.clone();
                let sdir = source_dir.to_path_buf();
                let rdir = reports_dir.clone();
                thread::spawn(move || {
                    match golem::run_golem(&sdir, &rdir) {
                        Ok(_) => {
                            let mut tasks = progress.lock().unwrap();
                            if let Some(t) = tasks.iter_mut().find(|t| t.name == "golem") {
                                t.status = BgStatus::Done;
                            }
                        }
                        Err(e) => {
                            let mut tasks = progress.lock().unwrap();
                            if let Some(t) = tasks.iter_mut().find(|t| t.name == "golem") {
                                t.status = BgStatus::Failed(e);
                            }
                        }
                    }
                });
            }
            Some("dotnet") => {
                bg_progress.lock().unwrap().push(BgTaskInfo { name: "dosai".into(), status: BgStatus::Running });
                let progress = bg_progress.clone();
                let sdir = source_dir.to_path_buf();
                let rdir = reports_dir.clone();
                thread::spawn(move || {
                    match dosai::run_dosai(&sdir, &rdir) {
                        Ok(_) => {
                            let mut tasks = progress.lock().unwrap();
                            if let Some(t) = tasks.iter_mut().find(|t| t.name == "dosai") {
                                t.status = BgStatus::Done;
                            }
                        }
                        Err(e) => {
                            let mut tasks = progress.lock().unwrap();
                            if let Some(t) = tasks.iter_mut().find(|t| t.name == "dosai") {
                                t.status = BgStatus::Failed(e);
                            }
                        }
                    }
                });
            }
            _ => {}
        }
    }

    // Create App with deferred init.
    let mut app = App::new(None, source_dir.to_string_lossy().to_string(), Summary::default(), source_root.clone());
    app.non_atom = true;
    app.project_language = language.clone();
    app.focus = Panel::Repl;
    app.atom_path = source_dir.to_string_lossy().to_string();
    app.bg_progress = bg_progress;
    app.init_phase = InitPhase::Starting;
    app.deferred_reports_dir = Some(reports_dir.to_string_lossy().to_string());

    // Set backend context if already loaded (from existing file before bg task).
    if let Some(b) = existing_backend {
        app.backend = Some(b);
    }
    app.generate_starter_questions();

    let backend = app.backend.as_ref().map(|b| b.clone_box());

    let agent_ctx = if config.enabled {
        match agent::create_provider(config) {
            Ok(provider) => {
                eprintln!("AI agent enabled: {} ({})", config.provider, config.model);
                Some(AgentCtx {
                    provider,
                    engine: None,
                    backend,
                    source_root: Some(source_root_str.clone()),
                    system_prompt: String::new(),
                    max_tokens: 8192,
                    no_thinking: config.no_thinking,
                    effort: config.effort.clone(),
                    allowed_tools: None,
                    cancel: Arc::new(AtomicBool::new(false)),
                    debug_logger: if config.debug { DebugLogger::new(Some(&source_root_str)) } else { None },
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

/// A boxed backend for non-atom analysis.
pub type BackendCtx = Box<dyn AnalysisBackend>;

/// Locate a pre-generated backend report named `filename`, searching the reports
/// directory first and then the source directory (where a user may have dropped a
/// report manually). Returns the directory that contains it, if any.
fn locate_report_dir(filename: &str, reports_dir: &Path, source_dir: &Path) -> Option<PathBuf> {
    for dir in [reports_dir, source_dir] {
        if dir.join(filename).is_file() {
            return Some(dir.to_path_buf());
        }
    }
    None
}

/// Shared fast-path initialisation for non-atom mode when data already exists.
#[allow(clippy::too_many_arguments)]
fn finish_non_atom_startup(
    source_dir: &Path,
    source_root: &Option<String>,
    language: &Option<String>,
    config: &Config,
    theme: &Theme,
    custom_system_prompt: Option<String>,
    ask: Option<String>,
    reports_dir: PathBuf,
    bom_store: BomStore,
    backend: Option<BackendCtx>,
) -> Result<(), Box<dyn std::error::Error>> {
    let source_root_str = source_root.clone().unwrap_or_else(|| source_dir.to_string_lossy().to_string());
    let bom_summary = if bom_store.loaded { bom_store.summary() } else { String::new() };
    let bom_components = if bom_store.loaded && !bom_store.components.is_empty() {
        let top: Vec<String> = bom_store.components.iter().take(20).map(|r| {
            format!("  - {} {} ({}) {}", r.type_display(), r.name_display(), r.version_display(), r.purl_display())
        }).collect();
        Some(top.join("\n"))
    } else { None };

    let summary_text = match &backend {
        Some(ctx) => ctx.summary(),
        None => format!("Language: {lang}\nNo structured analysis available. Use ripgrep/read_file to explore the codebase.", lang = language.as_deref().unwrap_or("unknown")),
    };

    let memory_index = crate::agent::memory::FactStore::open(Some(&source_root_str))
        .map(|s| s.index_markdown())
        .filter(|s| s != "none yet");
    let memory_section = memory_index.as_ref().map(|idx| {
        format!(
            "\n## Project memory (facts learned in previous sessions — HINTS, re-verify before reporting)\n\
             {idx}\n\
             Use the project_memory tool (action:\"recall\"/\"search\") to read a fact's full body.\n"
        )
    }).unwrap_or_default();

    let system_prompt = match custom_system_prompt {
        Some(sp) => format!("{sp}{memory_section}"),
        None => match &backend {
            Some(ctx) => format!("{}{memory_section}", ctx.system_prompt(&summary_text, Some(&bom_summary), bom_components.as_deref(), None)),
            None => {
                format!("{}{memory_section}", build_agent_only_prompt(language.as_deref().unwrap_or("unknown"), &summary_text, &bom_summary, bom_components.as_deref()))
            }
        },
    };

    if let Some(question) = ask {
        return run_headless_agent_non_atom(config, backend, source_root_str, system_prompt, question);
    }

    let mut app = App::new(None, source_dir.to_string_lossy().to_string(), Summary::default(), source_root.clone());
    app.non_atom = true;
    app.project_language = language.clone();
    app.focus = Panel::Repl;
    app.atom_path = source_dir.to_string_lossy().to_string();
    app.backend = backend.as_ref().map(|b| b.clone_box());

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

    app.generate_starter_questions();

    let agent_ctx = if config.enabled {
        match agent::create_provider(config) {
            Ok(provider) => {
                eprintln!("AI agent enabled: {} ({})", config.provider, config.model);
                Some(AgentCtx {
                    provider,
                    engine: None,
                    backend: backend.as_ref().map(|b| b.clone_box()),
                    source_root: Some(source_root_str.clone()),
                    system_prompt,
                    max_tokens: 8192,
                    no_thinking: config.no_thinking,
                    effort: config.effort.clone(),
                    allowed_tools: None,
                    cancel: Arc::new(AtomicBool::new(false)),
                    debug_logger: if config.debug { DebugLogger::new(Some(&source_root_str)) } else { None },
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
fn load_or_generate_rusi(source_dir: &Path, reports_dir: &Path, headless: bool) -> Result<RusiCtx, String> {
    let make = |report: rusi::loader::LoadedReport, dir: &Path| RusiCtx {
        report,
        source_root: source_dir.to_string_lossy().to_string(),
        callgraph_path: Some(dir.join(rusi::runner::RUSI_CALLGRAPH_FILENAME).to_string_lossy().to_string()),
        dataflow_path: Some(dir.join(rusi::runner::RUSI_DATAFLOW_FILENAME).to_string_lossy().to_string()),
    };

    // If a report already exists (reports dir preferred, then source dir), load it.
    if let Some(dir) = locate_report_dir(rusi::runner::RUSI_REPORT_FILENAME, reports_dir, source_dir) {
        let report_path = rusi::rusi_report_path(&dir);
        eprintln!("Loading existing rusi report: {}", report_path.display());
        let report = rusi::loader::LoadedReport::from_file(&report_path)?;
        return Ok(make(report, &dir));
    }

    if !headless {
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
    } else {
        eprintln!("No rusi report found. Running rusi analysis (headless)...");
    }

    let out_path = rusi::run_rusi(source_dir, reports_dir)?;
    if !headless {
        eprintln!("done.");
    }
    let report = rusi::loader::LoadedReport::from_file(&out_path)?;
    Ok(make(report, reports_dir))
}

/// Load blint reports for a binary `artifact`, searching the artifact's own directory
/// first and then `reports_dir`. blint names its files after the full artifact filename
/// (including extension). Returns `None` if no metadata file is found.
fn load_blint_backend(artifact: &Path, reports_dir: &Path) -> Option<BlintCtx> {
    let base = artifact.file_name().and_then(|s| s.to_str())?;
    let parent = artifact.parent().unwrap_or(Path::new("."));
    for dir in [parent, reports_dir] {
        if dir.join(format!("{base}-metadata.json")).is_file()
            && let Ok(reports) = BlintReports::load(base, dir)
        {
            return Some(BlintCtx {
                reports,
                artifact_path: artifact.to_string_lossy().to_string(),
            });
        }
    }
    None
}

/// In atom mode, opportunistically load a blint backend so `blint_*` tools are offered
/// alongside `atom_*` for binary artifacts (APK/JAR) that were analyzed by both. Scans
/// each of `dirs` **and their immediate subdirectories** (atom and blint reports may live
/// side by side or one level deep, e.g. `reports/blint-<app>-reports/`) for a blint
/// metadata report (`*-metadata.json` carrying blint markers). Returns `None` when none.
fn find_aux_blint_backend(dirs: &[&Path]) -> Option<BlintCtx> {
    // Expand to the input dirs plus their immediate subdirs, de-duplicated, order-preserving.
    let mut search: Vec<PathBuf> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for dir in dirs {
        for cand in std::iter::once(dir.to_path_buf()).chain(immediate_subdirs(dir)) {
            if seen.insert(cand.clone()) {
                search.push(cand);
            }
        }
    }
    for dir in &search {
        if let Some(ctx) = scan_dir_for_blint(dir) {
            return Some(ctx);
        }
    }
    None
}

/// Immediate (one-level) subdirectories of `dir`, sorted for deterministic scan order.
fn immediate_subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut subs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    subs.sort();
    subs
}

/// Scan a single directory for a blint metadata report and load the full report set if one
/// is found. A `*-metadata.json` qualifies only if it carries blint markers (so an atom or
/// other tool's metadata file isn't mistaken for blint output).
fn scan_dir_for_blint(dir: &Path) -> Option<BlintCtx> {
    let Ok(entries) = std::fs::read_dir(dir) else { return None };
    let mut metas: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).map(|n| n.ends_with("-metadata.json")).unwrap_or(false))
        .collect();
    metas.sort();
    for meta in metas {
        let Ok(report) = crate::shared::LoadedReport::from_file(&meta) else { continue };
        let r = &report.report;
        let is_blint = r.get("exe_type").is_some() || r.get("binary_type").is_some()
            || r.get("disassembled_functions").is_some()
            || r.get("callgraph").map(|c| c.is_object()).unwrap_or(false);
        if !is_blint { continue; }
        let Some(base) = meta.file_name().and_then(|n| n.to_str()).map(|n| n.trim_end_matches("-metadata.json")) else { continue };
        if let Ok(reports) = BlintReports::load(base, dir) {
            eprintln!("Also loaded blint report ({base}) — blint_* tools enabled alongside atom");
            return Some(BlintCtx { reports, artifact_path: base.to_string() });
        }
    }
    None
}

/// Try to load an existing golem report (from `reports_dir` or `source_dir`) or run golem
/// to generate one into `reports_dir`.
fn load_or_generate_golem(source_dir: &Path, reports_dir: &Path, headless: bool) -> Result<GolemCtx, String> {
    let make = |report: golem::loader::LoadedReport| GolemCtx {
        report,
        source_root: source_dir.to_string_lossy().to_string(),
        callgraph_path: None, // golem embeds the call graph in the JSON report; no sidecar
        dataflow_path: None,
    };

    if let Some(dir) = locate_report_dir(golem::runner::GOLEM_REPORT_FILENAME, reports_dir, source_dir) {
        let report_path = golem::golem_report_path(&dir);
        eprintln!("Loading existing golem report: {}", report_path.display());
        return Ok(make(golem::loader::LoadedReport::from_file(&report_path)?));
    }

    if !headless {
        let msg = format!(
            "No golem analysis found for {d}\n\
             Run golem to analyze this Go codebase? This may take a few minutes.",
            d = source_dir.display()
        );
        if !bom::prompt_yes_no(&msg) {
            return Err("golem analysis cancelled by user".into());
        }
        eprint!("Running golem analysis... ");
        let _ = std::io::stderr().flush();
    } else {
        eprintln!("No golem report found. Running golem analysis (headless)...");
    }

    let out_path = golem::run_golem(source_dir, reports_dir)?;
    if !headless {
        eprintln!("done.");
    }
    Ok(make(golem::loader::LoadedReport::from_file(&out_path)?))
}

/// Try to load existing dosai reports (from `reports_dir` or `source_dir`) or run dosai to
/// generate them into `reports_dir`.
fn load_or_generate_dosai(source_dir: &Path, reports_dir: &Path, headless: bool) -> Result<DosaiCtx, String> {
    let make = |reports: dosai::loader::DosaiReports| DosaiCtx {
        dataflows: reports.dataflows,
        methods: reports.methods,
        crypto: reports.crypto,
        source_root: source_dir.to_string_lossy().to_string(),
    };

    if let Some(dir) = locate_report_dir(dosai::runner::DOSAI_DATAFLOWS_FILENAME, reports_dir, source_dir) {
        eprintln!("Loading existing dosai reports from: {}", dir.display());
        return Ok(make(dosai::loader::DosaiReports::load(&dir)?));
    }

    if !headless {
        let msg = format!(
            "No dosai analysis found for {d}\n\
             Run dosai to analyze this .NET codebase? This may take a few minutes.",
            d = source_dir.display()
        );
        if !bom::prompt_yes_no(&msg) {
            return Err("dosai analysis cancelled by user".into());
        }
        eprint!("Running dosai analysis... ");
        let _ = std::io::stderr().flush();
    } else {
        eprintln!("No dosai reports found. Running dosai analysis (headless)...");
    }

    let outputs = dosai::run_dosai(source_dir, reports_dir)?;
    if outputs.is_empty() {
        return Err("dosai analysis produced no output files".into());
    }
    if !headless {
        eprintln!("done.");
    }
    Ok(make(dosai::loader::DosaiReports::load(reports_dir)?))
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

    let identity_rules = crate::shared::backend::PROJECT_IDENTITY_RULES;
    let red_team = crate::shared::backend::RED_TEAM_MISSION;
    let response_style = crate::shared::backend::RESPONSE_STYLE;

    format!(
        r#"You are chennai, an adversarial, red-team code & security analysis agent for a {language} codebase. You think like an attacker and hunt for reachable, exploitable, and previously-unknown weaknesses, not merely known CVEs.

## Codebase
Language: {language}
No structured analysis data is available for this language. You must explore the codebase using the shell tools available to you.

## Available tools
- ripgrep: Search source code with regex (confined to the project root).
- read_file: Read source files (use line ranges for precise context).
- git_diff / git_log / git_show: Read-only git history.
- bom_query: Query the CycloneDX SBOM for dependency information.{bom_section}

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

{identity_rules}

{red_team}

{response_style}

You are an authorized red-team review of the user's own code. Analyze it adversarially and directly: hunt for reachable sinks, missing authn/authz/RBAC, and supply-chain risk, and favor unknown vulnerabilities over known CVEs. Answer concisely with specific file:line references and a concrete exploit path.
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
    let memory_index = crate::agent::memory::FactStore::open(source_root.as_deref())
        .map(|s| s.index_markdown());
    let system_prompt = AgentCtx::build_system_prompt(
        &summary.language, &summary.version, &summary.rows,
        None, None, None, memory_index.as_deref(),
    );
    let debug_logger = if config.debug { DebugLogger::new(source_root.as_deref()) } else { None };
    let ctx = AgentCtx {
        provider,
        engine: Some(Arc::new(Mutex::new(engine))),
        backend: None,
        source_root,
        system_prompt,
        max_tokens: 8192,
        no_thinking: config.no_thinking,
        effort: config.effort.clone(),
        allowed_tools: None,
        cancel: Arc::new(AtomicBool::new(false)),
        debug_logger,
    };
    eprintln!("Asking: {question}");
    let result = agent::run_headless(&ctx, &question)?;
    println!("\n{}", result);
    Ok(())
}

/// Headless agent for non-atom modes (rusi or agent-only).
fn run_headless_agent_non_atom(
    config: &Config,
    backend: Option<BackendCtx>,
    source_root: String,
    system_prompt: String,
    question: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if !config.enabled {
        eprintln!("AI agent is not enabled. Set ANTHROPIC_API_KEY or OPENAI_API_KEY to enable.");
        std::process::exit(1);
    }
    let provider = agent::create_provider(config).map_err(|e| format!("provider: {e}"))?;
    let debug_logger = if config.debug { DebugLogger::new(Some(&source_root)) } else { None };
    let ctx = AgentCtx {
        provider,
        engine: None,
        backend,
        source_root: Some(source_root),
        system_prompt,
        max_tokens: 8192,
        no_thinking: config.no_thinking,
        effort: config.effort.clone(),
        allowed_tools: None,
        cancel: Arc::new(AtomicBool::new(false)),
        debug_logger,
    };
    eprintln!("Asking: {question}");
    let result = agent::run_headless(&ctx, &question)?;
    println!("\n{}", result);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut ratatui::Terminal<B>,
    app: &mut App,
    theme: &Theme,
    mut agent_ctx: Option<AgentCtx>,
    config: Config,
    source_root: Option<String>,
    reports_dir: PathBuf,
    custom_system_prompt: Option<String>,
) -> io::Result<()> {
    // Share the cancel flag of the initial agent context with the app so the UI's
    // `c`/Esc cancel flips the same AtomicBool the first worker thread polls. Without
    // this, the first run's thread uses the ctx's Arc while `cancel_agent` flips the
    // separate Arc created in `enable_agent`, so cancelling silently has no effect.
    // (Subsequent runs re-sync via the ctx recreation path below.)
    if let Some(ref ctx) = agent_ctx {
        app.agent_cancel = Some(ctx.cancel.clone());
    }
    loop {
        terminal.draw(|frame| ui::render(frame, app, theme))?;

        if app.should_quit { return Ok(()); }

        // Poll background startup tasks and run deferred init when all done.
        if app.init_phase == InitPhase::Starting {
            try_complete_startup(app, &source_root, &reports_dir);
            if app.init_phase == InitPhase::Ready {
                eprintln!("Startup complete: {}", app.status);
            }
        }

        // Refine starter questions via a one-shot, time-boxed LLM call. Templates are
        // already shown; this swaps in context-aware ones if the model answers in time.
        if app.starter_refine_pending && config.enabled {
            app.starter_refine_pending = false;
            app.starter_refined = true;
            if let Ok(provider) = agent::create_provider(&config) {
                let context = app.starter_question_context();
                let cancel = Arc::new(AtomicBool::new(false));
                let (tx, rx) = std::sync::mpsc::channel::<Vec<model::StarterQuestion>>();
                app.starter_rx = Some(rx);
                app.starter_cancel = Some(cancel.clone());
                app.starter_deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(12));
                thread::spawn(move || {
                    let pairs = agent::refine_starter_questions(provider.as_ref(), &context, &cancel);
                    let questions = pairs.into_iter()
                        .map(|(label, command)| model::StarterQuestion { label, command })
                        .collect();
                    tx.send(questions).ok();
                });
            }
        }
        if app.starter_rx.is_some() {
            match app.starter_rx.as_ref().unwrap().try_recv() {
                Ok(questions) => {
                    app.apply_refined_starter_questions(questions);
                    app.starter_rx = None;
                    app.starter_cancel = None;
                    app.starter_deadline = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    app.starter_rx = None;
                    app.starter_cancel = None;
                    app.starter_deadline = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    if app.starter_deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                        if let Some(c) = app.starter_cancel.as_ref() { c.store(true, std::sync::atomic::Ordering::SeqCst); }
                        app.starter_rx = None;
                        app.starter_cancel = None;
                        app.starter_deadline = None;
                    }
                }
            }
        }

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
                    // Atom is primary when an engine is open: use the atom system prompt even
                    // if a blint backend is also attached (the backend just adds blint_* tools).
                    // Fall back to the backend prompt only in pure non-atom mode.
                    let memory_index = crate::agent::memory::FactStore::open(source_root.as_deref())
                        .map(|s| s.index_markdown());
                    let memory_section = memory_index.as_deref().filter(|s| *s != "none yet").map(|idx| {
                        format!(
                            "\n## Project memory (facts learned in previous sessions — HINTS, re-verify before reporting)\n\
                             {idx}\n\
                             Use the project_memory tool (action:\"recall\"/\"search\") to read a fact's full body.\n"
                        )
                    }).unwrap_or_default();
                    let system_prompt = if let Some(sp) = &custom_system_prompt {
                        format!("{sp}{memory_section}")
                    } else {
                        let console_history = app.build_console_history();
                        match (&app.engine, &app.backend) {
                            (None, Some(b)) => format!("{}{memory_section}", b.system_prompt(
                                &b.summary(), bom_summary.as_deref(),
                                bom_components_summary.as_deref(), Some(&console_history),
                            )),
                            _ => AgentCtx::build_system_prompt(
                                &app.summary.language, &app.summary.version, &app.summary.rows,
                                bom_summary.as_deref(), bom_components_summary.as_deref(),
                                Some(&console_history), memory_index.as_deref(),
                            ),
                        }
                    };
                    let cancel = Arc::new(AtomicBool::new(false));
                    app.agent_cancel = Some(cancel.clone());
                    agent_ctx = Some(AgentCtx {
                        provider,
                        engine: app.engine.clone(),
                        backend: app.backend.as_ref().map(|b| b.clone_box()),
                        source_root: source_root.clone(),
                        system_prompt,
                        max_tokens: 8192,
                        no_thinking: config.no_thinking,
                        effort: config.effort.clone(),
                        allowed_tools: None,
                        cancel,
                        debug_logger: if config.debug { DebugLogger::new(source_root.as_deref()) } else { None },
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
                let backend_for_thread = ctx.backend.as_ref().map(|b| b.clone_box());
                let cancel_for_thread = ctx.cancel.clone();
                let provider = ctx.provider;
                let max_tokens = ctx.max_tokens;
                let source_root_for_thread = ctx.source_root.clone();
                let debug_logger = ctx.debug_logger.clone();

                thread::spawn(move || {
                    let thread_ctx = AgentCtx {
                        provider,
                        engine: engine_for_thread,
                        backend: backend_for_thread,
                        source_root: source_root_for_thread,
                        system_prompt,
                        max_tokens,
                        no_thinking,
                        effort,
                        allowed_tools,
                        cancel: cancel_for_thread,
                        debug_logger,
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
            KeyCode::PageUp | KeyCode::Char('b') => { app.agent_page_up(); return; }
            KeyCode::PageDown | KeyCode::Char(' ') => { app.agent_page_down(); return; }
            KeyCode::Home | KeyCode::Char('g') => { app.agent_scroll = 0; app.agent_auto_scroll = false; return; }
            KeyCode::End | KeyCode::Char('G') => { app.agent_auto_scroll = true; return; }
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
            KeyCode::Tab => app.focus = app.focus.next(app.non_atom),
            KeyCode::BackTab => app.focus = app.focus.prev(app.non_atom),
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
        KeyCode::Tab => app.focus = app.focus.next(app.non_atom),
        KeyCode::BackTab => app.focus = app.focus.prev(app.non_atom),

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
        KeyCode::Tab => app.focus = app.focus.next(app.non_atom),
        KeyCode::BackTab => app.focus = app.focus.prev(app.non_atom),
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

/// Quick non-blocking check for an existing `.atom` file at `path` or inside it.
/// Returns `None` when no atom is found (meaning generation would be needed).
fn fast_find_atom(path: &Path) -> Option<PathBuf> {
    if path.is_file() {
        return Some(path.to_path_buf());
    }
    if let Ok(entries) = std::fs::read_dir(path) {
        let mut atoms: Vec<_> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|e| e == "atom").unwrap_or(false))
            .collect();
        atoms.sort();
        if let Some(a) = atoms.into_iter().next() {
            return Some(a);
        }
    }
    None
}

/// Complete deferred initialisation after background tasks finish.
/// Called from the event loop when `app.init_phase == InitPhase::Starting`.
fn try_complete_startup(app: &mut App, source_root: &Option<String>, reports_dir: &Path) {
    let all_done = {
        let tasks = app.bg_progress.lock().unwrap();
        tasks.iter().all(|t| t.status != BgStatus::Running)
    };
    if !all_done {
        return;
    }

    // All background tasks done — run deferred init.
    if let Some(atom_path) = app.deferred_atom_path.clone() {
        // Atom mode: spawn engine, open atom, load summary.
        let cmd = match &app.deferred_engine_cmd {
            Some(c) => PathBuf::from(c),
            None => { app.init_phase = InitPhase::Ready; return; }
        };
        let command = match Engine::resolve_command(cmd.to_str()) {
            Some(c) => c,
            None => { app.status = "engine binary not found".into(); app.init_phase = InitPhase::Ready; return; }
        };
        match Engine::spawn(&command) {
            Ok(mut eng) => {
                let open_args = match source_root {
                    Some(src) => json!({ "path": atom_path, "sourceRoot": src }),
                    None      => json!({ "path": atom_path }),
                };
                match eng.request::<OpenInfo>("open", open_args) {
                    Ok(_) => {
                        match eng.request::<Summary>("summary", json!({})) {
                            Ok(summary) => {
                                let engine_arc = Arc::new(Mutex::new(eng));
                                app.engine = Some(engine_arc);
                                app.summary = summary;
                                app.atom_path = atom_path;

                                // Load BOM from the reports directory.
                                let mut bom_store = bom::find_existing_boms(reports_dir);
                                if !bom_store.loaded {
                                    let sp = source_root.as_ref().map(PathBuf::from);
                                    bom_store = bom::find_existing_boms(sp.as_deref().unwrap_or(Path::new(".")));
                                }
                                if bom_store.loaded {
                                    app.bom_store = Some(bom_store);
                                    app.status = format!(
                                        "BOM loaded ({} components) — type 'bom' to view",
                                        app.bom_store.as_ref().map(|s| s.total_components).unwrap_or(0)
                                    );
                                } else {
                                    app.status = "Atom ready. No BOM found.".into();
                                }
                                app.generate_starter_questions();
                                app.init_phase = InitPhase::Ready;
                            }
                            Err(e) => { app.status = format!("engine summary failed: {e}"); app.init_phase = InitPhase::Ready; }
                        }
                    }
                    Err(e) => { app.status = format!("engine open failed: {e}"); app.init_phase = InitPhase::Ready; }
                }
            }
            Err(e) => { app.status = format!("engine spawn failed: {e}"); app.init_phase = InitPhase::Ready; }
        }
    } else {
        // Non-atom mode deferred init: load BOM / rusi (already generated by bg tasks).
        try_complete_non_atom_startup(app, source_root, reports_dir);
    }
}

/// Deferred init for non-atom mode: load generated BOM / backend reports and update App.
fn try_complete_non_atom_startup(app: &mut App, source_root: &Option<String>, reports_dir: &Path) {
    // Load BOM from reports directory.
    let mut bom_store = bom::find_existing_boms(reports_dir);
    if !bom_store.loaded {
        let sp = source_root.as_ref().map(PathBuf::from);
        bom_store = bom::find_existing_boms(sp.as_deref().unwrap_or(Path::new(".")));
    }
    if bom_store.loaded {
        app.bom_store = Some(bom_store);
    }

    // Load the appropriate backend report if not already loaded. Reports are searched
    // in the reports directory first, then the source directory.
    let source_dir = Path::new(&app.atom_path);
    if app.backend.is_none() {
        // Try rusi (Rust)
        if let Some(dir) = locate_report_dir(rusi::runner::RUSI_REPORT_FILENAME, reports_dir, source_dir)
            && let Ok(report) = rusi::loader::LoadedReport::from_file(&rusi::rusi_report_path(&dir))
        {
            app.backend = Some(Box::new(RusiCtx {
                report,
                source_root: app.atom_path.clone(),
                callgraph_path: None,
                dataflow_path: None,
            }));
        }
        // Try golem (Go)
        if app.backend.is_none()
            && let Some(dir) = locate_report_dir(golem::runner::GOLEM_REPORT_FILENAME, reports_dir, source_dir)
            && let Ok(report) = golem::loader::LoadedReport::from_file(&golem::golem_report_path(&dir))
        {
            app.backend = Some(Box::new(GolemCtx {
                report,
                source_root: app.atom_path.clone(),
                callgraph_path: None,
                dataflow_path: None,
            }));
        }
        // Try dosai (.NET)
        if app.backend.is_none()
            && let Some(dir) = locate_report_dir(dosai::runner::DOSAI_DATAFLOWS_FILENAME, reports_dir, source_dir)
            && let Ok(reports) = dosai::loader::DosaiReports::load(&dir)
        {
            app.backend = Some(Box::new(DosaiCtx {
                dataflows: reports.dataflows,
                methods: reports.methods,
                crypto: reports.crypto,
                source_root: app.atom_path.clone(),
            }));
        }
        // Try blint (binary)
        if app.backend.is_none()
            && let Some(ctx) = load_blint_backend(source_dir, reports_dir)
        {
            app.backend = Some(Box::new(ctx));
        }
    }

    let bom_size = app.bom_store.as_ref().map(|s| s.total_components).unwrap_or(0);
    if bom_size > 0 {
        app.status = format!(
            "BOM loaded ({} components). AI agent is your primary interface.",
            bom_size
        );
    } else {
        app.status = "No SBOM found. Generate with: cdxgen -o sbom.cdx.json <source_dir>".into();
    }
    app.generate_starter_questions();
    app.init_phase = InitPhase::Ready;
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
    let memory_index = crate::agent::memory::FactStore::open(source_root)
        .map(|s| s.index_markdown());
    let prompt = AgentCtx::build_system_prompt(
        &summary.language, &summary.version, &summary.rows,
        None, None, None, memory_index.as_deref(),
    );
    Ok(prompt)
}

/// Build the system prompt for a non-atom language project (dump mode).
fn build_dump_prompt_non_atom(
    source_dir: &Path,
    language: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Dump mode has no CLI reports-dir context, so use the default location.
    let reports_dir = source_dir.join(".chen").join("chennai-reports");
    let memory_index = crate::agent::memory::FactStore::open(Some(source_dir.to_str().unwrap_or_default()))
        .map(|s| s.index_markdown())
        .filter(|s| s != "none yet");
    let memory_section = memory_index.as_ref().map(|idx| {
        format!(
            "\n## Project memory (facts learned in previous sessions — HINTS, re-verify before reporting)\n\
             {idx}\n\
             Use the project_memory tool (action:\"recall\"/\"search\") to read a fact's full body.\n"
        )
    }).unwrap_or_default();
    match language.as_deref() {
        Some("rust") => {
            let rusi_ctx = load_or_generate_rusi(source_dir, &reports_dir, true)
                .map_err(|e| format!("rusi: {e}"))?;
            let summary_text = rusi_ctx.summary();
            let prompt = format!("{}{memory_section}", crate::rusi::build_rusi_system_prompt(&summary_text, None, None, None));
            Ok(prompt)
        }
        Some("go") => {
            let golem_ctx = load_or_generate_golem(source_dir, &reports_dir, true)
                .map_err(|e| format!("golem: {e}"))?;
            let summary_text = golem_ctx.summary();
            let prompt = format!("{}{memory_section}", crate::golem::build_golem_system_prompt(&summary_text, None, None, None));
            Ok(prompt)
        }
        Some("dotnet") => {
            let dosai_ctx = load_or_generate_dosai(source_dir, &reports_dir, true)
                .map_err(|e| format!("dosai: {e}"))?;
            let summary_text = dosai_ctx.summary();
            let prompt = format!("{}{memory_section}", crate::dosai::build_dosai_system_prompt(&summary_text, None, None, None));
            Ok(prompt)
        }
        _ => {
            let lang = language.as_deref().unwrap_or("unknown");
            let summary_text = format!("Language: {lang}\nNo structured analysis available.");
            let prompt = format!("{}{memory_section}", build_agent_only_prompt(lang, &summary_text, "", None));
            Ok(prompt)
        }
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
    AgentCtx::build_system_prompt("<language>", "<version>", &rows, None, None, None, None)
}

/// Check whether a file path matches known binary/artifact extensions.
/// Determine whether `path` is a binary artifact that blint should analyze.
///
/// Recognizes known packaging/extension types first (APK/AAB/IPA, shared libraries,
/// PE/Mach-O, WASM), then falls back to sniffing magic bytes so that extension-less
/// native executables (the common case for ELF and Mach-O binaries) are detected too.
fn is_binary_file(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str())
        && matches!(
            ext.to_lowercase().as_str(),
            "apk" | "aab" | "apkm" | "ipa" | "so" | "dll" | "dylib" | "exe" | "wasm" | "elf"
        )
    {
        return true;
    }
    has_binary_magic(path)
}

/// Sniff the leading bytes of `path` for known executable/object magic numbers:
/// ELF (`\x7fELF`), Mach-O (32/64-bit, both endiannesses, and fat binaries),
/// PE (`MZ`), and WebAssembly (`\0asm`).
fn has_binary_magic(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    matches!(
        &magic,
        b"\x7fELF"                         // ELF
            | b"\xfe\xed\xfa\xce"          // Mach-O 32-bit (big-endian)
            | b"\xfe\xed\xfa\xcf"          // Mach-O 64-bit (big-endian)
            | b"\xce\xfa\xed\xfe"          // Mach-O 32-bit (little-endian)
            | b"\xcf\xfa\xed\xfe"          // Mach-O 64-bit (little-endian)
            | b"\xca\xfe\xba\xbe"          // Mach-O universal/fat
            | b"\x00asm"                   // WebAssembly
    ) || &magic[..2] == b"MZ" // PE/DOS executable
}
