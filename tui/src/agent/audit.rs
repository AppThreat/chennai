//! Deterministic audit pipeline: a fixed sequence of sub-agents that runs without
//! an LLM orchestrator deciding which roles to spawn. The pipeline shape and cost
//! envelope are deterministic; the per-stage LLM text is not (recommend effort +
//! temperature 0 where supported).
//!
//! Usage: `chennai audit <path> --json`
//!
//! Default fixed pipeline (reporter MUST be last — it owns `report_finding` and
//! is the crystallisation point):
//!
//!   recon → sink-hunter → taint-prover → auth-boundary → supply-chain → reporter

use super::AgentCtx;
use super::finding::{ProfileSegment, RunProfile};
use super::orchestrator::{finalize_run_with_options, run_subagent};
use super::process_note::ProcessNote;
use super::roles::{discover_roles, is_valid_role_name, resolve_role};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// The default fixed pipeline. Reporter MUST be last.
pub const DEFAULT_PIPELINE: &[&str] = &[
    "recon",
    "sink-hunter",
    "taint-prover",
    "auth-boundary",
    "supply-chain",
    "reporter",
];

/// Outcome of a single stage in the audit pipeline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StageResult {
    /// Role name that was run.
    pub role: String,
    /// The sub-agent's closing synthesis text.
    pub summary: String,
    /// Number of new findings added during this stage.
    pub findings_delta: usize,
    /// Whether the stage completed normally (end_turn) or was truncated by the turn budget.
    pub completed: bool,
    /// Tokens consumed by this stage.
    pub tokens: u64,
    /// Wall-clock time spent on this stage (seconds).
    pub elapsed_secs: f64,
}

/// The complete outcome of an audit run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditOutcome {
    /// The pipeline that was actually executed.
    pub pipeline: Vec<String>,
    /// Per-stage results.
    pub stages: Vec<StageResult>,
    /// Total number of findings after the run.
    pub total_findings: usize,
    /// Number of confirmed findings after the run.
    pub confirmed_findings: usize,
    /// The run profile with per-segment data.
    #[serde(skip)]
    pub profile: RunProfile,
}

/// Run the deterministic audit pipeline (strict mode): a pipeline containing an
/// invalid or undiscovered role name is rejected up front with an error.
///
/// Reuses the orchestrator's building blocks (`run_subagent`, `resolve_role`,
/// `resolve_turn_budget`, `finalize_run`) but drives them in a fixed code-defined
/// order instead of letting an LLM decide.
///
/// On a mid-run provider error, state (ProcessNote, findings, profile) is
/// persisted before returning `Err`, so the interrupted run stays resumable.
pub fn run_audit(
    ctx: &AgentCtx,
    objective: Option<&str>,
    pipeline: Option<&[String]>,
    reports_dir: Option<&Path>,
    stage_turn_budget: Option<u32>,
    include_low_value: bool,
    resume: bool,
) -> Result<AuditOutcome, Box<dyn std::error::Error>> {
    run_audit_impl(
        ctx,
        objective,
        pipeline,
        reports_dir,
        stage_turn_budget,
        false,
        include_low_value,
        resume,
    )
}

/// Run the deterministic audit with `--skip-missing-roles` tolerance: invalid or
/// undiscovered role names are warned about and skipped instead of erroring.
pub fn run_audit_skip_missing(
    ctx: &AgentCtx,
    objective: Option<&str>,
    pipeline: Option<&[String]>,
    reports_dir: Option<&Path>,
    stage_turn_budget: Option<u32>,
    include_low_value: bool,
    resume: bool,
) -> Result<AuditOutcome, Box<dyn std::error::Error>> {
    run_audit_impl(
        ctx,
        objective,
        pipeline,
        reports_dir,
        stage_turn_budget,
        true,
        include_low_value,
        resume,
    )
}

/// Resolve the effective pipeline from an optional override.
///
/// In strict mode (`skip_missing == false`) any invalid or undiscovered role name
/// is a hard error. In lenient mode such names are warned about and dropped. When
/// no override is given the fixed [`DEFAULT_PIPELINE`] is used verbatim.
fn resolve_pipeline(
    base: &Path,
    pipeline: Option<&[String]>,
    skip_missing: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let names = match pipeline {
        None => return Ok(DEFAULT_PIPELINE.iter().map(|s| s.to_string()).collect()),
        Some(names) => names,
    };

    let discovered = discover_roles(base);
    let available = || discovered.keys().cloned().collect::<Vec<_>>().join(", ");
    let mut resolved: Vec<String> = Vec::new();

    for name in names {
        if !is_valid_role_name(name) {
            if skip_missing {
                eprintln!("[audit] WARNING: skipping invalid role name '{name}'");
                continue;
            }
            return Err(format!(
                "invalid role name '{name}': must match ^[a-z0-9][a-z0-9-]{{0,63}}$"
            )
            .into());
        }
        if !discovered.contains_key(name) {
            if skip_missing {
                eprintln!(
                    "[audit] WARNING: skipping unknown role '{name}' (not discovered). Available: {}",
                    available()
                );
                continue;
            }
            return Err(format!(
                "unknown role '{name}': not found in built-in, user-global, or project-local roles. \
                 Available: {}",
                available()
            )
            .into());
        }
        resolved.push(name.clone());
    }

    if resolved.is_empty() {
        return Err("pipeline is empty after validation — nothing to run".into());
    }
    Ok(resolved)
}

/// Shared implementation behind [`run_audit`] and [`run_audit_skip_missing`].
#[allow(clippy::too_many_arguments)]
fn run_audit_impl(
    ctx: &AgentCtx,
    objective: Option<&str>,
    pipeline: Option<&[String]>,
    reports_dir: Option<&Path>,
    stage_turn_budget: Option<u32>,
    skip_missing: bool,
    include_low_value: bool,
    resume: bool,
) -> Result<AuditOutcome, Box<dyn std::error::Error>> {
    // State restoration is gated entirely on --resume: it is the single switch
    // that brings back the Process Note, prior findings, and stage progress. A
    // fresh (non-resume) run starts clean and overwrites any stale on-disk state
    // as it goes, so an earlier run's results can never leak into this one.
    if resume {
        let persisted = ProcessNote::load(ctx.source_root.as_deref());
        if !persisted.is_empty() {
            let mut note = ctx.process_note.lock().unwrap();
            *note = persisted;
            eprintln!("\n[audit] Restored Process Note from .chen/agent-state/");
        }
        let loaded = super::finding::FindingSet::load(ctx.source_root.as_deref());
        if !loaded.findings.is_empty() {
            let mut findings = ctx.findings.lock().unwrap();
            *findings = loaded;
            eprintln!(
                "[audit] Restored {} finding(s) from .chen/agent-state/",
                findings.findings.len()
            );
        }
    }

    let base = ctx
        .source_root
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let pipeline_names = resolve_pipeline(&base, pipeline, skip_missing)?;

    // On resume, load prior stage progress so completed stages are skipped. A
    // fresh run starts with EMPTY progress and overwrites the file as it goes,
    // so stale completions from an earlier run can never cause this run to skip
    // a stage it never executed.
    let mut audit_progress = if resume {
        super::finding::AuditProgress::load(ctx.source_root.as_deref())
    } else {
        super::finding::AuditProgress::default()
    };
    if resume {
        eprintln!(
            "[audit] Resuming — {} stage(s) already completed: {}",
            audit_progress.completed_stages.len(),
            audit_progress.completed_stages.join(", "),
        );
    }

    // Warn (never block) when reporter is not last — it owns report_finding and is
    // the crystallisation point, so findings may not be finalised otherwise.
    if let Some(last) = pipeline_names.last()
        && last != "reporter"
    {
        eprintln!(
            "\n[audit] WARNING: pipeline does not end with 'reporter' ({last}). \
             The reporter stage owns the report_finding tool and is the crystallisation point. \
             Findings may not be properly finalised."
        );
    }

    let run_start = Instant::now();
    let mut stages: Vec<StageResult> = Vec::new();
    let objective_text = objective.unwrap_or("Perform a full security audit of this codebase.");

    if resume {
        eprintln!(
            "[audit] Note: profile totals reflect only stages run this session, not cross-session cumulative cost."
        );
    }

    for role_name in &pipeline_names {
        if ctx.cancel.load(Ordering::Relaxed) {
            eprintln!("\n[audit] Cancelled before stage '{role_name}'.");
            break;
        }

        // On resume, skip stages that already completed.
        if resume && audit_progress.is_completed(role_name) {
            eprintln!("\n[audit] ⏭ Stage '{role_name}' already completed, skipping (resume)");
            stages.push(StageResult {
                role: role_name.clone(),
                summary: "skipped (resumed)".to_string(),
                findings_delta: 0,
                completed: true,
                tokens: 0,
                elapsed_secs: 0.0,
            });
            continue;
        }

        // Snapshot the ledger and findings count before this stage so we can
        // attribute per-stage token/finding deltas.
        let ledger_before = {
            let ledger = ctx.token_ledger.lock().unwrap();
            ledger.snapshot()
        };
        let findings_before = {
            let f = ctx.findings.lock().unwrap();
            f.findings.len()
        };
        let start = Instant::now();

        // Build the seed message from the role body + objective + current Process
        // Note (so each stage sees prior stages' work). Each stage gets a fresh
        // Transcript inside run_subagent (thinking-signature isolation).
        let note_text = {
            let note = ctx.process_note.lock().unwrap();
            note.render()
        };
        let role_def = resolve_role(&base, role_name)
            .ok_or_else(|| format!("failed to resolve role '{role_name}'"))?;
        let mut seed = format!("{}\n\n## Objective\n{}", role_def.body, objective_text);
        if !note_text.is_empty() {
            seed.push_str("\n\n");
            seed.push_str(&note_text);
        }

        // A `--turn-budget` override applies to every stage; otherwise fall back to
        // the role's frontmatter budget, then the built-in per-role default.
        let effective_turns =
            super::resolve_turn_budget(stage_turn_budget, role_name, role_def.max_turns);
        eprintln!("\n[audit] ▶ Stage '{role_name}' (max {effective_turns} turns)...");

        let result = run_subagent(ctx, role_name, &seed, effective_turns);

        // Attribute deltas to this stage.
        let findings_delta = {
            let f = ctx.findings.lock().unwrap();
            f.findings.len().saturating_sub(findings_before)
        };
        let ledger_delta = {
            let ledger = ctx.token_ledger.lock().unwrap();
            ledger.delta_since(&ledger_before)
        };
        let tokens = ledger_delta.total_tokens();
        let elapsed = start.elapsed();

        {
            let mut profile = ctx.run_profile.lock().unwrap();
            profile.push_segment(ProfileSegment {
                label: role_name.clone(),
                tokens: ledger_delta,
                elapsed,
                turns: ledger_delta.turns,
                findings_delta,
                completed: result.completed,
            });
        }

        // Persist progress incrementally after each stage that completes.
        if result.completed {
            let _ = audit_progress.mark_completed(role_name, ctx.source_root.as_deref());
        }

        let status = if result.completed {
            "✓ completed"
        } else {
            "✗ truncated (turn budget exhausted)"
        };
        eprintln!(
            "[audit]   {role_name} — {findings_delta} findings, {tokens} tokens, {:.1}s — {status}",
            elapsed.as_secs_f64(),
        );

        stages.push(StageResult {
            role: role_name.clone(),
            summary: result.summary.clone(),
            findings_delta,
            completed: result.completed,
            tokens,
            elapsed_secs: elapsed.as_secs_f64(),
        });
    }

    // --- Post-run bookkeeping ---
    // Shared with run_orchestrator / run_headless: writes reports, persists the
    // Process Note + findings, prints the ledger summary, records the synthetic
    // "audit-driver" segment (reconciles the profile TOTAL with the ledger), and
    // saves profile.json. All locks are scoped narrowly inside finalize_run to
    // avoid the std-Mutex non-reentrancy deadlock.
    finalize_run_with_options(
        ctx,
        run_start,
        reports_dir,
        Some("audit-driver"),
        include_low_value,
    );

    // Save audit progress one final time so it's up to date even if some stages
    // were truncated (truncated stages are NOT marked completed).
    let _ = audit_progress.save(ctx.source_root.as_deref());

    let (total_findings, confirmed_findings) = {
        let f = ctx.findings.lock().unwrap();
        (f.findings.len(), f.confirmed_count())
    };
    let profile = ctx.run_profile.lock().unwrap().clone();

    Ok(AuditOutcome {
        pipeline: pipeline_names,
        stages,
        total_findings,
        confirmed_findings,
        profile,
    })
}

/// Render the `chennai.audit.v1` JSON schema for the audit outcome.
pub fn render_audit_json(outcome: &AuditOutcome, path: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "schema": "chennai.audit.v1",
        "path": path,
        "mode": "audit",
        "pipeline": outcome.pipeline,
        "findings": serde_json::Value::Null, // Populated by caller from FindingSet
        "totals": {
            "findings": outcome.total_findings,
            "confirmed": outcome.confirmed_findings,
        },
        "stages": outcome.stages,
        "profile": outcome.profile.to_json(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::finding::{FindingSet, TokenLedger};
    use crate::agent::process_note::ProcessNote;
    use crate::agent::provider::{ContentBlock, LlmProvider, TurnResult};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    /// Mock provider that returns a fixed sequence of responses.
    struct MockProvider {
        turns: Vec<(String, Vec<ContentBlock>)>,
        index: std::sync::Mutex<usize>,
    }

    impl MockProvider {
        fn new(turns: Vec<(&str, Vec<ContentBlock>)>) -> Self {
            MockProvider {
                turns: turns.into_iter().map(|(s, c)| (s.to_string(), c)).collect(),
                index: std::sync::Mutex::new(0),
            }
        }
    }

    impl super::super::provider::LlmProvider for MockProvider {
        fn stream_turn(
            &self,
            _req: &super::super::provider::TurnRequest,
            sink: &mut dyn super::super::provider::EventSink,
        ) -> Result<TurnResult, super::super::provider::ProviderError> {
            use crate::agent::provider::AgentEvent;
            let mut idx = self.index.lock().unwrap();
            if *idx >= self.turns.len() {
                return Ok(TurnResult {
                    content: vec![],
                    stop_reason: "end_turn".into(),
                    usage: None,
                });
            }
            let (stop_reason, blocks) = self.turns[*idx].clone();
            *idx += 1;
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
    // Default pipeline is fixed and reporter is last
    // -----------------------------------------------------------------------

    #[test]
    fn default_pipeline_is_fixed_and_reporter_last() {
        assert_eq!(DEFAULT_PIPELINE.len(), 6);
        assert_eq!(DEFAULT_PIPELINE[0], "recon");
        assert_eq!(DEFAULT_PIPELINE[1], "sink-hunter");
        assert_eq!(DEFAULT_PIPELINE[2], "taint-prover");
        assert_eq!(DEFAULT_PIPELINE[3], "auth-boundary");
        assert_eq!(DEFAULT_PIPELINE[4], "supply-chain");
        assert_eq!(DEFAULT_PIPELINE[5], "reporter");
    }

    // -----------------------------------------------------------------------
    // Pipeline override validates and rejects bad roles
    // -----------------------------------------------------------------------

    #[test]
    fn pipeline_override_validates_and_rejects_bad_roles() {
        let provider =
            MockProvider::new(vec![("end_turn", vec![ContentBlock::Text("done".into())])]);
        let ctx = make_ctx(Box::new(provider));

        // Invalid role name (uppercase not allowed).
        let result = run_audit(
            &ctx,
            None,
            Some(&["RECON".to_string()]),
            None,
            None,
            false,
            false,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid role name")
        );

        // Undiscovered role.
        let result = run_audit(
            &ctx,
            None,
            Some(&["nonexistent-role".to_string()]),
            None,
            None,
            false,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown role"));
    }

    #[test]
    fn pipeline_override_skip_missing_roles() {
        let provider =
            MockProvider::new(vec![("end_turn", vec![ContentBlock::Text("done".into())])]);
        let ctx = make_ctx(Box::new(provider));

        // With skip_missing, unknown roles are silently skipped.
        // "nonexistent" is skipped, "recon" runs (if discovered).
        // Since we have no source_root with roles, recon IS a builtin so it should be found.
        let result = run_audit_skip_missing(
            &ctx,
            None,
            Some(&["nonexistent".to_string(), "recon".to_string()]),
            None,
            None,
            false,
            false,
        );
        // Should succeed — nonexistent was skipped, recon was kept.
        // Note: recon may or may not resolve without a source root with agent files.
        // The builtin role is always available, so it should work.
        if let Err(e) = &result {
            // If it fails, it should be because of a different reason than the bad role.
            let msg = e.to_string();
            assert!(
                !msg.contains("nonexistent"),
                "should have skipped the unknown role"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Audit finalize reconciles profile with ledger
    // -----------------------------------------------------------------------

    #[test]
    fn audit_finalize_reconciles_profile_with_ledger() {
        let provider = MockProvider::new(vec![(
            "end_turn",
            vec![ContentBlock::Text("Recon done.".into())],
        )]);
        let mut ctx = make_ctx(Box::new(provider));
        let dir = tempfile::tempdir().unwrap();
        ctx.source_root = Some(dir.path().to_str().unwrap().to_string());

        let outcome = run_audit(
            &ctx,
            None,
            Some(&["recon".to_string()]),
            Some(dir.path()),
            None,
            false,
            false,
        )
        .expect("audit should succeed");

        // Profile total should match the ledger total.
        let ledger_total = {
            let l = ctx.token_ledger.lock().unwrap();
            l.total_tokens()
        };
        assert_eq!(
            outcome.profile.total_tokens(),
            ledger_total,
            "profile total must reconcile with ledger total"
        );

        // profile.json should exist.
        let profile_path = dir
            .path()
            .join(".chen")
            .join("agent-state")
            .join("profile.json");
        assert!(profile_path.exists(), "profile.json should be written");
    }

    // -----------------------------------------------------------------------
    // Audit persists on stage error (state files written even on failure)
    // -----------------------------------------------------------------------

    #[test]
    fn audit_persists_on_stage_error() {
        // Provider that fails on the second call (simulating a mid-run provider error).
        struct FailingProvider {
            call_count: std::sync::Mutex<usize>,
        }
        impl super::super::provider::LlmProvider for FailingProvider {
            fn stream_turn(
                &self,
                _req: &super::super::provider::TurnRequest,
                _sink: &mut dyn super::super::provider::EventSink,
            ) -> Result<TurnResult, super::super::provider::ProviderError> {
                let mut count = self.call_count.lock().unwrap();
                *count += 1;
                if *count > 1 {
                    return Err(super::super::provider::ProviderError::Stream(
                        "simulated mid-run failure".into(),
                    ));
                }
                // First call succeeds (recon stage starts).
                Ok(TurnResult {
                    content: vec![ContentBlock::Text("Starting recon.".into())],
                    stop_reason: "end_turn".into(),
                    usage: Some((100, 50)),
                })
            }
        }

        let mut ctx = make_ctx(Box::new(FailingProvider {
            call_count: std::sync::Mutex::new(0),
        }));
        let dir = tempfile::tempdir().unwrap();
        ctx.source_root = Some(dir.path().to_str().unwrap().to_string());

        // The second stage will fail, but the first stage should have written state.
        let _result = run_audit(
            &ctx,
            None,
            Some(&["recon".to_string(), "sink-hunter".to_string()]),
            Some(dir.path()),
            None,
            false,
            false,
        );

        // We don't care if it fails — the important thing is that state was persisted.
        // The first stage (recon) completes, then sink-hunter's provider call fails.
        // run_subagent catches provider errors gracefully (breaks the turn loop).
        // So the audit should actually succeed, having completed recon and then
        // had sink-hunter return early.
        // But if it does fail, state should still be on disk.
        let note_path = dir
            .path()
            .join(".chen")
            .join("agent-state")
            .join("process_note.json");
        assert!(
            note_path.exists(),
            "process_note.json should be persisted even on error"
        );
    }

    // -----------------------------------------------------------------------
    // Headless smoke test: stub provider completes and writes profile.json
    // -----------------------------------------------------------------------

    #[test]
    fn headless_audit_smoke_test_writes_profile() {
        let provider = MockProvider::new(vec![(
            "end_turn",
            vec![ContentBlock::Text("Audit done.".into())],
        )]);
        let mut ctx = make_ctx(Box::new(provider));
        let dir = tempfile::tempdir().unwrap();
        ctx.source_root = Some(dir.path().to_str().unwrap().to_string());

        let outcome = run_audit(
            &ctx,
            Some("Test objective"),
            Some(&["recon".to_string()]),
            Some(dir.path()),
            None,
            false,
            false,
        )
        .expect("audit should succeed");

        assert_eq!(outcome.pipeline, vec!["recon"]);
        assert_eq!(outcome.stages.len(), 1);
        assert_eq!(outcome.stages[0].role, "recon");
        assert!(outcome.stages[0].completed);

        let profile_path = dir
            .path()
            .join(".chen")
            .join("agent-state")
            .join("profile.json");
        assert!(profile_path.exists(), "profile.json should be written");
    }

    // -----------------------------------------------------------------------
    // Audit JSON schema v1 shape
    // -----------------------------------------------------------------------

    #[test]
    fn audit_json_schema_v1_shape() {
        let stages = vec![StageResult {
            role: "recon".to_string(),
            summary: "Found 3 entrypoints.".to_string(),
            findings_delta: 3,
            completed: true,
            tokens: 160,
            elapsed_secs: 5.0,
        }];
        let outcome = AuditOutcome {
            pipeline: vec!["recon".to_string()],
            stages: stages.clone(),
            total_findings: 3,
            confirmed_findings: 2,
            profile: RunProfile::new(),
        };

        let json = render_audit_json(&outcome, Some("/path/to/project"));

        // Check required top-level keys.
        assert_eq!(json["schema"].as_str().unwrap(), "chennai.audit.v1");
        assert_eq!(json["mode"].as_str().unwrap(), "audit");
        assert_eq!(json["path"].as_str().unwrap(), "/path/to/project");
        assert!(json["pipeline"].is_array());
        assert!(json["totals"]["findings"].is_number());
        assert!(json["totals"]["confirmed"].is_number());
        assert!(json["stages"].is_array());
        assert!(json["profile"].is_object());
    }

    // -----------------------------------------------------------------------
    // Resume tests
    // -----------------------------------------------------------------------

    #[test]
    fn resume_skips_completed_stages() {
        let dir = tempfile::tempdir().unwrap();
        // Seed audit-progress.json with "recon" already completed.
        let progress = super::super::finding::AuditProgress {
            completed_stages: vec!["recon".to_string()],
        };
        progress.save(Some(dir.path().to_str().unwrap())).unwrap();

        let provider = MockProvider::new(vec![(
            "end_turn",
            vec![ContentBlock::Text("Sink hunter done.".into())],
        )]);
        let mut ctx = make_ctx(Box::new(provider));
        ctx.source_root = Some(dir.path().to_str().unwrap().to_string());

        // Run pipeline [recon, sink-hunter] with --resume → recon skipped.
        let outcome = run_audit(
            &ctx,
            None,
            Some(&["recon".to_string(), "sink-hunter".to_string()]),
            Some(dir.path()),
            None,
            false,
            true,
        )
        .expect("resume audit should succeed");

        assert_eq!(outcome.stages.len(), 2);
        // Recon should be skipped (completed: true, findings_delta: 0).
        assert_eq!(outcome.stages[0].role, "recon");
        assert!(outcome.stages[0].completed);
        assert_eq!(outcome.stages[0].findings_delta, 0);
        assert_eq!(outcome.stages[0].tokens, 0);
        assert!(outcome.stages[0].summary.contains("skipped (resumed)"));
        // Sink-hunter should have run.
        assert_eq!(outcome.stages[1].role, "sink-hunter");
        assert!(outcome.stages[1].completed);
    }

    #[test]
    fn resume_restores_findings() {
        let dir = tempfile::tempdir().unwrap();
        // Seed findings.json with a pre-existing finding.
        let finding = super::super::finding::Finding {
            id: "F-prev-01".to_string(),
            title: "Pre-existing finding".to_string(),
            severity: super::super::finding::Severity::High,
            cwe: Some("CWE-78".to_string()),
            confidence: super::super::finding::Confidence::Confirmed,
            source: super::super::finding::Location {
                file: "src/cmd.rs".to_string(),
                line: Some(10),
                tag: Some("cli".to_string()),
            },
            sink: super::super::finding::Location {
                file: "src/exec.rs".to_string(),
                line: Some(20),
                tag: None,
            },
            proof: super::super::finding::Proof {
                expr: "test".to_string(),
                path_count: 1,
                verified: true,
            },
            reachable: true,
            sanitizers_checked: vec![],
            grounded_by: None,
            remediation: None,
        };
        let set = super::super::finding::FindingSet {
            findings: vec![finding],
            proof_cache: std::collections::HashMap::new(),
        };
        ProcessNote::save_findings(Some(dir.path().to_str().unwrap()), &set).unwrap();

        // Seed audit-progress with ALL stages completed.
        let mut progress = super::super::finding::AuditProgress::new();
        progress
            .mark_completed("recon", Some(dir.path().to_str().unwrap()))
            .unwrap();
        progress
            .mark_completed("sink-hunter", Some(dir.path().to_str().unwrap()))
            .unwrap();
        progress
            .mark_completed("reporter", Some(dir.path().to_str().unwrap()))
            .unwrap();

        let provider =
            MockProvider::new(vec![("end_turn", vec![ContentBlock::Text("Done.".into())])]);
        let mut ctx = make_ctx(Box::new(provider));
        ctx.source_root = Some(dir.path().to_str().unwrap().to_string());

        let outcome = run_audit(
            &ctx,
            None,
            Some(&[
                "recon".to_string(),
                "sink-hunter".to_string(),
                "reporter".to_string(),
            ]),
            Some(dir.path()),
            None,
            false,
            true,
        )
        .expect("resume with all stages complete should succeed");

        // All stages should be skipped, but the outcome should reflect the
        // restored finding.
        assert_eq!(
            outcome.total_findings, 1,
            "restored findings should appear in outcome"
        );
        assert_eq!(outcome.confirmed_findings, 1);
    }

    #[test]
    fn fresh_run_ignores_prior_progress() {
        let dir = tempfile::tempdir().unwrap();
        // Seed audit-progress.json — but run without --resume.
        let progress = super::super::finding::AuditProgress {
            completed_stages: vec!["recon".to_string()],
        };
        progress.save(Some(dir.path().to_str().unwrap())).unwrap();

        let provider = MockProvider::new(vec![
            ("end_turn", vec![ContentBlock::Text("Recon ran.".into())]),
            (
                "end_turn",
                vec![ContentBlock::Text("Sink hunter ran.".into())],
            ),
        ]);
        let mut ctx = make_ctx(Box::new(provider));
        ctx.source_root = Some(dir.path().to_str().unwrap().to_string());

        // Run without --resume → all stages should execute (recon NOT skipped).
        let outcome = run_audit(
            &ctx,
            None,
            Some(&["recon".to_string(), "sink-hunter".to_string()]),
            Some(dir.path()),
            None,
            false,
            false,
        )
        .expect("fresh audit should succeed");

        assert_eq!(outcome.stages.len(), 2);
        // Recon should have actually run (not skipped).
        assert_eq!(outcome.stages[0].role, "recon");
        assert!(
            outcome.stages[0].tokens > 0,
            "recon should have run, not been skipped"
        );
        assert!(!outcome.stages[0].summary.contains("skipped (resumed)"));
    }

    #[test]
    fn fresh_run_resets_stale_progress() {
        // A stale progress file listing a stage that this fresh run does NOT
        // execute must not survive: otherwise a later --resume would wrongly
        // skip a stage that was never run in the interim.
        let dir = tempfile::tempdir().unwrap();
        let sr = dir.path().to_str().unwrap();
        let stale = super::super::finding::AuditProgress {
            completed_stages: vec!["reporter".to_string(), "sink-hunter".to_string()],
        };
        stale.save(Some(sr)).unwrap();

        let provider = MockProvider::new(vec![(
            "end_turn",
            vec![ContentBlock::Text("Recon ran.".into())],
        )]);
        let mut ctx = make_ctx(Box::new(provider));
        ctx.source_root = Some(sr.to_string());

        // Fresh (non-resume) run of a single-stage pipeline.
        run_audit(
            &ctx,
            None,
            Some(&["recon".to_string()]),
            Some(dir.path()),
            None,
            false,
            false,
        )
        .expect("fresh audit should succeed");

        // The persisted progress must reflect ONLY this run: recon, and none of
        // the stale entries.
        let saved = super::super::finding::AuditProgress::load(Some(sr));
        assert_eq!(saved.completed_stages, vec!["recon".to_string()]);
        assert!(
            !saved.is_completed("reporter"),
            "stale 'reporter' must be gone"
        );
        assert!(
            !saved.is_completed("sink-hunter"),
            "stale 'sink-hunter' must be gone"
        );
    }
}
