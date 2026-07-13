//! Deterministic scoring: match reported findings against ground-truth
//! entries without any LLM involvement.
//!
//! A finding is a true positive (TP) for a ground-truth entry iff:
//!   1. CWE family matches (coarse mapping via `cwe_family`).
//!   2. Sink file matches (basename comparison).
//!   3. Sink line is within `line_window` of the ground-truth sink line.
//!   4. If `must_be_reachable` is set, the finding must be confirmed/reachable.
//!
//! Each finding satisfies at most one GT entry (greedy nearest-line tie-break).
//! Unmatched reported findings → false positives (FP).
//! Unmatched ground truth → false negatives (FN).

use crate::corpus::{cwe_family, CorpusCase};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A finding parsed from a chennai run result (JSON output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportedFinding {
    /// CWE identifier, if present.
    pub cwe: Option<String>,
    /// Sink file path.
    pub sink_file: Option<String>,
    /// Sink line number, if present.
    pub sink_line: Option<u32>,
    /// Whether the finding is confirmed/reachable.
    pub reachable: Option<bool>,
}

impl ReportedFinding {
    /// Create from a serde_json::Value (chennai.audit.v1 findings array entry).
    pub fn from_json(val: &serde_json::Value) -> Option<Self> {
        Some(ReportedFinding {
            cwe: val.get("cwe").and_then(|v| v.as_str()).map(|s| s.to_string()),
            sink_file: val.get("sink").and_then(|s| s.get("file")).and_then(|v| v.as_str()).map(|s| s.to_string()),
            sink_line: val.get("sink").and_then(|s| s.get("line")).and_then(|v| v.as_u64()).map(|v| v as u32),
            reachable: val.get("reachable").and_then(|v| v.as_bool()),
        })
    }
}

/// Score for a single (case × mode) run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreResult {
    /// Case name.
    pub case: String,
    /// Mode (audit, orchestrate, single).
    pub mode: String,
    /// True positives: correctly identified vulnerabilities.
    pub tp: usize,
    /// False positives: reported findings that don't match ground truth.
    pub fp: usize,
    /// False negatives: ground-truth entries not found.
    pub fn_count: usize,
    /// Total ground-truth entries.
    pub gt_total: usize,
    /// Total reported findings.
    pub reported_total: usize,
    /// Recall: confirmed TPs / ground-truth vulns (0.0 if no GT).
    pub recall: f64,
    /// False positive rate: FPs / reported findings (0.0 if none reported).
    pub fp_rate: f64,
    /// Tokens per confirmed finding (0.0 if no confirmed).
    pub tokens_per_confirmed: f64,
    /// Total tokens consumed by the run.
    pub total_tokens: u64,
    /// Total turns in the run.
    pub total_turns: u64,
    /// Confirmed findings count.
    pub confirmed: usize,
    /// Wall-clock seconds.
    pub wall_secs: f64,
    /// Per-finding match details (which GT entry matched which finding).
    #[serde(default)]
    pub matches: Vec<MatchDetail>,
}

/// Details of a single finding-to-ground-truth match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchDetail {
    pub gt_id: String,
    pub finding_index: usize,
    pub line_distance: u32,
}

/// Score a single (case × mode) run against its ground truth.
///
/// Uses greedy nearest-line matching: for each GT entry, the closest matching
/// reported finding (by line distance) is assigned. Each finding is used at
/// most once.
pub fn score_run(
    case: &CorpusCase,
    mode: &str,
    findings: &[ReportedFinding],
    total_tokens: u64,
    total_turns: u64,
    confirmed: usize,
    wall_secs: f64,
) -> ScoreResult {
    let gt_total = case.ground_truth.len();
    let reported_total = findings.len();

    if gt_total == 0 {
        // No ground truth — all reported findings are FP.
        return ScoreResult {
            case: case.name.clone(),
            mode: mode.to_string(),
            tp: 0,
            fp: reported_total,
            fn_count: 0,
            gt_total: 0,
            reported_total,
            recall: 1.0, // No GT to miss — trivially perfect recall.
            fp_rate: if reported_total > 0 {
                1.0
            } else {
                0.0
            },
            tokens_per_confirmed: 0.0,
            total_tokens,
            total_turns,
            confirmed,
            wall_secs,
            matches: Vec::new(),
        };
    }

    // Greedy nearest-line matching.
    let mut used: HashSet<usize> = HashSet::new();
    let mut tp = 0;
    let mut matches = Vec::new();

    for gt in &case.ground_truth {
        let mut best_idx: Option<usize> = None;
        let mut best_dist = u32::MAX;

        for (i, finding) in findings.iter().enumerate() {
            if used.contains(&i) {
                continue;
            }

            // Check CWE family match.
            let cwe_match = finding.cwe.as_deref()
                .map(|fc| cwe_family(fc) == cwe_family(&gt.cwe))
                .unwrap_or(false);
            if !cwe_match {
                continue;
            }

            // Check sink file match (basename comparison).
            let file_match = finding.sink_file.as_ref()
                .map(|ff| {
                    let fb = std::path::Path::new(ff).file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    let gb = std::path::Path::new(&gt.sink_file).file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    fb == gb
                })
                .unwrap_or(false);
            if !file_match {
                continue;
            }

            // Check reachability if required.
            if gt.must_be_reachable {
                let reachable = finding.reachable.unwrap_or(false);
                if !reachable {
                    continue;
                }
            }

            // Check line window.
            let finding_line = finding.sink_line.unwrap_or(u32::MAX);
            let dist = if finding_line >= gt.sink_line.saturating_sub(gt.line_window)
                && finding_line <= gt.sink_line + gt.line_window
            {
                finding_line.abs_diff(gt.sink_line)
            } else {
                continue;
            };

            // Tie-break: greedy nearest-line.
            if dist < best_dist {
                best_dist = dist;
                best_idx = Some(i);
            }
        }

        if let Some(idx) = best_idx {
            used.insert(idx);
            tp += 1;
            matches.push(MatchDetail {
                gt_id: gt.id.clone(),
                finding_index: idx,
                line_distance: best_dist,
            });
        }
    }

    let fn_count = gt_total - tp;
    let fp = reported_total - tp;

    let recall = tp as f64 / gt_total as f64;
    let fp_rate = if reported_total > 0 {
        fp as f64 / reported_total as f64
    } else {
        0.0
    };
    let tokens_per_confirmed = if confirmed > 0 {
        total_tokens as f64 / confirmed as f64
    } else {
        0.0
    };

    ScoreResult {
        case: case.name.clone(),
        mode: mode.to_string(),
        tp,
        fp,
        fn_count,
        gt_total,
        reported_total,
        recall,
        fp_rate,
        tokens_per_confirmed,
        total_tokens,
        total_turns,
        confirmed,
        wall_secs,
        matches,
    }
}

/// Parse findings from a chennai.audit.v1 JSON output.
pub fn parse_findings_from_v1(json: &serde_json::Value) -> Vec<ReportedFinding> {
    json.get("findings")
        .and_then(|f| f.get("findings"))
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(ReportedFinding::from_json)
                .collect()
        })
        .unwrap_or_default()
}

/// Parse run totals from a chennai.audit.v1 JSON output.
///
/// Tokens/turns/elapsed live under `profile.totals` (see `RunProfile::to_json`);
/// the top-level `totals` object only carries `findings`/`confirmed`.
pub fn parse_totals_from_v1(json: &serde_json::Value) -> (u64, u64, usize, f64) {
    let tokens = json.pointer("/profile/totals/tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let turns = json.pointer("/profile/totals/turns")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let confirmed = json.pointer("/totals/confirmed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let elapsed = json.pointer("/profile/totals/elapsed_secs")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    (tokens, turns, confirmed, elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::GroundTruth;

    fn sample_case() -> CorpusCase {
        CorpusCase {
            name: "test-sqli".into(),
            lang: "java".into(),
            source: "vendored".into(),
            build: None,
            description: "Test case with SQLi".into(),
            objective: None,
            ground_truth: vec![
                GroundTruth {
                    id: "GT-001".into(),
                    cwe: "CWE-89".into(),
                    severity: "High".into(),
                    sink_file: "src/db/QueryExecutor.java".into(),
                    sink_line: 42,
                    line_window: 5,
                    must_be_reachable: true,
                },
                GroundTruth {
                    id: "GT-002".into(),
                    cwe: "CWE-22".into(),
                    severity: "High".into(),
                    sink_file: "src/file/PathHandler.java".into(),
                    sink_line: 100,
                    line_window: 10,
                    must_be_reachable: true,
                },
            ],
        }
    }

    #[test]
    fn perfect_score_all_gt_matched() {
        let case = sample_case();
        let findings = vec![
            ReportedFinding {
                cwe: Some("CWE-89".into()),
                sink_file: Some("src/db/QueryExecutor.java".into()),
                sink_line: Some(42),
                reachable: Some(true),
            },
            ReportedFinding {
                cwe: Some("CWE-22".into()),
                sink_file: Some("src/file/PathHandler.java".into()),
                sink_line: Some(100),
                reachable: Some(true),
            },
        ];

        let result = score_run(&case, "audit", &findings, 1000, 10, 2, 5.0);

        assert_eq!(result.tp, 2);
        assert_eq!(result.fp, 0);
        assert_eq!(result.fn_count, 0);
        assert!((result.recall - 1.0).abs() < f64::EPSILON);
        assert!((result.fp_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn false_positive_unmatched_finding() {
        let case = sample_case();
        let findings = vec![
            ReportedFinding {
                cwe: Some("CWE-89".into()),
                sink_file: Some("src/db/QueryExecutor.java".into()),
                sink_line: Some(42),
                reachable: Some(true),
            },
            ReportedFinding {
                cwe: Some("CWE-79".into()),
                sink_file: Some("src/ui/Template.java".into()),
                sink_line: Some(10),
                reachable: Some(true),
            },
        ];

        let result = score_run(&case, "audit", &findings, 1000, 10, 1, 5.0);

        assert_eq!(result.tp, 1);
        assert_eq!(result.fp, 1);
        assert_eq!(result.fn_count, 1);
    }

    #[test]
    fn false_negative_missing_gt() {
        let case = sample_case();
        let findings = vec![];

        let result = score_run(&case, "audit", &findings, 100, 5, 0, 2.0);

        assert_eq!(result.tp, 0);
        assert_eq!(result.fp, 0);
        assert_eq!(result.fn_count, 2);
        assert!((result.recall - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn line_window_boundary() {
        let case = CorpusCase {
            name: "boundary".into(),
            lang: "java".into(),
            source: "test".into(),
            build: None,
            description: "Test".into(),
            objective: None,
            ground_truth: vec![GroundTruth {
                id: "GT-001".into(),
                cwe: "CWE-89".into(),
                severity: "High".into(),
                sink_file: "A.java".into(),
                sink_line: 50,
                line_window: 5,
                must_be_reachable: true,
            }],
        };

        // Within window (50 - 5 = 45, so 45 is included).
        let findings = vec![ReportedFinding {
            cwe: Some("CWE-89".into()),
            sink_file: Some("A.java".into()),
            sink_line: Some(45),
            reachable: Some(true),
        }];
        let result = score_run(&case, "audit", &findings, 100, 5, 1, 1.0);
        assert_eq!(result.tp, 1);

        // Outside window (50 - 5 - 1 = 44).
        let findings = vec![ReportedFinding {
            cwe: Some("CWE-89".into()),
            sink_file: Some("A.java".into()),
            sink_line: Some(44),
            reachable: Some(true),
        }];
        let result = score_run(&case, "audit", &findings, 100, 5, 0, 1.0);
        assert_eq!(result.tp, 0);
        assert_eq!(result.fp, 1);
    }

    #[test]
    fn must_be_reachable_filter() {
        let case = CorpusCase {
            name: "reachable".into(),
            lang: "java".into(),
            source: "test".into(),
            build: None,
            description: "Test".into(),
            objective: None,
            ground_truth: vec![GroundTruth {
                id: "GT-001".into(),
                cwe: "CWE-89".into(),
                severity: "High".into(),
                sink_file: "A.java".into(),
                sink_line: 50,
                line_window: 5,
                must_be_reachable: true,
            }],
        };

        // Finding matches on file/CWE/line but is not reachable → FN, not TP.
        let findings = vec![ReportedFinding {
            cwe: Some("CWE-89".into()),
            sink_file: Some("A.java".into()),
            sink_line: Some(50),
            reachable: Some(false),
        }];
        let result = score_run(&case, "audit", &findings, 100, 5, 0, 1.0);
        assert_eq!(result.tp, 0);
        assert_eq!(result.fn_count, 1);
        assert_eq!(result.fp, 1); // The unmatched finding is an FP.
    }

    #[test]
    fn greedy_nearest_line_tie_break() {
        let case = CorpusCase {
            name: "tie".into(),
            lang: "java".into(),
            source: "test".into(),
            build: None,
            description: "Test".into(),
            objective: None,
            ground_truth: vec![GroundTruth {
                id: "GT-001".into(),
                cwe: "CWE-89".into(),
                severity: "High".into(),
                sink_file: "A.java".into(),
                sink_line: 50,
                line_window: 20,
                must_be_reachable: true,
            }],
        };

        // Two findings match, one closer than the other.
        let findings = vec![
            ReportedFinding {
                cwe: Some("CWE-89".into()),
                sink_file: Some("A.java".into()),
                sink_line: Some(48),
                reachable: Some(true),
            },
            ReportedFinding {
                cwe: Some("CWE-89".into()),
                sink_file: Some("A.java".into()),
                sink_line: Some(55),
                reachable: Some(true),
            },
        ];
        let result = score_run(&case, "audit", &findings, 100, 5, 1, 1.0);
        assert_eq!(result.tp, 1);
        assert_eq!(result.fp, 1); // The farther one is FP.
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].line_distance, 2); // 50 - 48 = 2.
        assert_eq!(result.matches[0].finding_index, 0); // Closer finding claimed first.
    }

    #[test]
    fn cwe_family_mismatch_rejects() {
        let case = sample_case();
        let findings = vec![ReportedFinding {
            cwe: Some("CWE-22".into()), // path-traversal, not injection
            sink_file: Some("src/db/QueryExecutor.java".into()),
            sink_line: Some(42),
            reachable: Some(true),
        }];
        let result = score_run(&case, "audit", &findings, 100, 5, 0, 1.0);
        assert_eq!(result.tp, 0);
        assert_eq!(result.fp, 1);
        assert_eq!(result.fn_count, 2);
    }

    #[test]
    fn no_ground_trivial_perfect() {
        let case = CorpusCase {
            name: "clean".into(),
            lang: "go".into(),
            source: "test".into(),
            build: None,
            description: "Clean case".into(),
            objective: None,
            ground_truth: vec![],
        };
        let findings = vec![];
        let result = score_run(&case, "audit", &findings, 0, 0, 0, 1.0);
        assert_eq!(result.tp, 0);
        assert_eq!(result.fp, 0);
        assert!((result.recall - 1.0).abs() < f64::EPSILON);
        assert!((result.fp_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn tokens_per_confirmed() {
        let case = sample_case();
        let findings = vec![ReportedFinding {
            cwe: Some("CWE-89".into()),
            sink_file: Some("src/db/QueryExecutor.java".into()),
            sink_line: Some(42),
            reachable: Some(true),
        }];
        let result = score_run(&case, "audit", &findings, 500, 10, 1, 5.0);
        assert!((result.tokens_per_confirmed - 500.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_findings_from_valid_v1() {
        let json = serde_json::json!({
            "schema": "chennai.audit.v1",
            "findings": {
                "findings": [
                    {
                        "cwe": "CWE-89",
                        "sink": {"file": "A.java", "line": 42},
                        "reachable": true,
                    },
                ],
                "total": 1,
                "confirmed": 1,
            },
        });
        let findings = parse_findings_from_v1(&json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-89"));
        assert_eq!(findings[0].sink_line, Some(42));
        assert_eq!(findings[0].reachable, Some(true));
    }

    #[test]
    fn parse_totals_reads_tokens_from_profile() {
        // Tokens/turns/elapsed come from profile.totals (matching RunProfile::to_json);
        // the top-level totals object only carries findings/confirmed.
        let json = serde_json::json!({
            "schema": "chennai.audit.v1",
            "totals": { "findings": 4, "confirmed": 3 },
            "profile": {
                "totals": { "tokens": 120_000, "turns": 42, "findings": 4, "elapsed_secs": 212.5 }
            },
        });
        let (tokens, turns, confirmed, elapsed) = parse_totals_from_v1(&json);
        assert_eq!(tokens, 120_000, "tokens must be read from profile.totals, not top-level totals");
        assert_eq!(turns, 42);
        assert_eq!(confirmed, 3);
        assert!((elapsed - 212.5).abs() < f64::EPSILON);
    }
}
