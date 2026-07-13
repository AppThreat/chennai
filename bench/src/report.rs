//! Rollup report generation: aggregate scored results across modes and cases,
//! emit JSON and Markdown rollups.

use crate::scoring::ScoreResult;
use serde::{Deserialize, Serialize};
use std::fmt::Write;

/// Per-mode aggregate statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeStats {
    pub mode: String,
    pub num_cases: usize,
    pub total_gt: usize,
    pub total_tp: usize,
    pub total_fp: usize,
    pub total_fn: usize,
    pub recall: f64,
    pub fp_rate: f64,
    pub mean_tokens_per_confirmed: f64,
    pub total_tokens: u64,
    pub mean_wall_secs: f64,
    pub mean_turns: f64,
    /// Per-case scores for this mode.
    pub cases: Vec<ScoreResult>,
}

/// Full rollup across all modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rollup {
    pub timestamp: String,
    pub chennai_version: String,
    pub modes: Vec<ModeStats>,
}

impl Rollup {
    /// Aggregate a list of score results into a rollup.
    pub fn from_scores(scores: &[ScoreResult]) -> Self {
        let mut mode_map: std::collections::BTreeMap<String, Vec<&ScoreResult>> =
            std::collections::BTreeMap::new();
        for s in scores {
            mode_map.entry(s.mode.clone()).or_default().push(s);
        }

        let modes: Vec<ModeStats> = mode_map
            .into_iter()
            .map(|(mode, results)| ModeStats::from_results(&mode, &results))
            .collect();

        Rollup {
            timestamp: chrono::Utc::now().to_rfc3339(),
            chennai_version: env!("CARGO_PKG_VERSION").to_string(),
            modes,
        }
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Render as Markdown summary table.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        let _ = writeln!(md, "# Benchmark Rollup");
        let _ = writeln!(md, "**Generated:** {}  ", self.timestamp);
        let _ = writeln!(md);

        // Summary table.
        let _ = writeln!(
            md,
            "| Mode | Cases | GT | TP | FP | FN | Recall | FP Rate | Tokens/Confirmed | Wall (s) | Turns |"
        );
        let _ = writeln!(
            md,
            "|------|-------|----|----|----|----|--------|---------|-------------------|----------|-------|"
        );

        for ms in &self.modes {
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} | {} | {:.1}% | {:.1}% | {:.0} | {:.1} | {:.0} |",
                ms.mode,
                ms.num_cases,
                ms.total_gt,
                ms.total_tp,
                ms.total_fp,
                ms.total_fn,
                ms.recall * 100.0,
                ms.fp_rate * 100.0,
                ms.mean_tokens_per_confirmed,
                ms.mean_wall_secs,
                ms.mean_turns,
            );
        }

        let _ = writeln!(md);

        // Per-case detail per mode.
        for ms in &self.modes {
            let _ = writeln!(md, "## {}", ms.mode);
            let _ = writeln!(md);
            let _ = writeln!(
                md,
                "| Case | TP | FP | FN | Recall | FP Rate | Tokens | Turns | Wall (s) |"
            );
            let _ = writeln!(
                md,
                "|------|----|----|----|--------|---------|--------|-------|----------|"
            );
            for c in &ms.cases {
                let _ = writeln!(
                    md,
                    "| {} | {} | {} | {} | {:.1}% | {:.1}% | {} | {} | {:.1} |",
                    c.case,
                    c.tp,
                    c.fp,
                    c.fn_count,
                    c.recall * 100.0,
                    c.fp_rate * 100.0,
                    c.total_tokens,
                    c.total_turns,
                    c.wall_secs,
                );
            }
            let _ = writeln!(md);
        }

        md
    }
}

impl ModeStats {
    fn from_results(mode: &str, results: &[&ScoreResult]) -> Self {
        let num_cases = results.len();
        let total_gt: usize = results.iter().map(|r| r.gt_total).sum();
        let total_tp: usize = results.iter().map(|r| r.tp).sum();
        let total_fp: usize = results.iter().map(|r| r.fp).sum();
        let total_fn: usize = results.iter().map(|r| r.fn_count).sum();
        let total_tokens: u64 = results.iter().map(|r| r.total_tokens).sum();

        let recall = if total_gt > 0 {
            total_tp as f64 / total_gt as f64
        } else {
            1.0
        };
        let fp_rate = if total_tp + total_fp > 0 {
            total_fp as f64 / (total_tp + total_fp) as f64
        } else {
            0.0
        };

        let confirmed_total: usize = results.iter().map(|r| r.confirmed).sum();
        let mean_tokens_per_confirmed = if confirmed_total > 0 {
            total_tokens as f64 / confirmed_total as f64
        } else {
            0.0
        };

        let total_wall: f64 = results.iter().map(|r| r.wall_secs).sum();
        let mean_wall_secs = if num_cases > 0 { total_wall / num_cases as f64 } else { 0.0 };

        let total_turns: u64 = results.iter().map(|r| r.total_turns).sum();
        let mean_turns = if num_cases > 0 {
            total_turns as f64 / num_cases as f64
        } else {
            0.0
        };

        ModeStats {
            mode: mode.to_string(),
            num_cases,
            total_gt,
            total_tp,
            total_fp,
            total_fn,
            recall,
            fp_rate,
            mean_tokens_per_confirmed,
            total_tokens,
            mean_wall_secs,
            mean_turns,
            cases: results.iter().map(|r| (*r).clone()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_score(case: &str, mode: &str, tp: usize, fp: usize, fn_count: usize, gt: usize) -> ScoreResult {
        ScoreResult {
            case: case.into(),
            mode: mode.into(),
            tp,
            fp,
            fn_count,
            gt_total: gt,
            reported_total: tp + fp,
            recall: if gt > 0 { tp as f64 / gt as f64 } else { 1.0 },
            fp_rate: if tp + fp > 0 { fp as f64 / (tp + fp) as f64 } else { 0.0 },
            tokens_per_confirmed: 100.0,
            total_tokens: 1000,
            total_turns: 10,
            confirmed: tp,
            wall_secs: 5.0,
            matches: Vec::new(),
        }
    }

    #[test]
    fn rollup_single_mode() {
        let scores = vec![
            make_score("case-a", "audit", 2, 1, 0, 2),
            make_score("case-b", "audit", 1, 0, 1, 2),
        ];
        let rollup = Rollup::from_scores(&scores);
        assert_eq!(rollup.modes.len(), 1);
        let ms = &rollup.modes[0];
        assert_eq!(ms.mode, "audit");
        assert_eq!(ms.num_cases, 2);
        assert_eq!(ms.total_tp, 3);
        assert_eq!(ms.total_fp, 1);
        assert_eq!(ms.total_fn, 1);
        assert_eq!(ms.total_gt, 4);
        assert!((ms.recall - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn rollup_multiple_modes() {
        let scores = vec![
            make_score("case-a", "audit", 2, 0, 0, 2),
            make_score("case-a", "orchestrate", 1, 1, 1, 2),
        ];
        let rollup = Rollup::from_scores(&scores);
        assert_eq!(rollup.modes.len(), 2);
    }

    #[test]
    fn markdown_contains_mode_header() {
        let scores = vec![make_score("case-a", "audit", 1, 0, 0, 1)];
        let rollup = Rollup::from_scores(&scores);
        let md = rollup.to_markdown();
        assert!(md.contains("## audit"));
    }

    #[test]
    fn json_serialization_roundtrip() {
        let scores = vec![make_score("case-a", "audit", 1, 0, 0, 1)];
        let rollup = Rollup::from_scores(&scores);
        let json = rollup.to_json().unwrap();
        let parsed: Rollup = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.modes.len(), 1);
        assert_eq!(parsed.modes[0].total_tp, 1);
    }
}
