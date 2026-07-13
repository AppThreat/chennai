//! Working memory for the current agent session: the Process Note.
//!
//! The Process Note records what the model has confirmed, ruled out, still
//! investigating, entrypoints found, and next steps. It is persisted under
//! `.chen/agent-state/` so a killed or interrupted session can resume.
//! Unlike `project_memory` (cross-session facts) and `FindingSet` (final
//! results), the Process Note is **durable working memory** for the current
//! analysis — injected at every turn so the model always sees its own
//! progress, survives compaction, and guides next actions.

use serde::{Deserialize, Serialize};

/// The current state of an analysis session.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessNote {
    pub confirmed: Vec<String>,
    pub ruled_out: Vec<String>,
    pub open_questions: Vec<String>,
    pub entrypoints: Vec<String>,
    /// Candidate dangerous sink call sites discovered during recon, structured
    /// as `"file:line sink_api"`. Consumed by sink-hunter to avoid re-discovery.
    #[serde(default)]
    pub candidate_sinks: Vec<String>,
    pub next_steps: Vec<String>,
}

impl ProcessNote {
    /// Render as compact markdown (empty when nothing is recorded).
    pub fn render(&self) -> String {
        fn field(label: &str, items: &[String]) -> String {
            if items.is_empty() {
                return String::new();
            }
            let bullets: String = items
                .iter()
                .map(|s| format!("  - {}", s))
                .collect::<Vec<_>>()
                .join("\n");
            format!("\n**{}:**\n{}", label, bullets)
        }

        let sections = [
            field("Confirmed findings", &self.confirmed),
            field("Ruled out", &self.ruled_out),
            field("Open questions", &self.open_questions),
            field("Entrypoints identified", &self.entrypoints),
            field("Candidate sinks", &self.candidate_sinks),
            field("Next steps", &self.next_steps),
        ];
        let body: String = sections.iter().filter(|s| !s.is_empty()).cloned().collect();
        if body.is_empty() {
            String::new()
        } else {
            format!("## Process Note{}", body)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.confirmed.is_empty()
            && self.ruled_out.is_empty()
            && self.open_questions.is_empty()
            && self.entrypoints.is_empty()
            && self.candidate_sinks.is_empty()
            && self.next_steps.is_empty()
    }

    /// Append items to a field (no duplicates).
    pub fn append_to(&mut self, field: &str, items: &[String]) -> Result<(), String> {
        let target: &mut Vec<String> = match field {
            "confirmed" => &mut self.confirmed,
            "ruled_out" => &mut self.ruled_out,
            "open_questions" => &mut self.open_questions,
            "entrypoints" => &mut self.entrypoints,
            "candidate_sinks" => &mut self.candidate_sinks,
            "next_steps" => &mut self.next_steps,
            other => return Err(format!("unknown process_note field: {other}")),
        };
        for item in items {
            if !target.contains(item) {
                target.push(item.clone());
            }
        }
        Ok(())
    }

    /// Replace a field entirely.
    pub fn replace_field(&mut self, field: &str, items: &[String]) -> Result<(), String> {
        let target: &mut Vec<String> = match field {
            "confirmed" => &mut self.confirmed,
            "ruled_out" => &mut self.ruled_out,
            "open_questions" => &mut self.open_questions,
            "entrypoints" => &mut self.entrypoints,
            "candidate_sinks" => &mut self.candidate_sinks,
            "next_steps" => &mut self.next_steps,
            other => return Err(format!("unknown process_note field: {other}")),
        };
        *target = items.to_vec();
        Ok(())
    }

    /// Persist to `<source_root>/.chen/agent-state/process_note.json`.
    pub fn save(&self, source_root: Option<&str>) -> Result<(), String> {
        let base = source_root.ok_or("no source root configured")?;
        let dir = std::path::Path::new(base).join(".chen").join("agent-state");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create agent-state dir: {e}"))?;
        let path = dir.join("process_note.json");
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("serialize: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("write process_note: {e}"))?;
        Ok(())
    }

    /// Load from `<source_root>/.chen/agent-state/process_note.json`.
    /// Returns an empty note when the file is missing or unreadable.
    pub fn load(source_root: Option<&str>) -> Self {
        let path = match source_root {
            Some(s) => std::path::Path::new(s).join(".chen").join("agent-state").join("process_note.json"),
            None => return Self::default(),
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        serde_json::from_str(&content).unwrap_or_default()
    }

    /// Persist a FindingSet.
    pub fn save_findings(source_root: Option<&str>, findings: &crate::agent::finding::FindingSet) -> Result<(), String> {
        let base = source_root.ok_or("no source root configured")?;
        let dir = std::path::Path::new(base).join(".chen").join("agent-state");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create agent-state dir: {e}"))?;
        let json = serde_json::to_string_pretty(&findings.findings).map_err(|e| format!("serialize findings: {e}"))?;
        std::fs::write(dir.join("findings.json"), json).map_err(|e| format!("write findings: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_note_render_is_empty() {
        let note = ProcessNote::default();
        assert!(note.is_empty());
        assert_eq!(note.render(), "");
    }

    #[test]
    fn render_includes_non_empty_fields() {
        let mut note = ProcessNote::default();
        note.confirmed.push("SQL injection in search".into());
        note.ruled_out.push("Path traversal in static assets".into());
        note.next_steps.push("Check auth middleware".into());
        let rendered = note.render();
        assert!(rendered.contains("Confirmed findings"));
        assert!(rendered.contains("SQL injection in search"));
        assert!(rendered.contains("Ruled out"));
        assert!(rendered.contains("Path traversal in static assets"));
        assert!(rendered.contains("Next steps"));
        assert!(rendered.contains("Check auth middleware"));
        // Fields not populated should not appear.
        assert!(!rendered.contains("Open questions"));
        assert!(!rendered.contains("Entrypoints identified"));
        assert!(!rendered.contains("Candidate sinks"));
    }

    #[test]
    fn append_adds_to_field_and_dedupes() {
        let mut note = ProcessNote::default();
        note.append_to("confirmed", &["item1".into()]).unwrap();
        assert_eq!(note.confirmed.len(), 1);
        note.append_to("confirmed", &["item1".into()]).unwrap();
        assert_eq!(note.confirmed.len(), 1);
        note.append_to("confirmed", &["item2".into()]).unwrap();
        assert_eq!(note.confirmed.len(), 2);
    }

    #[test]
    fn replace_overwrites_field() {
        let mut note = ProcessNote::default();
        note.append_to("confirmed", &["old".into()]).unwrap();
        note.replace_field("confirmed", &["new1".into(), "new2".into()]).unwrap();
        assert_eq!(note.confirmed, vec!["new1", "new2"]);
    }

    #[test]
    fn get_returns_rendered_note() {
        let mut note = ProcessNote::default();
        note.confirmed.push("Test finding".into());
        let rendered = note.render();
        assert!(rendered.contains("Test finding"));
    }

    #[test]
    fn unknown_field_returns_error() {
        let mut note = ProcessNote::default();
        assert!(note.append_to("bogus", &["x".into()]).is_err());
        assert!(note.replace_field("bogus", &["x".into()]).is_err());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut note = ProcessNote::default();
        note.confirmed.push("Testing save/load".into());
        note.next_steps.push("Verify roundtrip".into());
        note.save(Some(dir.path().to_str().unwrap())).unwrap();

        let loaded = ProcessNote::load(Some(dir.path().to_str().unwrap()));
        assert_eq!(loaded.confirmed, vec!["Testing save/load"]);
        assert_eq!(loaded.next_steps, vec!["Verify roundtrip"]);
    }

    #[test]
    fn load_missing_file_returns_empty_note() {
        // A non-existent directory should produce an empty note, not an error.
        let note = ProcessNote::load(Some("/tmp/nonexistent-path-for-test"));
        assert!(note.is_empty());
    }

    #[test]
    fn load_without_source_root_returns_empty() {
        let note = ProcessNote::load(None);
        assert!(note.is_empty());
    }

    #[test]
    fn candidate_sinks_roundtrip_save_load_and_render() {
        let dir = tempfile::tempdir().unwrap();
        let mut note = ProcessNote::default();
        note.candidate_sinks.push("commoncode/command.py:42 subprocess.Popen(shell=True)".into());
        note.candidate_sinks.push("lib/exec.py:10 os.system(cmd)".into());
        note.entrypoints.push("main".into());
        note.save(Some(dir.path().to_str().unwrap())).unwrap();

        let loaded = ProcessNote::load(Some(dir.path().to_str().unwrap()));
        assert_eq!(loaded.candidate_sinks.len(), 2);
        assert_eq!(loaded.candidate_sinks[0], "commoncode/command.py:42 subprocess.Popen(shell=True)");
        assert_eq!(loaded.candidate_sinks[1], "lib/exec.py:10 os.system(cmd)");

        // Renders only when non-empty.
        let rendered = loaded.render();
        assert!(rendered.contains("Candidate sinks"));
        assert!(rendered.contains("subprocess.Popen"));
        assert!(rendered.contains("os.system"));
    }

    #[test]
    fn candidate_sinks_not_rendered_when_empty() {
        let mut note = ProcessNote::default();
        note.confirmed.push("something".into());
        let rendered = note.render();
        assert!(!rendered.contains("Candidate sinks"));
    }

    #[test]
    fn load_missing_candidate_sinks_field_backward_compat() {
        // Older process_note.json without `candidate_sinks` must still load (serde default).
        let json = serde_json::json!({
            "confirmed": ["test"],
            "ruled_out": [],
            "open_questions": [],
            "entrypoints": [],
            "next_steps": []
        });
        let note: ProcessNote = serde_json::from_value(json).unwrap();
        assert_eq!(note.confirmed, vec!["test"]);
        assert!(note.candidate_sinks.is_empty());
    }
}
