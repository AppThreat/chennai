//! Persistent per-project memory of durable facts (architecture, entrypoints,
//! auth boundaries, confirmed/refuted findings, user corrections).
//!
//! Facts are stored as individual markdown files with YAML frontmatter under
//! `<source_root>/.chen/facts-memory/`. The index is computed live from the
//! on-disk `.md` files and injected into the LLM's system prompt; full bodies
//! are loaded on demand via the `project_memory` tool.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The type/category of a project memory fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactType {
    Project,
    Finding,
    Reference,
    Feedback,
}

impl FactType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FactType::Project => "project",
            FactType::Finding => "finding",
            FactType::Reference => "reference",
            FactType::Feedback => "feedback",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "project" => Some(FactType::Project),
            "finding" => Some(FactType::Finding),
            "reference" => Some(FactType::Reference),
            "feedback" => Some(FactType::Feedback),
            _ => None,
        }
    }
}

/// A single project memory fact (full content, including body).
#[derive(Debug, Clone)]
pub struct Fact {
    pub name: String,
    pub description: String,
    pub fact_type: FactType,
    pub grounded_by: Option<String>,
    pub confidence: Option<String>,
    pub source_refs: Vec<String>,
    pub created: String,
    pub updated: String,
    pub commit: Option<String>,
    pub body: String,
}

/// Lightweight metadata (frontmatter only, no body) used for index entries.
#[derive(Debug, Clone)]
pub struct FactMeta {
    pub name: String,
    pub description: String,
    pub fact_type: FactType,
    pub updated: String,
}

/// Pruning budget used to keep the fact store bounded.
pub struct PruneBudget {
    pub max_facts: usize,
    #[allow(dead_code)]
    pub max_index_bytes: usize,
}

impl Default for PruneBudget {
    fn default() -> Self {
        PruneBudget {
            max_facts: 200,
            max_index_bytes: 16 * 1024,
        }
    }
}

/// Summary of what the pruner did.
pub struct PruneReport {
    pub demoted: usize,
    pub evicted: usize,
}

impl PruneReport {
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.demoted == 0 && self.evicted == 0
    }
}

// ---------------------------------------------------------------------------
// Serde struct for safe YAML frontmatter serialization
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct FactFrontmatter {
    name: String,
    description: String,
    metadata: FactMetadata,
    created: String,
    updated: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct FactMetadata {
    #[serde(rename = "type")]
    fact_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grounded_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confidence: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    source_refs: Vec<String>,
}

// ---------------------------------------------------------------------------
// FactStore
// ---------------------------------------------------------------------------

/// Persistent, file-based store for project facts under `.chen/facts-memory/`.
pub struct FactStore {
    dir: PathBuf,
    commit: Option<String>,
}

impl FactStore {
    /// Open (or create) the fact store at `<source_root>/.chen/facts-memory/`.
    ///
    /// Returns `None` when no source root is provided or when the directory
    /// cannot be created. On first open the `.chen/.gitignore` is seeded so
    /// `facts-memory/` is never committed.
    pub fn open(source_root: Option<&str>) -> Option<Self> {
        let base_path = source_root?;
        let base = Path::new(base_path);
        let dir = base.join(".chen").join("facts-memory");
        std::fs::create_dir_all(&dir).ok()?;

        Self::ensure_gitignore(base);

        let commit = Self::read_git_head_short(base);

        let store = FactStore { dir, commit };
        // Open-time pass: evict to budget only (non-destructive, no staleness
        // demotion — that is reserved for the explicit `:memory prune` command).
        store.evict_to_budget(&PruneBudget::default());
        Some(store)
    }

    /// Ensure `.chen/.gitignore` ignores `facts-memory/` (and known siblings).
    fn ensure_gitignore(base: &Path) {
        let gitignore_path = base.join(".chen").join(".gitignore");
        let existing = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
        let mut lines: Vec<&str> = existing.lines().collect();

        let needed = ["facts-memory/", "chennai-debug-logs/", "chennai-reports/"];
        let mut changed = false;
        for entry in &needed {
            if !lines.contains(entry) {
                lines.push(entry);
                changed = true;
            }
        }
        if changed {
            let _ = std::fs::write(&gitignore_path, lines.join("\n") + "\n");
        }
    }

    /// Read the short git HEAD hash (first 8 chars). Returns `None` on error.
    fn read_git_head_short(base: &Path) -> Option<String> {
        let output = std::process::Command::new("git")
            .args(["rev-parse", "--short=8", "HEAD"])
            .current_dir(base)
            .output()
            .ok()?;
        if output.status.success() {
            let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !hash.is_empty() { Some(hash) } else { None }
        } else {
            None
        }
    }

    /// Return the filesystem-safe slug for a fact name.
    fn slugify(name: &str) -> String {
        let slug: String = name
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == ' ')
            .map(|c| if c == ' ' || c == '_' { '-' } else { c })
            .collect();
        let mut result = String::with_capacity(slug.len());
        let mut prev_dash = false;
        for c in slug.chars() {
            if c == '-' {
                if !prev_dash { result.push('-'); }
                prev_dash = true;
            } else {
                result.push(c);
                prev_dash = false;
            }
        }
        let result = result.trim_matches('-').to_string();
        if result.len() > 60 { result[..60].to_string() } else { result }
    }

    /// Validate that `name` (raw or slug) contains no path separators or `..`.
    fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("fact name cannot be empty".into());
        }
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(format!("invalid fact name '{name}': path separators and '..' are not allowed"));
        }
        Ok(())
    }

    /// Path to a fact file. Name is validated before use, so path-traversal
    /// safety is guaranteed by `validate_name`.
    fn fact_path_unchecked(&self, slug: &str) -> PathBuf {
        self.dir.join(format!("{slug}.md"))
    }

    /// List all fact files, parsing only frontmatter (fast, no body reads).
    pub fn list(&self) -> Vec<FactMeta> {
        let mut facts = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return facts };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") { continue; }
            if path.file_stem().and_then(|s| s.to_str()) == Some("MEMORY") { continue; }
            if let Some(meta) = Self::parse_frontmatter_file(&path) {
                facts.push(meta);
            }
        }
        facts.sort_by(|a, b| a.name.cmp(&b.name));
        facts
    }

    /// Load a full fact (frontmatter + body) by name.
    pub fn load(&self, name: &str) -> Option<Fact> {
        let slug = Self::slugify(name);
        let path = self.fact_path_unchecked(&slug);
        if !path.exists() { return None; }
        Self::parse_fact_file(&path)
    }

    /// Save (create or update) a fact. Auto-stamps `created`/`updated`/`commit`.
    /// When `name` already exists, the original `created` is preserved and
    /// `source_refs` are merged (deduplicated).
    pub fn save(&self, fact: &Fact) -> Result<(), String> {
        Self::validate_name(&fact.name)?;
        let slug = Self::slugify(&fact.name);
        // Validate the slug too (secondary gate after slugify strips dangerous chars).
        Self::validate_name(&slug)?;
        let path = self.fact_path_unchecked(&slug);

        let (created, merged_refs) = if path.exists() {
            if let Some(existing) = Self::parse_fact_file(&path) {
                let mut refs: std::collections::BTreeSet<String> = existing.source_refs.into_iter().collect();
                refs.extend(fact.source_refs.clone());
                let v: Vec<String> = refs.into_iter().collect();
                (existing.created, v)
            } else {
                (fact.created.clone(), fact.source_refs.clone())
            }
        } else {
            (fact.created.clone(), fact.source_refs.clone())
        };

        let now = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let content = Self::format_fact_file(
            &slug, &fact.description, fact.fact_type,
            fact.grounded_by.as_deref(), fact.confidence.as_deref(),
            &merged_refs, &created, &now, self.commit.as_deref(), &fact.body,
        );
        std::fs::write(&path, content).map_err(|e| format!("failed to write fact: {e}"))?;
        Ok(())
    }

    /// Delete a fact by name.
    pub fn delete(&self, name: &str) -> Result<(), String> {
        Self::validate_name(name)?;
        let slug = Self::slugify(name);
        Self::validate_name(&slug)?;
        let path = self.fact_path_unchecked(&slug);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("failed to delete fact: {e}"))?;
        }
        Ok(())
    }

    /// Search fact bodies for a keyword. Matches only name, description, and body
    /// (NOT frontmatter metadata) to keep precision high.
    pub fn search(&self, query: &str) -> Vec<FactMeta> {
        let lower = query.to_ascii_lowercase();
        let mut results = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return results };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") { continue; }
            if path.file_stem().and_then(|s| s.to_str()) == Some("MEMORY") { continue; }
            let Some(meta) = Self::parse_frontmatter_file(&path) else { continue };
            // Only search name, description, and body — not frontmatter metadata.
            if meta.name.to_ascii_lowercase().contains(&lower)
                || meta.description.to_ascii_lowercase().contains(&lower)
            {
                results.push(meta);
            } else {
                // Check the body (everything after the closing frontmatter delimiter).
                let content = std::fs::read_to_string(&path).unwrap_or_default();
                if let Some(body_start) = content.rfind("\n---") {
                    let body = &content[body_start + 4..];
                    if body.to_ascii_lowercase().contains(&lower) {
                        results.push(meta);
                    }
                }
            }
        }
        results.sort_by(|a, b| a.name.cmp(&b.name));
        results
    }

    /// Generate the index content (one bullet per fact) for injection into the
    /// system prompt. Computed live from on-disk files — no separate index file
    /// is maintained.
    pub fn index_markdown(&self) -> String {
        self.index_markdown_bounded(16 * 1024)
    }

    /// Like `index_markdown` but with an explicit byte budget.
    fn index_markdown_bounded(&self, max_bytes: usize) -> String {
        let facts = self.list();
        if facts.is_empty() {
            return "none yet".to_string();
        }
        let mut lines: Vec<String> = facts.iter()
            .map(|f| format!("- [{name}]({name}.md) — {desc}", name = f.name, desc = f.description))
            .collect();
        lines.sort();
        let mut result = lines.join("\n");
        if result.len() > max_bytes {
            let cutoff = result.char_indices()
                .take(max_bytes)
                .last()
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(result.len());
            result.truncate(cutoff);
            result.push_str("\n... (index truncated)");
        }
        result
    }

    /// Prune the store: demote stale facts and evict to budget.
    ///
    /// **Staleness demotion**: facts whose `commit` is behind HEAD AND whose
    /// every `source_ref` file is missing on disk are demoted to low confidence
    /// and prefixed with a STALE note. Demotion is reserved for the explicit
    /// `:memory prune` command only — open-time passes skip it.
    ///
    /// **Eviction**: when the store exceeds `max_facts`, the lowest-priority
    /// facts (oldest-`updated` findings and references) are deleted. Project
    /// and feedback facts are never auto-evicted.
    pub fn prune(&self, budget: &PruneBudget) -> PruneReport {
        let mut report = PruneReport { demoted: 0, evicted: 0 };

        // Staleness demotion.
        if let Some(ref current_commit) = self.commit {
            for fact in &self.list() {
                let Some(fact_commit) = self.read_fact_commit(&fact.name) else { continue };
                if fact_commit == *current_commit { continue; }
                let Some(full) = self.load(&fact.name) else { continue };
                // Only demote when EVERY source_ref file is missing (not just any).
                let all_missing = !full.source_refs.is_empty()
                    && full.source_refs.iter().all(|r| {
                        let file_path = strip_line_suffix(r);
                        let p = self.dir.parent()
                            .and_then(|d| d.parent())
                            .map(|base| base.join(&file_path));
                        p.is_none_or(|p| !p.exists())
                    });
                if all_missing {
                    let new_body = format!(
                        "> STALE: source refs missing as of {}\n\n{}",
                        current_commit, full.body
                    );
                    let updated = Fact {
                        confidence: Some("low".into()),
                        body: new_body,
                        updated: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                        commit: Some(current_commit.clone()),
                        ..full
                    };
                    self.write_fact_internal(&updated);
                    report.demoted += 1;
                }
            }
        }

        // Eviction: if over max_facts, delete lowest-priority facts.
        // Project and Feedback types are sticky — never auto-evicted.
        let current_facts = self.list();
        if current_facts.len() > budget.max_facts {
            let to_evict = current_facts.len() - budget.max_facts;
            let mut evictable: Vec<&FactMeta> = current_facts.iter()
                .filter(|f| matches!(f.fact_type, FactType::Finding | FactType::Reference))
                .collect();
            evictable.sort_by_key(|f| f.updated.clone());
            for f in evictable.iter().take(to_evict) {
                let _ = self.delete(&f.name);
                report.evicted += 1;
            }
        }

        report
    }

    /// Non-destructive eviction-only pass for open-time use.
    fn evict_to_budget(&self, budget: &PruneBudget) -> PruneReport {
        let mut report = PruneReport { demoted: 0, evicted: 0 };
        let current_facts = self.list();
        if current_facts.len() > budget.max_facts {
            let to_evict = current_facts.len() - budget.max_facts;
            let mut evictable: Vec<&FactMeta> = current_facts.iter()
                .filter(|f| matches!(f.fact_type, FactType::Finding | FactType::Reference))
                .collect();
            evictable.sort_by_key(|f| f.updated.clone());
            for f in evictable.iter().take(to_evict) {
                let _ = self.delete(&f.name);
                report.evicted += 1;
            }
        }
        report
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Write a fact to disk without triggering any side-effects (no prune, no
    /// index rebuild). Used by prune's demotion to avoid re-entrancy.
    fn write_fact_internal(&self, fact: &Fact) {
        let slug = Self::slugify(&fact.name);
        let path = self.fact_path_unchecked(&slug);
        let content = Self::format_fact_file(
            &slug, &fact.description, fact.fact_type,
            fact.grounded_by.as_deref(), fact.confidence.as_deref(),
            &fact.source_refs, &fact.created, &fact.updated,
            fact.commit.as_deref(), &fact.body,
        );
        let _ = std::fs::write(&path, content);
    }

    /// Read the `commit` field from a fact file's frontmatter.
    fn read_fact_commit(&self, name: &str) -> Option<String> {
        let slug = Self::slugify(name);
        let path = self.fact_path_unchecked(&slug);
        let content = std::fs::read_to_string(&path).ok()?;
        let yaml_str = Self::extract_frontmatter_yaml(&content)?;
        let yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_str).ok()?;
        yaml.get("commit").and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    /// Extract the YAML frontmatter string from a markdown file.
    fn extract_frontmatter_yaml(content: &str) -> Option<String> {
        let trimmed = content.trim_start();
        let rest = trimmed.strip_prefix("---\n")
            .or_else(|| trimmed.strip_prefix("---\r\n"))?;
        let closing = rest.find("\n---").or_else(|| rest.find("\r\n---"))?;
        Some(rest[..closing].to_string())
    }

    /// Parse frontmatter from a file and return metadata (no body).
    fn parse_frontmatter_file(path: &Path) -> Option<FactMeta> {
        let content = std::fs::read_to_string(path).ok()?;
        let yaml_str = Self::extract_frontmatter_yaml(&content)?;
        let fm: FactFrontmatter = serde_yaml::from_str(&yaml_str).ok()?;
        let fact_type = FactType::from_str(&fm.metadata.fact_type)?;
        Some(FactMeta {
            name: fm.name,
            description: fm.description,
            fact_type,
            updated: fm.updated,
        })
    }

    /// Parse a full fact file (frontmatter + body).
    fn parse_fact_file(path: &Path) -> Option<Fact> {
        let content = std::fs::read_to_string(path).ok()?;
        let trimmed = content.trim_start();
        let rest = trimmed.strip_prefix("---\n")
            .or_else(|| trimmed.strip_prefix("---\r\n"))?;
        let closing = rest.find("\n---").or_else(|| rest.find("\r\n---"))?;
        let yaml_str = &rest[..closing];
        let body = rest[closing + 4..].trim().to_string();

        let fm: FactFrontmatter = serde_yaml::from_str(yaml_str).ok()?;
        let fact_type = FactType::from_str(&fm.metadata.fact_type)?;

        Some(Fact {
            name: fm.name,
            description: fm.description,
            fact_type,
            grounded_by: fm.metadata.grounded_by,
            confidence: fm.metadata.confidence,
            source_refs: fm.metadata.source_refs,
            created: fm.created,
            updated: fm.updated,
            commit: fm.commit,
            body,
        })
    }

    /// Format a fact file with YAML frontmatter (serde-serialized, safe) + body.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn format_fact_file(
        slug: &str, description: &str, fact_type: FactType,
        grounded_by: Option<&str>, confidence: Option<&str>,
        source_refs: &[String], created: &str, updated: &str,
        commit: Option<&str>, body: &str,
    ) -> String {
        let fm = FactFrontmatter {
            name: slug.to_string(),
            description: description.to_string(),
            metadata: FactMetadata {
                fact_type: fact_type.as_str().to_string(),
                grounded_by: grounded_by.map(|s| s.to_string()),
                confidence: confidence.map(|s| s.to_string()),
                source_refs: source_refs.to_vec(),
            },
            created: created.to_string(),
            updated: updated.to_string(),
            commit: commit.map(|s| s.to_string()),
        };
        let yaml = serde_yaml::to_string(&fm).unwrap_or_default();
        format!("---\n{yaml}---\n\n{body}\n")
    }
}

/// Strip a `:line` suffix from a source ref path like `src/auth.ts:42`.
/// On Windows, `C:\...` paths contain colons after the drive letter, so we
/// only split on the LAST colon.
fn strip_line_suffix(ref_path: &str) -> String {
    if let Some((path, _line)) = ref_path.rsplit_once(':') {
        // Only strip if the part after the colon looks like a line number (digits).
        let after_colon = &ref_path[path.len() + 1..];
        if after_colon.chars().all(|c| c.is_ascii_digit()) {
            return path.to_string();
        }
    }
    ref_path.to_string()
}

// ---------------------------------------------------------------------------
// Memory dispatch
// ---------------------------------------------------------------------------

/// Dispatch a `project_memory` tool call. Opens the store from `source_root`,
/// runs the requested action, and returns `(content, is_error)`.
pub fn memory_dispatch(
    source_root: Option<&str>,
    call_id: &str,
    input: &Value,
) -> super::ToolExecResult {
    let store = match FactStore::open(source_root) {
        Some(s) => s,
        None => {
            return super::ToolExecResult {
                call_id: call_id.into(),
                content: "Fact store not available (no source root configured).".into(),
                is_error: true,
            };
        }
    };

    let action = input.get("action").and_then(Value::as_str).unwrap_or("");
    let result = match action {
        "recall" => action_recall(&store, input),
        "search" => action_search(&store, input),
        "save" => action_save(&store, input),
        "delete" => action_delete(&store, input),
        _ => (format!("Unknown action '{action}'. Valid actions: recall, search, save, delete."), true),
    };

    super::ToolExecResult {
        call_id: call_id.into(),
        content: result.0,
        is_error: result.1,
    }
}

fn action_recall(store: &FactStore, input: &Value) -> (String, bool) {
    let name = input.get("name").and_then(Value::as_str).unwrap_or("");
    if name.is_empty() {
        return ("'name' is required for 'recall' action.".into(), true);
    }
    match store.load(name) {
        Some(fact) => {
            // Reuse the same format as the actual file for consistency.
            let content = FactStore::format_fact_file(
                &fact.name, &fact.description, fact.fact_type,
                fact.grounded_by.as_deref(), fact.confidence.as_deref(),
                &fact.source_refs, &fact.created, &fact.updated,
                fact.commit.as_deref(), &fact.body,
            );
            (content, false)
        }
        None => (format!("Fact '{name}' not found."), true),
    }
}

fn action_search(store: &FactStore, input: &Value) -> (String, bool) {
    let query = input.get("query").and_then(Value::as_str).unwrap_or("");
    if query.is_empty() {
        return ("'query' is required for 'search' action.".into(), true);
    }
    let results = store.search(query);
    if results.is_empty() {
        return ("No facts matching query.".into(), false);
    }
    let lines: Vec<String> = results.iter()
        .map(|f| format!("- [{name}]({name}.md) ({t}) — {desc}",
            name = f.name, t = f.fact_type.as_str(), desc = f.description))
        .collect();
    (lines.join("\n"), false)
}

fn action_save(store: &FactStore, input: &Value) -> (String, bool) {
    let name = input.get("name").and_then(Value::as_str).unwrap_or("");
    if name.is_empty() {
        return ("'name' is required for 'save' action.".into(), true);
    }
    let description = input.get("description").and_then(Value::as_str).unwrap_or("");
    let type_str = input.get("type").and_then(Value::as_str).unwrap_or("project");
    let grounded_by = input.get("grounded_by").and_then(Value::as_str);
    let confidence = input.get("confidence").and_then(Value::as_str);
    let body = input.get("body").and_then(Value::as_str).unwrap_or("");
    let source_refs: Vec<String> = input.get("source_refs")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let fact_type = FactType::from_str(type_str).unwrap_or(FactType::Project);

    let is_text_tool = grounded_by.is_none_or(|g| {
        matches!(g, "ripgrep" | "read_file" | "text")
    });
    let (final_confidence, final_grounded_by) = if is_text_tool {
        (Some("low".into()), grounded_by.map(|g| g.to_string()).or(Some("text".into())))
    } else {
        (confidence.map(|c| c.to_string()), grounded_by.map(|g| g.to_string()))
    };

    let now = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let fact = Fact {
        name: name.to_string(),
        description: description.to_string(),
        fact_type,
        grounded_by: final_grounded_by,
        confidence: final_confidence,
        source_refs,
        created: now.clone(),
        updated: now,
        commit: None,
        body: body.to_string(),
    };

    match store.save(&fact) {
        Ok(()) => (format!("Fact '{name}' saved."), false),
        Err(e) => (format!("Failed to save fact: {e}"), true),
    }
}

fn action_delete(store: &FactStore, input: &Value) -> (String, bool) {
    let name = input.get("name").and_then(Value::as_str).unwrap_or("");
    if name.is_empty() {
        return ("'name' is required for 'delete' action.".into(), true);
    }
    match store.delete(name) {
        Ok(()) => (format!("Fact '{name}' deleted."), false),
        Err(e) => (format!("Failed to delete fact: {e}"), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_store() -> (FactStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();
        (store, dir)
    }

    #[test]
    fn open_creates_directory_and_gitignore() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap()));
        assert!(store.is_some());
        let facts_dir = dir.path().join(".chen").join("facts-memory");
        assert!(facts_dir.exists());
        let gitignore = dir.path().join(".chen").join(".gitignore");
        assert!(gitignore.exists());
        let content = std::fs::read_to_string(gitignore).unwrap();
        assert!(content.contains("facts-memory/"));
    }

    #[test]
    fn open_returns_none_without_source_root() {
        assert!(FactStore::open(None).is_none());
    }

    #[test]
    fn save_creates_file() {
        let (store, dir) = setup_store();
        let fact = Fact {
            name: "test-fact".into(),
            description: "A test fact".into(),
            fact_type: FactType::Project,
            grounded_by: Some("atom_flows".into()),
            confidence: Some("high".into()),
            source_refs: vec!["src/main.rs:42".into()],
            created: "2026-06-29".into(),
            updated: "2026-06-29".into(),
            commit: None,
            body: "This is a test fact body.".into(),
        };
        store.save(&fact).unwrap();
        let path = dir.path().join(".chen").join("facts-memory").join("test-fact.md");
        assert!(path.exists());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        let fact = Fact {
            name: "auth-boundary".into(),
            description: "Auth is enforced in requireAuth middleware".into(),
            fact_type: FactType::Project,
            grounded_by: Some("atom_flows".into()),
            confidence: Some("high".into()),
            source_refs: vec!["src/mw/auth.ts:42".into()],
            created: "2026-06-29".into(),
            updated: "2026-06-29".into(),
            commit: None,
            body: "All HTTP routes pass through requireAuth.".into(),
        };
        store.save(&fact).unwrap();

        let loaded = store.load("auth-boundary").unwrap();
        assert_eq!(loaded.name, "auth-boundary");
        assert_eq!(loaded.description, "Auth is enforced in requireAuth middleware");
        assert_eq!(loaded.fact_type, FactType::Project);
        assert_eq!(loaded.grounded_by.as_deref(), Some("atom_flows"));
        assert_eq!(loaded.confidence.as_deref(), Some("high"));
        assert_eq!(loaded.body, "All HTTP routes pass through requireAuth.");
    }

    #[test]
    fn save_updates_existing_fact_preserving_created() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        let fact1 = Fact {
            name: "my-fact".into(),
            description: "Original".into(),
            fact_type: FactType::Finding,
            grounded_by: Some("atom_algorithms".into()),
            confidence: Some("medium".into()),
            source_refs: vec![],
            created: "2026-01-01".into(),
            updated: "2026-01-01".into(),
            commit: None,
            body: "Original body".into(),
        };
        store.save(&fact1).unwrap();

        let fact2 = Fact {
            name: "my-fact".into(),
            description: "Updated".into(),
            fact_type: FactType::Finding,
            grounded_by: Some("atom_algorithms".into()),
            confidence: Some("high".into()),
            source_refs: vec!["new/file.rs:10".into()],
            created: "2099-01-01".into(),
            updated: "2099-01-01".into(),
            commit: None,
            body: "Updated body".into(),
        };
        store.save(&fact2).unwrap();

        let loaded = store.load("my-fact").unwrap();
        assert_eq!(loaded.created, "2026-01-01");
        assert_eq!(loaded.updated, chrono::Utc::now().format("%Y-%m-%d").to_string());
        assert_eq!(loaded.description, "Updated");
        assert_eq!(loaded.body, "Updated body");
        assert!(loaded.source_refs.contains(&"new/file.rs:10".into()));
    }

    #[test]
    fn delete_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        let fact = Fact {
            name: "delete-me".into(),
            description: "To be deleted".into(),
            fact_type: FactType::Reference,
            grounded_by: None,
            confidence: None,
            source_refs: vec![],
            created: "2026-06-29".into(),
            updated: "2026-06-29".into(),
            commit: None,
            body: "".into(),
        };
        store.save(&fact).unwrap();
        assert!(store.load("delete-me").is_some());

        store.delete("delete-me").unwrap();
        assert!(store.load("delete-me").is_none());

        let index = store.index_markdown();
        assert!(!index.contains("delete-me"));
    }

    #[test]
    fn search_matches_name_description_and_body_not_frontmatter() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        store.save(&Fact {
            name: "sql-injection".into(),
            description: "SQL injection in user search".into(),
            fact_type: FactType::Finding,
            grounded_by: Some("atom_flows".into()),
            confidence: Some("high".into()),
            source_refs: vec!["src/search.rs:42".into()],
            created: "2026-06-29".into(),
            updated: "2026-06-29".into(),
            commit: None,
            body: "User input reaches executeQuery directly.".into(),
        }).unwrap();

        store.save(&Fact {
            name: "auth-boundary".into(),
            description: "Auth boundary at middleware".into(),
            fact_type: FactType::Project,
            grounded_by: Some("atom_flows".into()),
            confidence: Some("high".into()),
            source_refs: vec!["src/mw/auth.ts:10".into()],
            created: "2026-06-29".into(),
            updated: "2026-06-29".into(),
            commit: None,
            body: "All routes pass through authentication middleware.".into(),
        }).unwrap();

        // Search in name.
        let results = store.search("sql");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "sql-injection");

        // Search in description.
        let results = store.search("middleware");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "auth-boundary");

        // Search in body.
        let results = store.search("executeQuery");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "sql-injection");

        // Search that should NOT match frontmatter metadata.
        let results = store.search("atom_flows");
        assert_eq!(results.len(), 0, "frontmatter metadata should not match");

        // Search that should NOT match source_refs.
        let results = store.search("search.rs");
        assert_eq!(results.len(), 0, "source_refs should not match");
    }

    #[test]
    fn slugify_handles_special_chars() {
        assert_eq!(FactStore::slugify("Hello World"), "hello-world");
        assert_eq!(FactStore::slugify("auth-boundary-express"), "auth-boundary-express");
        assert_eq!(FactStore::slugify("  spaced  out  "), "spaced-out");
        assert_eq!(FactStore::slugify("UPPER_CASE"), "upper-case");
        assert_eq!(FactStore::slugify(&"a".repeat(100)).len(), 60);
    }

    #[test]
    fn validate_name_rejects_path_separators() {
        assert!(FactStore::validate_name("../escape").is_err());
        assert!(FactStore::validate_name("a/b").is_err());
        assert!(FactStore::validate_name("a\\b").is_err());
        assert!(FactStore::validate_name("a..b").is_err());
        assert!(FactStore::validate_name("valid-slug").is_ok());
    }

    #[test]
    fn index_markdown_is_sorted_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        store.save(&Fact {
            name: "z-fact".into(), description: "Last".into(),
            fact_type: FactType::Project, grounded_by: None, confidence: None,
            source_refs: vec![], created: "2026-01-01".into(), updated: "2026-01-01".into(),
            commit: None, body: "".into(),
        }).unwrap();
        store.save(&Fact {
            name: "a-fact".into(), description: "First".into(),
            fact_type: FactType::Project, grounded_by: None, confidence: None,
            source_refs: vec![], created: "2026-01-01".into(), updated: "2026-01-01".into(),
            commit: None, body: "".into(),
        }).unwrap();

        let index = store.index_markdown();
        let lines: Vec<&str> = index.lines().collect();
        assert!(lines[0].contains("a-fact"));
        assert!(lines[1].contains("z-fact"));
    }

    #[test]
    fn index_markdown_returns_none_yet_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();
        assert_eq!(store.index_markdown(), "none yet");
    }

    #[test]
    fn text_tool_facts_get_low_confidence() {
        let input = serde_json::json!({
            "action": "save",
            "name": "text-fact",
            "description": "A grep-based fact",
            "type": "finding",
            "grounded_by": "ripgrep",
            "confidence": "high",
            "body": "Found a pattern in source files."
        });
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        let result = action_save(&store, &input);
        assert!(!result.1, "save should succeed: {}", result.0);

        let loaded = store.load("text-fact").unwrap();
        assert_eq!(loaded.confidence.as_deref(), Some("low"));
        assert_eq!(loaded.grounded_by.as_deref(), Some("ripgrep"));
    }

    #[test]
    fn flow_tool_facts_keep_stated_confidence() {
        let input = serde_json::json!({
            "action": "save",
            "name": "flow-fact",
            "description": "A dataflow fact",
            "type": "project",
            "grounded_by": "atom_flows",
            "confidence": "high",
            "body": "Flow from input to SQL sink."
        });
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        let result = action_save(&store, &input);
        assert!(!result.1);

        let loaded = store.load("flow-fact").unwrap();
        assert_eq!(loaded.confidence.as_deref(), Some("high"));
        assert_eq!(loaded.grounded_by.as_deref(), Some("atom_flows"));
    }

    #[test]
    fn prune_evicts_to_budget() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        for i in 0..3 {
            store.save(&Fact {
                name: format!("fact-{i}"), description: format!("Fact {i}"),
                fact_type: FactType::Finding, grounded_by: Some("text".into()),
                confidence: Some("low".into()), source_refs: vec![],
                created: "2026-01-01".into(), updated: "2026-01-01".into(),
                commit: None, body: format!("{i}"),
            }).unwrap();
        }
        assert_eq!(store.list().len(), 3);

        let report = store.prune(&PruneBudget { max_facts: 1, max_index_bytes: 16 * 1024 });
        assert_eq!(report.evicted, 2);

        let facts = store.list();
        assert_eq!(facts.len(), 1);
    }

    #[test]
    fn prune_does_not_evict_project_facts() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        store.save(&Fact {
            name: "sticky-project".into(), description: "Sticky".into(),
            fact_type: FactType::Project, grounded_by: None, confidence: None,
            source_refs: vec![], created: "2026-01-01".into(), updated: "2026-01-01".into(),
            commit: None, body: "".into(),
        }).unwrap();

        let report = store.prune(&PruneBudget { max_facts: 0, max_index_bytes: 16 * 1024 });
        assert_eq!(report.evicted, 0, "project facts are sticky");
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn html_description_does_not_corrupt_frontmatter() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        let fact = Fact {
            name: "colon-desc".into(),
            description: "Auth: enforced via JWT; type: bearer".into(),
            fact_type: FactType::Project,
            grounded_by: Some("atom_flows".into()),
            confidence: Some("high".into()),
            source_refs: vec![],
            created: "2026-01-01".into(),
            updated: "2026-01-01".into(),
            commit: None,
            body: "Body with --- triple dash --- and : colon".into(),
        };
        store.save(&fact).unwrap();

        let loaded = store.load("colon-desc").unwrap();
        assert_eq!(loaded.description, "Auth: enforced via JWT; type: bearer");
        assert_eq!(loaded.body, "Body with --- triple dash --- and : colon");
        assert!(loaded.confidence.is_some());
    }

    #[test]
    fn strip_line_suffix_removes_trailing_line_number() {
        assert_eq!(strip_line_suffix("src/auth.ts:42"), "src/auth.ts");
        assert_eq!(strip_line_suffix("src/auth.ts"), "src/auth.ts");
        assert_eq!(strip_line_suffix("C:\\Users\\me\\file.rs:10"), "C:\\Users\\me\\file.rs");
        assert_eq!(strip_line_suffix("file:notanumber"), "file:notanumber");
        assert_eq!(strip_line_suffix(""), "");
    }

    #[test]
    fn memory_dispatch_without_source_returns_error() {
        let result = memory_dispatch(None, "id1", &serde_json::json!({"action": "recall", "name": "x"}));
        assert!(result.is_error);
        assert!(result.content.contains("no source root configured"));
    }

    #[test]
    fn action_recall_reuses_format() {
        let input = serde_json::json!({
            "action": "save",
            "name": "recall-test",
            "description": "Test recall format",
            "type": "project",
            "grounded_by": "atom_flows",
            "confidence": "high",
            "body": "Body content here."
        });
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();
        action_save(&store, &input);

        let result = action_recall(&store, &serde_json::json!({"name": "recall-test"}));
        assert!(!result.1);
        assert!(result.0.contains("name: recall-test"));
        assert!(result.0.contains("description: Test recall format"));
        assert!(result.0.contains("Body content here."));
    }
}
