//! Persistent per-project memory of durable facts (architecture, entrypoints,
//! auth boundaries, confirmed/refuted findings, user corrections).
//!
//! Facts are stored as individual markdown files with YAML frontmatter under
//! `<source_root>/.chen/facts-memory/`. An index (`MEMORY.md`) is injected into the
//! LLM's system prompt so the model knows what facts exist; full bodies are loaded
//! on demand via the `project_memory` tool.
//!
//! ## On-disk layout
//! ```text
//! <source_root>/.chen/facts-memory/
//!   MEMORY.md          # one-line-per-fact index (injected into system prompt)
//!   <slug>.md          # one fact per file
//! ```

use serde_json::Value;
use std::collections::HashSet;
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
    #[allow(dead_code)]
    pub confidence: Option<String>,
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
    pub deduped: usize,
    pub demoted: usize,
    pub evicted: usize,
}

impl PruneReport {
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.deduped == 0 && self.demoted == 0 && self.evicted == 0
    }
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
    ///
    /// Automatically runs a lightweight prune pass at session start to keep the
    /// store bounded without user intervention.
    pub fn open(source_root: Option<&str>) -> Option<Self> {
        let base_path = source_root?;
        let base = Path::new(base_path);
        let dir = base.join(".chen").join("facts-memory");
        std::fs::create_dir_all(&dir).ok()?;

        Self::ensure_gitignore(base);

        let commit = Self::read_git_head_short(base);

        let store = FactStore { dir, commit };
        // Automatic open-time prune (best-effort, metadata-only pass).
        store.prune(&PruneBudget::default());
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

    /// Validate that `slug` is safe: no path separators, no `..`.
    fn validate_slug(slug: &str) -> Result<(), String> {
        if slug.is_empty() {
            return Err("fact name cannot be empty".into());
        }
        if slug.contains('/') || slug.contains('\\') || slug.contains("..") {
            return Err(format!("invalid fact name '{slug}': path separators and '..' are not allowed"));
        }
        if !slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("invalid fact name '{slug}': only lowercase alphanumeric and '-' allowed"));
        }
        Ok(())
    }

    /// Canonicalised path for a fact file, verified to stay within the store dir.
    fn fact_path(&self, slug: &str) -> Result<PathBuf, String> {
        let root_canon = self.dir.canonicalize()
            .map_err(|e| format!("cannot resolve store directory: {e}"))?;
        let joined = root_canon.join(format!("{slug}.md"));
        let canon = joined.canonicalize().unwrap_or(joined);
        if canon.starts_with(&root_canon) {
            Ok(canon)
        } else {
            Err(format!("path '{slug}.md' escapes the store directory"))
        }
    }

    /// The path to the index file (non-canonicalised for creation).
    fn index_path(&self) -> PathBuf {
        self.dir.join("MEMORY.md")
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
    pub fn load(&self, slug: &str) -> Option<Fact> {
        let slug = Self::slugify(slug);
        let path = self.fact_path(&slug).ok()?;
        if !path.exists() { return None; }
        Self::parse_fact_file(&path)
    }

    /// Save (create or update) a fact. Auto-stamps `created`/`updated`/`commit`.
    /// When `name` already exists, the original `created` is preserved and
    /// `source_refs` are merged (deduplicated).
    pub fn save(&self, fact: &Fact) -> Result<(), String> {
        let slug = Self::slugify(&fact.name);
        Self::validate_slug(&slug)?;
        let path = self.fact_path(&slug)?;

        let (created, merged_refs) = if path.exists() {
            if let Some(existing) = Self::parse_fact_file(&path) {
                let mut refs: HashSet<String> = existing.source_refs.into_iter().collect();
                refs.extend(fact.source_refs.clone());
                let mut v: Vec<String> = refs.into_iter().collect();
                v.sort();
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

        self.upsert_index(&slug, &fact.description)?;

        // Best-effort prune after save.
        self.prune(&PruneBudget::default());

        Ok(())
    }

    /// Delete a fact by name.
    pub fn delete(&self, slug: &str) -> Result<(), String> {
        let slug = Self::slugify(slug);
        if let Ok(path) = self.fact_path(&slug)
            && path.exists() {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("failed to delete fact: {e}"))?;
            }
        self.drop_index_line(&slug)?;
        Ok(())
    }

    /// Search fact bodies for a keyword (substring match on name, description, body).
    pub fn search(&self, query: &str) -> Vec<FactMeta> {
        let lower = query.to_ascii_lowercase();
        let mut results = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return results };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") { continue; }
            if path.file_stem().and_then(|s| s.to_str()) == Some("MEMORY") { continue; }
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            if content.to_ascii_lowercase().contains(&lower)
                && let Some(meta) = Self::parse_frontmatter_file(&path) {
                    results.push(meta);
                }
        }
        results.sort_by(|a, b| a.name.cmp(&b.name));
        results
    }

    /// Generate the MEMORY.md index content (one bullet per fact).
    pub fn index_markdown(&self) -> String {
        let facts = self.list();
        if facts.is_empty() {
            return "none yet".to_string();
        }
        let mut lines: Vec<String> = facts.iter()
            .map(|f| format!("- [{name}]({name}.md) — {desc}", name = f.name, desc = f.description))
            .collect();
        lines.sort();
        let mut result = lines.join("\n");
        if result.len() > 16 * 1024 {
            let cutoff = result.char_indices()
                .take(16 * 1024)
                .last()
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(result.len());
            result.truncate(cutoff);
            result.push_str("\n... (index truncated)");
        }
        result
    }

    /// Rebuild MEMORY.md from all `.md` files in the store directory.
    pub fn rebuild_index(&self) {
        let content = self.index_markdown();
        let _ = std::fs::write(self.index_path(), content);
    }

    /// Prune the store against a budget. Runs de-duplication, staleness demotion,
    /// and eviction. Returns a report of actions taken.
    pub fn prune(&self, budget: &PruneBudget) -> PruneReport {
        let mut report = PruneReport { deduped: 0, demoted: 0, evicted: 0 };

        let facts = self.list();
        if facts.is_empty() { return report; }

        // 1. De-dupe: if two facts share the same name slug, keep the most recently updated.
        let mut seen = HashSet::new();
        for fact in &facts {
            if !seen.insert(fact.name.clone()) {
                let _ = self.delete(&fact.name);
                report.deduped += 1;
            }
        }

        // 2. Staleness demotion: if commit is behind HEAD and source_refs are missing, demote.
        if let Some(ref current_commit) = self.commit {
            let recheck = self.list();
            for fact in &recheck {
                if let Some(fact_commit) = self.read_fact_commit(&fact.name)
                    && fact_commit != *current_commit
                        && let Some(full) = self.load(&fact.name) {
                            let any_missing = full.source_refs.iter().any(|r| {
                                let p = self.dir.parent().and_then(|d| d.parent()).map(|base| base.join(r));
                                p.is_none_or(|p| !p.exists())
                            });
                            if any_missing {
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
                                let _ = self.save(&updated);
                                report.demoted += 1;
                            }
                        }
            }
        }

        // 3. Evict to budget when over max_facts.
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

        if report.deduped > 0 || report.demoted > 0 || report.evicted > 0 {
            self.rebuild_index();
        }

        report
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Read the `commit` field from a fact file's frontmatter.
    fn read_fact_commit(&self, slug: &str) -> Option<String> {
        let path = self.fact_path(slug).ok()?;
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
        let yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_str).ok()?;
        let mapping = yaml.as_mapping()?;

        let name = mapping.get(serde_yaml::Value::String("name".into()))?.as_str()?.to_string();
        let description = mapping.get(serde_yaml::Value::String("description".into()))?.as_str()?.to_string();
        let metadata = mapping.get(serde_yaml::Value::String("metadata".into()))?.as_mapping()?;
        let type_str = metadata.get(serde_yaml::Value::String("type".into()))?.as_str()?;
        let fact_type = FactType::from_str(type_str)?;
        let confidence = metadata.get(serde_yaml::Value::String("confidence".into()))
            .and_then(|v| v.as_str()).map(|s| s.to_string());
        let updated = mapping.get(serde_yaml::Value::String("updated".into()))?.as_str()?.to_string();

        Some(FactMeta { name, description, fact_type, confidence, updated })
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

        let yaml: serde_yaml::Value = serde_yaml::from_str(yaml_str).ok()?;
        let mapping = yaml.as_mapping()?;

        let name = mapping.get(serde_yaml::Value::String("name".into()))?.as_str()?.to_string();
        let description = mapping.get(serde_yaml::Value::String("description".into()))?.as_str()?.to_string();
        let metadata = mapping.get(serde_yaml::Value::String("metadata".into()))?.as_mapping()?;
        let type_str = metadata.get(serde_yaml::Value::String("type".into()))?.as_str()?;
        let fact_type = FactType::from_str(type_str)?;

        let grounded_by = metadata.get(serde_yaml::Value::String("grounded_by".into()))
            .and_then(|v| v.as_str()).map(|s| s.to_string());
        let confidence = metadata.get(serde_yaml::Value::String("confidence".into()))
            .and_then(|v| v.as_str()).map(|s| s.to_string());
        let source_refs = metadata.get(serde_yaml::Value::String("source_refs".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| seq.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        let created = mapping.get(serde_yaml::Value::String("created".into()))?.as_str()?.to_string();
        let updated = mapping.get(serde_yaml::Value::String("updated".into()))?.as_str()?.to_string();
        let commit = mapping.get(serde_yaml::Value::String("commit".into()))
            .and_then(|v| v.as_str()).map(|s| s.to_string());

        Some(Fact {
            name, description, fact_type, grounded_by, confidence,
            source_refs, created, updated, commit, body,
        })
    }

    /// Format a fact file with YAML frontmatter + body.
    #[allow(clippy::too_many_arguments)]
    fn format_fact_file(
        slug: &str, description: &str, fact_type: FactType,
        grounded_by: Option<&str>, confidence: Option<&str>,
        source_refs: &[String], created: &str, updated: &str,
        commit: Option<&str>, body: &str,
    ) -> String {
        let mut lines = Vec::new();
        lines.push("---".into());
        lines.push(format!("name: {slug}"));
        lines.push(format!("description: {description}"));
        lines.push("metadata:".into());
        lines.push(format!("  type: {}", fact_type.as_str()));
        if let Some(g) = grounded_by {
            lines.push(format!("  grounded_by: {g}"));
        }
        if let Some(c) = confidence {
            lines.push(format!("  confidence: {c}"));
        }
        if !source_refs.is_empty() {
            lines.push("  source_refs:".into());
            for r in source_refs {
                lines.push(format!("    - \"{}\"", r.replace('\"', "\\\"")));
            }
        }
        lines.push(format!("created: {created}"));
        lines.push(format!("updated: {updated}"));
        if let Some(c) = commit {
            lines.push(format!("commit: {c}"));
        }
        lines.push("---".into());
        lines.push(String::new());
        lines.push(body.to_string());
        lines.join("\n")
    }

    /// Upsert a line in MEMORY.md for a given fact.
    fn upsert_index(&self, slug: &str, description: &str) -> Result<(), String> {
        let index_path = self.index_path();
        let line = format!("- [{slug}]({slug}.md) — {description}");
        let existing = std::fs::read_to_string(&index_path).unwrap_or_default();
        let mut lines: Vec<String> = existing.lines().map(|l| l.to_string()).collect();
        lines.retain(|l| !l.starts_with(&format!("- [{slug}]")));
        lines.push(line);
        lines.sort();
        lines.dedup();
        let content = lines.join("\n") + "\n";
        std::fs::write(&index_path, content).map_err(|e| format!("failed to write index: {e}"))?;
        Ok(())
    }

    /// Remove the line for a given slug from MEMORY.md.
    fn drop_index_line(&self, slug: &str) -> Result<(), String> {
        let index_path = self.index_path();
        let existing = std::fs::read_to_string(&index_path).unwrap_or_default();
        let lines: Vec<&str> = existing.lines()
            .filter(|l| !l.starts_with(&format!("- [{slug}]")))
            .collect();
        let content = lines.join("\n") + "\n";
        std::fs::write(&index_path, content).map_err(|e| format!("failed to update index: {e}"))?;
        Ok(())
    }
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
            let refs = fact.source_refs.join(", ");
            let content = format!(
                "---\nname: {name}\ndescription: {desc}\ntype: {t}\
                 \ngrounded_by: {gb}\nconfidence: {conf}\nsource_refs: [{refs}]\
                 \ncreated: {created}\nupdated: {updated}\ncommit: {commit}\n---\n\n{body}",
                name = fact.name, desc = fact.description, t = fact.fact_type.as_str(),
                gb = fact.grounded_by.as_deref().unwrap_or(""),
                conf = fact.confidence.as_deref().unwrap_or(""),
                created = fact.created, updated = fact.updated,
                commit = fact.commit.as_deref().unwrap_or(""),
                body = fact.body,
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
    fn save_creates_file_and_index_entry() {
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
        drop(&store);
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
            created: "2099-01-01".into(), // should be ignored in favor of original
            updated: "2099-01-01".into(), // should be updated
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
    fn delete_removes_file_and_index_entry() {
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
    fn search_finds_by_name_and_body() {
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

        let results = store.search("sql");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "sql-injection");

        let results = store.search("middleware");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "auth-boundary");
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
    fn validate_slug_rejects_path_separators() {
        assert!(FactStore::validate_slug("../escape").is_err());
        assert!(FactStore::validate_slug("a/b").is_err());
        assert!(FactStore::validate_slug("a\\b").is_err());
        assert!(FactStore::validate_slug("a..b").is_err());
        assert!(FactStore::validate_slug("valid-slug").is_ok());
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
    fn prune_dedupes_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        // Write two fact files manually to simulate a state where dedup is needed.
        let content1 = "---\nname: dup-fact\ndescription: First\nmetadata:\n  type: finding\ncreated: 2026-01-01\nupdated: 2026-01-02\n---\n\nfirst\n";
        let content2 = "---\nname: dup-fact\ndescription: Second\nmetadata:\n  type: finding\ncreated: 2026-01-01\nupdated: 2026-01-01\n---\n\nsecond\n";
        std::fs::write(store.dir.join("dup-fact.md"), content1).unwrap();
        std::fs::write(store.dir.join("dup-fact.md"), content2).unwrap(); // overwrites

        // Save the second using a different slug to have two files.
        let content_a = "---\nname: dup-fact-a\ndescription: A\nmetadata:\n  type: finding\ncreated: 2026-01-01\nupdated: 2026-01-01\n---\n\na\n";
        let content_b = "---\nname: dup-fact-b\ndescription: B\nmetadata:\n  type: finding\ncreated: 2026-01-01\nupdated: 2026-01-01\n---\n\nb\n";
        std::fs::write(store.dir.join("dup-fact-a.md"), content_a).unwrap();
        std::fs::write(store.dir.join("dup-fact-b.md"), content_b).unwrap();

        assert_eq!(store.list().len(), 3);

        let report = store.prune(&PruneBudget { max_facts: 1, max_index_bytes: 16 * 1024 });
        assert_eq!(report.evicted, 2);

        let facts = store.list();
        assert_eq!(facts.len(), 1);
    }

    #[test]
    fn rebuild_index_matches_on_disk_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = FactStore::open(Some(dir.path().to_str().unwrap())).unwrap();

        store.save(&Fact {
            name: "fact-a".into(), description: "Fact A".into(),
            fact_type: FactType::Project, grounded_by: None, confidence: None,
            source_refs: vec![], created: "2026-01-01".into(), updated: "2026-01-01".into(),
            commit: None, body: "".into(),
        }).unwrap();
        store.save(&Fact {
            name: "fact-b".into(), description: "Fact B".into(),
            fact_type: FactType::Finding, grounded_by: Some("atom_flows".into()),
            confidence: Some("high".into()), source_refs: vec![],
            created: "2026-01-01".into(), updated: "2026-01-01".into(),
            commit: None, body: "".into(),
        }).unwrap();

        store.rebuild_index();
        let index = store.index_markdown();
        assert!(index.contains("fact-a"));
        assert!(index.contains("fact-b"));
    }

    #[test]
    fn memory_dispatch_without_source_returns_error() {
        let result = memory_dispatch(None, "id1", &serde_json::json!({"action": "recall", "name": "x"}));
        assert!(result.is_error);
        assert!(result.content.contains("no source root configured"));
    }
}
