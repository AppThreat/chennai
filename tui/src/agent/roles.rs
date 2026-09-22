//! Project-local, user-global, and built-in role discovery for orchestrated sub-agents.
//!
//! A project can drop markdown role definitions into `<source_root>/.chen/agents/roles/`
//! and the orchestrator discovers them at runtime — no Rust rebuild required. Resolution
//! follows a strict precedence: project-local → user-global → compiled-in built-in.
//!
//! Role names must match `^[a-z0-9][a-z0-9-]{0,63}$` to prevent path traversal and
//! encoding issues. Names are validated before any filesystem access.

use super::SlashCommand;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Built-in role names (always available even without any filesystem config)
// ---------------------------------------------------------------------------

/// Canonical list of built-in role names compiled into the binary.
const BUILTIN_ROLE_NAMES: &[&str] = &[
    "recon",
    "sink-hunter",
    "taint-prover",
    "auth-boundary",
    "supply-chain",
    "reporter",
];

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Returns `true` if `name` is a valid role identifier. Accepts lowercase
/// alphanumeric characters and hyphens (not at the start), 1–64 characters
/// total. Rejects anything that could be a path traversal, contain shell
/// metacharacters, or be empty.
pub fn is_valid_role_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

// ---------------------------------------------------------------------------
// Directory helpers
// ---------------------------------------------------------------------------

/// Returns the project-local roles directory: `<base>/.chen/agents/roles`.
/// Does NOT create the directory — only returns the path.
pub fn project_roles_dir(base: &Path) -> PathBuf {
    base.join(".chen").join("agents").join("roles")
}

/// Returns the user-global roles directory: `~/.config/chennai/agents/roles`.
fn user_roles_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("chennai")
            .join("agents")
            .join("roles"),
    )
}

/// Reads all `*.md` file stems from a directory, filtering out names that
/// fail validation. Returns a sorted vector of valid role name strings.
fn list_md_stems(dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_md = path.is_file() && path.extension().is_some_and(|ext| ext == "md");
            if let Some(stem) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|s| is_md && is_valid_role_name(s))
            {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Role discovery — union of all three sources
// ---------------------------------------------------------------------------

/// The provenance of a discovered role name, used to build the dynamic
/// menu and to decide resolution precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleSource {
    /// Compiled into the binary (one of the six built-in roles).
    Builtin,
    /// Found in the user-global override directory.
    UserGlobal,
    /// Found in the project-local directory.
    ProjectLocal,
}

/// Discover all available role names as the union of built-ins, user-global
/// overrides, and project-local definitions. Returns a sorted map from role
/// name to its highest-precedence source.
pub fn discover_roles(base: &Path) -> BTreeMap<String, RoleSource> {
    discover_roles_impl(base, user_roles_dir().as_deref())
}

/// Testable core of [`discover_roles`] with an injectable user-global directory
/// (so tests never touch the real `~/.config`).
fn discover_roles_impl(base: &Path, user_dir: Option<&Path>) -> BTreeMap<String, RoleSource> {
    let mut roles = BTreeMap::new();

    // Built-ins (lowest precedence — overwritten if a file exists).
    for &name in BUILTIN_ROLE_NAMES {
        roles.insert(name.to_string(), RoleSource::Builtin);
    }

    // User-global overrides.
    if let Some(dir) = user_dir {
        for name in list_md_stems(dir) {
            roles.insert(name, RoleSource::UserGlobal);
        }
    }

    // Project-local overrides (highest precedence).
    let project_dir = project_roles_dir(base);
    for name in list_md_stems(&project_dir) {
        roles.insert(name, RoleSource::ProjectLocal);
    }

    roles
}

// ---------------------------------------------------------------------------
// Role resolution — precedence: project → user → built-in
// ---------------------------------------------------------------------------

/// Read a role definition file from a directory and parse its frontmatter.
fn read_role_file(dir: &Path, name: &str) -> Option<SlashCommand> {
    let path = dir.join(format!("{name}.md"));
    let raw = std::fs::read_to_string(path).ok()?;
    Some(super::parse_frontmatter(&raw))
}

/// Resolve a role template following the precedence chain:
///
/// 1. Project-local (`<base>/.chen/agents/roles/<name>.md`)
/// 2. User-global (`~/.config/chennai/agents/roles/<name>.md`)
/// 3. Built-in (compiled-in const)
///
/// Returns `None` if no definition is found at any level or the name
/// fails validation.
pub fn resolve_role(base: &Path, name: &str) -> Option<SlashCommand> {
    resolve_role_impl(base, name, user_roles_dir().as_deref())
}

/// Testable core of [`resolve_role`] with an injectable user-global directory.
fn resolve_role_impl(base: &Path, name: &str, user_dir: Option<&Path>) -> Option<SlashCommand> {
    // Guard: must be a valid name before any filesystem lookup.
    if !is_valid_role_name(name) {
        return None;
    }

    // 1. Project-local.
    let project_dir = project_roles_dir(base);
    if let Some(role) = read_role_file(&project_dir, name) {
        return Some(role);
    }

    // 2. User-global.
    if let Some(role) = user_dir.and_then(|dir| read_role_file(dir, name)) {
        return Some(role);
    }

    // 3. Built-in.
    super::builtin_role(name).map(super::parse_frontmatter)
}

// ---------------------------------------------------------------------------
// Dynamic orchestrator menu — build role descriptions for the prompt
// ---------------------------------------------------------------------------

/// Extract a one-line description from a [`SlashCommand`]. Prefers the
/// `description:` frontmatter field; falls back to the first non-empty
/// body line if no description is set.
pub fn role_description(role: &SlashCommand) -> String {
    if let Some(desc) = role.description.as_ref().filter(|d| !d.is_empty()) {
        return desc.clone();
    }
    // Fallback: first non-empty line of the body.
    role.body
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("(no description)")
        .trim()
        .to_string()
}

/// Build a dynamic "Available roles" section for the orchestrator prompt,
/// replacing the old hardcoded role list. Returns a markdown section listing
/// each discovered role with its description, or a default section if none
/// are found.
///
/// If `role_subset` is provided, only those roles are listed (and they must
/// still exist in the discovered set). Otherwise all discovered roles appear.
pub fn build_roles_section(base: &Path, role_subset: Option<&[String]>) -> String {
    let discovered = discover_roles(base);

    let names: Vec<&String> = if let Some(subset) = role_subset {
        subset
            .iter()
            .filter(|n| discovered.contains_key(n.as_str()))
            .collect()
    } else {
        discovered.keys().collect()
    };

    if names.is_empty() {
        return "No roles available.".into();
    }

    let mut lines = String::from("### Available sub-agent roles\n");
    for name in names {
        let desc = resolve_role(base, name)
            .map(|r| role_description(&r))
            .unwrap_or_else(|| "(definition not found)".into());
        lines.push_str(&format!("- **{}**: {}\n", name, desc));
    }
    lines
}

// ---------------------------------------------------------------------------
// Project orchestration manifest
// ---------------------------------------------------------------------------

/// Optional per-project configuration for orchestration shape knobs.
/// Loaded from `<source_root>/.chen/agents/orchestrate.toml`.
///
/// These settings describe *how* an orchestrated run behaves — they cannot
/// *initiate* a run. The on/off switch stays with the `--orchestrate` CLI
/// flag, the `CHENNAI_ORCHESTRATE` env var, or the `/orchestrate` slash
/// command — all user-controlled.
#[derive(Debug, Clone, Default)]
pub struct OrchestrateManifest {
    /// Override the maximum number of sub-agents (CLI/env still win).
    pub max_subagents: Option<usize>,
    /// Override the advisory global turn budget (CLI/env still win).
    pub turn_budget: Option<u64>,
    /// Override the advisory global token budget (CLI/env still win).
    /// May only *lower* the ceiling, never raise it above the hard cap.
    pub token_budget: Option<u64>,
    /// Restrict/order the role menu to this subset (must still be valid names).
    pub roles: Option<Vec<String>>,
    /// Path to a project-specific orchestrator prompt (relative to source root).
    pub orchestrator_prompt: Option<String>,
}

/// Load the orchestration manifest from `<base>/.chen/agents/orchestrate.toml`
/// if it exists. Returns `Default` (all `None`) when no manifest is present
/// or the file cannot be parsed — manifest errors are never fatal.
pub fn load_manifest(base: &Path) -> OrchestrateManifest {
    let path = base.join(".chen").join("agents").join("orchestrate.toml");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return OrchestrateManifest::default(),
    };

    // Use a flexible Value-based parse so unknown keys are ignored and
    // partial manifests work without breaking.
    let value: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return OrchestrateManifest::default(),
    };

    let table = match value.as_table() {
        Some(t) => t,
        None => return OrchestrateManifest::default(),
    };

    OrchestrateManifest {
        max_subagents: table
            .get("max_subagents")
            .and_then(|v| v.as_integer())
            .map(|n| n as usize),
        turn_budget: table
            .get("turn_budget")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        token_budget: table
            .get("token_budget")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        roles: table.get("roles").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .filter(|s| is_valid_role_name(s))
                .collect()
        }),
        orchestrator_prompt: table
            .get("orchestrator_prompt")
            .and_then(|v| v.as_str())
            .map(String::from),
    }
}

// ---------------------------------------------------------------------------
// Token budget ceiling
// ---------------------------------------------------------------------------

/// Hard ceiling for the global token budget. No configuration source (CLI, env,
/// or project manifest) can raise the effective budget above this value.
/// The manifest may only *lower* it.
pub const TOKEN_BUDGET_CEILING: u64 = 256_000;

/// Clamp a token budget value to the hard ceiling, returning the effective value
/// and a flag indicating whether clamping occurred.
pub fn clamp_token_budget(requested: u64) -> (u64, bool) {
    if requested > TOKEN_BUDGET_CEILING {
        (TOKEN_BUDGET_CEILING, true)
    } else {
        (requested, false)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // -----------------------------------------------------------------------
    // Name validation
    // -----------------------------------------------------------------------

    #[test]
    fn valid_role_names_accepted() {
        assert!(is_valid_role_name("recon"));
        assert!(is_valid_role_name("sink-hunter"));
        assert!(is_valid_role_name("taint-prover"));
        assert!(is_valid_role_name("auth-boundary"));
        assert!(is_valid_role_name("supply-chain"));
        assert!(is_valid_role_name("reporter"));
        assert!(is_valid_role_name("a"));
        assert!(is_valid_role_name("my-custom-role-42"));
        assert!(is_valid_role_name(&"x".repeat(64)));
    }

    #[test]
    fn invalid_role_names_rejected() {
        assert!(!is_valid_role_name(""));
        assert!(!is_valid_role_name(&"a".repeat(65)));
        assert!(!is_valid_role_name("-bad"));
        assert!(!is_valid_role_name("My-Role"));
        assert!(!is_valid_role_name("../etc/passwd"));
        assert!(!is_valid_role_name("foo/bar"));
        assert!(!is_valid_role_name("foo bar"));
        assert!(!is_valid_role_name("foo.bar"));
        assert!(!is_valid_role_name("foo_bar"));
        assert!(!is_valid_role_name("foo!role"));
    }

    // -----------------------------------------------------------------------
    // discover_roles — union of sources
    // -----------------------------------------------------------------------

    #[test]
    fn discover_roles_builtin_only_when_no_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let roles = discover_roles(tmp.path());
        assert_eq!(roles.len(), 6);
        assert_eq!(roles.get("recon"), Some(&RoleSource::Builtin));
        assert_eq!(roles.get("sink-hunter"), Some(&RoleSource::Builtin));
        assert_eq!(roles.get("taint-prover"), Some(&RoleSource::Builtin));
        assert_eq!(roles.get("auth-boundary"), Some(&RoleSource::Builtin));
        assert_eq!(roles.get("supply-chain"), Some(&RoleSource::Builtin));
        assert_eq!(roles.get("reporter"), Some(&RoleSource::Builtin));
    }

    #[test]
    fn discover_roles_includes_user_global() {
        let tmp = tempfile::tempdir().unwrap();
        let user_dir = tempfile::tempdir().unwrap();
        fs::write(
            user_dir.path().join("crypto-auditor.md"),
            "---\ntools: [atom_query]\n---\nCustom role",
        )
        .unwrap();

        let roles = discover_roles_impl(tmp.path(), Some(user_dir.path()));
        assert!(roles.contains_key("crypto-auditor"));
        assert_eq!(roles.get("crypto-auditor"), Some(&RoleSource::UserGlobal));
        assert_eq!(roles.get("recon"), Some(&RoleSource::Builtin));
    }

    #[test]
    fn discover_roles_includes_project_local() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = project_roles_dir(tmp.path());
        let _ = fs::create_dir_all(&project_dir);
        fs::write(
            project_dir.join("crypto-auditor.md"),
            "---\ntools: [atom_query]\n---\nProject role",
        )
        .unwrap();

        let roles = discover_roles(tmp.path());
        assert_eq!(roles.get("crypto-auditor"), Some(&RoleSource::ProjectLocal));
    }

    #[test]
    fn discover_roles_project_overrides_user_precedence() {
        let tmp = tempfile::tempdir().unwrap();
        let user_dir = tempfile::tempdir().unwrap();
        fs::write(
            user_dir.path().join("override-test.md"),
            "---\ntools: [atom_query]\n---\nUser version",
        )
        .unwrap();

        let project_dir = project_roles_dir(tmp.path());
        let _ = fs::create_dir_all(&project_dir);
        fs::write(
            project_dir.join("override-test.md"),
            "---\ntools: [atom_dsl_eval]\n---\nProject version",
        )
        .unwrap();

        let roles = discover_roles_impl(tmp.path(), Some(user_dir.path()));
        assert_eq!(
            roles.get("override-test"),
            Some(&RoleSource::ProjectLocal),
            "project-local should win over user-global"
        );
    }

    #[test]
    fn discover_roles_rejects_invalid_names() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = project_roles_dir(tmp.path());
        let _ = fs::create_dir_all(&project_dir);
        // Files with invalid names should be silently skipped.
        fs::write(project_dir.join("../traversal.md"), "bad").unwrap();
        fs::write(project_dir.join("UPPER-CASE.md"), "bad").unwrap();
        fs::write(project_dir.join("has space.md"), "bad").unwrap();

        let roles = discover_roles(tmp.path());
        assert!(!roles.contains_key("../traversal"));
        assert!(!roles.contains_key("UPPER-CASE"));
        assert!(!roles.contains_key("has space"));
        // Built-ins still present — no new names added.
        assert_eq!(roles.len(), 6);
    }

    #[test]
    fn discover_roles_non_md_files_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = project_roles_dir(tmp.path());
        let _ = fs::create_dir_all(&project_dir);
        fs::write(project_dir.join("readme.txt"), "not a role").unwrap();
        fs::write(project_dir.join("role.md.bak"), "backup").unwrap();

        let roles = discover_roles(tmp.path());
        assert!(!roles.contains_key("readme"));
        assert!(!roles.contains_key("role"));
    }

    // -----------------------------------------------------------------------
    // resolve_role — precedence chain
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_role_returns_builtin_when_no_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let role = resolve_role(tmp.path(), "recon");
        assert!(role.is_some());
        let body = role.unwrap().body;
        assert!(body.contains("Reconnaissance"));
    }

    #[test]
    fn resolve_role_returns_project_over_user_over_builtin() {
        let tmp = tempfile::tempdir().unwrap();
        let user_dir = tempfile::tempdir().unwrap();
        fs::write(
            user_dir.path().join("precedence-test.md"),
            "---\ntools: [atom_query]\n---\nUser body",
        )
        .unwrap();

        let project_dir = project_roles_dir(tmp.path());
        let _ = fs::create_dir_all(&project_dir);
        let project_file = project_dir.join("precedence-test.md");
        fs::write(
            &project_file,
            "---\ntools: [atom_dsl_eval]\n---\nProject body",
        )
        .unwrap();

        // Project-local should win.
        let role = resolve_role_impl(tmp.path(), "precedence-test", Some(user_dir.path())).unwrap();
        assert!(role.body.contains("Project body"));

        // Remove project, now user should win.
        fs::remove_file(&project_file).unwrap();
        let role = resolve_role_impl(tmp.path(), "precedence-test", Some(user_dir.path())).unwrap();
        assert!(role.body.contains("User body"));

        // No project, no user — unknown role.
        assert!(resolve_role_impl(tmp.path(), "precedence-test", None).is_none());

        // Built-in still works.
        assert!(resolve_role_impl(tmp.path(), "recon", None).is_some());
    }

    #[test]
    fn resolve_role_rejects_invalid_names() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(resolve_role(tmp.path(), "../etc/passwd").is_none());
        assert!(resolve_role(tmp.path(), "").is_none());
        assert!(resolve_role(tmp.path(), "UPPER").is_none());
    }

    // -----------------------------------------------------------------------
    // build_roles_section — dynamic menu
    // -----------------------------------------------------------------------

    #[test]
    fn build_roles_section_lists_builtin_roles() {
        let tmp = tempfile::tempdir().unwrap();
        let section = build_roles_section(tmp.path(), None);
        assert!(section.contains("Available sub-agent roles"));
        assert!(section.contains("recon"));
        assert!(section.contains("sink-hunter"));
        assert!(section.contains("taint-prover"));
        assert!(section.contains("auth-boundary"));
        assert!(section.contains("supply-chain"));
        assert!(section.contains("reporter"));
    }

    #[test]
    fn build_roles_section_includes_custom_role() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = project_roles_dir(tmp.path());
        let _ = fs::create_dir_all(&project_dir);
        fs::write(
            project_dir.join("crypto-auditor.md"),
            "---\ndescription: Audits cryptographic implementations\ntools: [atom_query]\n---\nCrypto role body",
        )
        .unwrap();

        let section = build_roles_section(tmp.path(), None);
        assert!(section.contains("crypto-auditor"));
        assert!(section.contains("Audits cryptographic implementations"));
    }

    #[test]
    fn build_roles_section_respects_subset() {
        let tmp = tempfile::tempdir().unwrap();
        let subset = vec!["recon".to_string(), "reporter".to_string()];
        let section = build_roles_section(tmp.path(), Some(&subset));
        assert!(section.contains("recon"));
        assert!(section.contains("reporter"));
        assert!(!section.contains("sink-hunter"));
    }

    #[test]
    fn build_roles_section_empty_when_no_matching_roles() {
        let tmp = tempfile::tempdir().unwrap();
        let subset: Vec<String> = vec!["nonexistent-role".to_string()];
        let section = build_roles_section(tmp.path(), Some(&subset));
        assert_eq!(section, "No roles available.");
    }

    // -----------------------------------------------------------------------
    // Token budget ceiling
    // -----------------------------------------------------------------------

    #[test]
    fn clamp_token_budget_within_ceiling() {
        let (val, clamped) = clamp_token_budget(100_000);
        assert_eq!(val, 100_000);
        assert!(!clamped);
    }

    #[test]
    fn clamp_token_budget_at_ceiling() {
        let (val, clamped) = clamp_token_budget(TOKEN_BUDGET_CEILING);
        assert_eq!(val, TOKEN_BUDGET_CEILING);
        assert!(!clamped);
    }

    #[test]
    fn clamp_token_budget_exceeds_ceiling() {
        let (val, clamped) = clamp_token_budget(1_500_000);
        assert_eq!(val, TOKEN_BUDGET_CEILING);
        assert!(clamped);
    }

    #[test]
    fn token_budget_ceiling_is_256k() {
        assert_eq!(TOKEN_BUDGET_CEILING, 256_000);
    }

    // -----------------------------------------------------------------------
    // Manifest loading
    // -----------------------------------------------------------------------

    #[test]
    fn load_manifest_returns_default_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = load_manifest(tmp.path());
        assert!(manifest.max_subagents.is_none());
        assert!(manifest.turn_budget.is_none());
        assert!(manifest.token_budget.is_none());
        assert!(manifest.roles.is_none());
        assert!(manifest.orchestrator_prompt.is_none());
    }

    #[test]
    fn load_manifest_parses_valid_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest_dir = tmp.path().join(".chen").join("agents");
        let _ = fs::create_dir_all(&manifest_dir);
        fs::write(
            manifest_dir.join("orchestrate.toml"),
            r#"
max_subagents = 6
turn_budget = 120
token_budget = 200000
roles = ["recon", "sink-hunter", "crypto-auditor"]
orchestrator_prompt = "agents/orchestrator.md"
"#,
        )
        .unwrap();

        let manifest = load_manifest(tmp.path());
        assert_eq!(manifest.max_subagents, Some(6));
        assert_eq!(manifest.turn_budget, Some(120));
        assert_eq!(manifest.token_budget, Some(200_000));
        assert_eq!(
            manifest.roles,
            Some(vec![
                "recon".into(),
                "sink-hunter".into(),
                "crypto-auditor".into()
            ])
        );
        assert_eq!(
            manifest.orchestrator_prompt,
            Some("agents/orchestrator.md".into())
        );
    }

    #[test]
    fn load_manifest_ignores_invalid_role_names() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest_dir = tmp.path().join(".chen").join("agents");
        let _ = fs::create_dir_all(&manifest_dir);
        fs::write(
            manifest_dir.join("orchestrate.toml"),
            r#"
roles = ["recon", "BAD-NAME", "../traversal", "good-name"]
"#,
        )
        .unwrap();

        let manifest = load_manifest(tmp.path());
        assert_eq!(
            manifest.roles,
            Some(vec!["recon".into(), "good-name".into()]),
            "invalid role names should be filtered out"
        );
    }

    #[test]
    fn load_manifest_handles_malformed_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest_dir = tmp.path().join(".chen").join("agents");
        let _ = fs::create_dir_all(&manifest_dir);
        fs::write(
            manifest_dir.join("orchestrate.toml"),
            "this is not [ valid toml {{{",
        )
        .unwrap();

        let manifest = load_manifest(tmp.path());
        assert!(manifest.max_subagents.is_none());
        assert!(manifest.roles.is_none());
    }

    #[test]
    fn load_manifest_handles_partial_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest_dir = tmp.path().join(".chen").join("agents");
        let _ = fs::create_dir_all(&manifest_dir);
        fs::write(manifest_dir.join("orchestrate.toml"), "max_subagents = 4\n").unwrap();

        let manifest = load_manifest(tmp.path());
        assert_eq!(manifest.max_subagents, Some(4));
        assert!(manifest.turn_budget.is_none());
        assert!(manifest.roles.is_none());
    }

    // -----------------------------------------------------------------------
    // project_roles_dir
    // -----------------------------------------------------------------------

    #[test]
    fn project_roles_dir_path() {
        let base = Path::new("/project");
        let dir = project_roles_dir(base);
        assert_eq!(dir, PathBuf::from("/project/.chen/agents/roles"));
    }

    // -----------------------------------------------------------------------
    // list_md_stems
    // -----------------------------------------------------------------------

    #[test]
    fn list_md_stems_finds_md_files() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("recon.md"), "content").unwrap();
        fs::write(tmp.path().join("hunter.md"), "content").unwrap();
        fs::write(tmp.path().join("readme.txt"), "not md").unwrap();

        let stems = list_md_stems(tmp.path());
        assert_eq!(stems, vec!["hunter", "recon"], "should be sorted");
    }

    #[test]
    fn list_md_stems_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let stems = list_md_stems(tmp.path());
        assert!(stems.is_empty());
    }

    #[test]
    fn list_md_stems_missing_dir() {
        let stems = list_md_stems(Path::new("/nonexistent/path"));
        assert!(stems.is_empty());
    }
}
