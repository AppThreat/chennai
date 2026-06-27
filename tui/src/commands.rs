//! The registry of runnable queries plus the REPL command parser.
//!
//! Each [`Command`] has a chen-DSL-style `repl` string (e.g. `atom.method.external`). The Summary
//! panel maps a row label to its command; the REPL panel parses free text into a [`ResolvedQuery`]
//! that the engine can execute.

/// A query the user can execute: a display label, the engine `kind`, an optional tag pattern, and
/// the chen-DSL-style text shown/typed in the REPL.
#[derive(Debug, Clone)]
pub struct Command {
    pub label: &'static str,
    pub kind: &'static str,
    pub pattern: Option<&'static str>,
    pub repl: &'static str,
}

const fn cmd(
    label: &'static str,
    kind: &'static str,
    pattern: Option<&'static str>,
    repl: &'static str,
) -> Command {
    Command { label, kind, pattern, repl }
}

/// All commands, in the same order the summary rows are produced by the engine.
pub const COMMANDS: &[Command] = &[
    cmd("Files", "files", None, "atom.file"),
    cmd("Methods", "methods", None, "atom.method"),
    cmd("External methods", "externalMethods", None, "atom.method.external"),
    cmd("Internal methods", "internalMethods", None, "atom.method.internal"),
    cmd("Calls", "calls", None, "atom.call"),
    cmd("Namespaces", "namespaces", None, "atom.namespace"),
    cmd("Annotations", "annotations", None, "atom.annotation"),
    cmd("Imports", "imports", None, "atom.imports"),
    cmd("Literals", "literals", None, "atom.literal"),
    cmd("Config files", "configFiles", None, "atom.configFile"),
    cmd(
        "Validation tags",
        "tags",
        Some("(validation|sanitization).*"),
        "atom.tag.name(\"(validation|sanitization).*\")",
    ),
    cmd("Unique packages", "tags", Some("pkg.*"), "atom.tag.name(\"pkg.*\")"),
    cmd("Framework tags", "tags", Some("framework.*"), "atom.tag.name(\"framework.*\")"),
    cmd(
        "Framework input",
        "tags",
        Some("framework-(input|route)"),
        "atom.tag.name(\"framework-(input|route)\")",
    ),
    cmd("Framework output", "tags", Some("framework-output"), "atom.tag.name(\"framework-output\")"),
    cmd("Crypto tags", "tags", Some("crypto.*"), "atom.tag.name(\"crypto.*\")"),
    cmd("Overlays", "overlays", None, "atom.metaData.overlays"),
];

/// Find the command whose label matches a summary row label.
pub fn by_label(label: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|c| c.label == label)
}

/// A parsed REPL command resolved to engine query arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedQuery {
    pub kind: String,
    pub pattern: Option<String>,
    pub title: String,
}

/// Suffixes the REPL tolerates so DSL-flavoured input (`atom.method.external.toJson`) resolves the
/// same as the bare expression.
const STRIPPABLE_SUFFIXES: &[&str] = &[".toJsonPretty", ".toJson", ".toList", ".p", ".l"];

fn strip_suffixes(input: &str) -> &str {
    let mut s = input.trim();
    loop {
        let trimmed = STRIPPABLE_SUFFIXES
            .iter()
            .find_map(|suf| s.strip_suffix(suf))
            .map(str::trim_end);
        match trimmed {
            Some(t) => s = t,
            None => return s,
        }
    }
}

/// Parse a REPL line into a [`ResolvedQuery`], or `None` if it is not recognised.
///
/// Recognises, case-sensitively for DSL forms: each command's `repl` string, a generic
/// `atom.tag.name("PATTERN")`, the raw engine `kind`, or (case-insensitively) the command label.
pub fn parse(input: &str) -> Option<ResolvedQuery> {
    let s = strip_suffixes(input);
    if s.is_empty() {
        return None;
    }

    // Generic tag form: atom.tag.name("PATTERN")
    if let Some(rest) = s.strip_prefix("atom.tag.name(")
        && let Some(inner) = rest.strip_suffix(')') {
            let pattern = inner.trim().trim_matches('"').to_string();
            return Some(ResolvedQuery {
                kind: "tags".into(),
                pattern: Some(pattern.clone()),
                title: format!("Tags: {pattern}"),
            });
        }

    // Exact DSL / kind / label match against the registry.
    let found = COMMANDS.iter().find(|c| {
        c.repl == s || c.kind == s || c.label.eq_ignore_ascii_case(s)
    });
    found.map(|c| ResolvedQuery {
        kind: c.kind.to_string(),
        pattern: c.pattern.map(str::to_string),
        title: c.label.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dsl_expression() {
        let q = parse("atom.method.external").unwrap();
        assert_eq!(q.kind, "externalMethods");
        assert_eq!(q.pattern, None);
        assert_eq!(q.title, "External methods");
    }

    #[test]
    fn strips_trailing_dsl_suffixes() {
        assert_eq!(parse("atom.method.external.toJson").unwrap().kind, "externalMethods");
        assert_eq!(parse("atom.file.toList").unwrap().kind, "files");
        assert_eq!(parse("atom.call.l").unwrap().kind, "calls");
    }

    #[test]
    fn parses_registered_tag_pattern() {
        let q = parse("atom.tag.name(\"framework-output\")").unwrap();
        assert_eq!(q.kind, "tags");
        assert_eq!(q.pattern.as_deref(), Some("framework-output"));
    }

    #[test]
    fn parses_arbitrary_tag_pattern() {
        let q = parse("atom.tag.name(\"my.custom.*\")").unwrap();
        assert_eq!(q.kind, "tags");
        assert_eq!(q.pattern.as_deref(), Some("my.custom.*"));
        assert_eq!(q.title, "Tags: my.custom.*");
    }

    #[test]
    fn parses_kind_and_label_forms() {
        assert_eq!(parse("files").unwrap().kind, "files");
        assert_eq!(parse("External methods").unwrap().kind, "externalMethods");
        assert_eq!(parse("external methods").unwrap().kind, "externalMethods");
    }

    #[test]
    fn rejects_unknown() {
        assert!(parse("atom.unknownThing").is_none());
        assert!(parse("").is_none());
        assert!(parse("   ").is_none());
    }

    #[test]
    fn every_command_repl_round_trips() {
        for c in COMMANDS {
            let q = parse(c.repl).unwrap_or_else(|| panic!("repl not parseable: {}", c.repl));
            assert_eq!(q.kind, c.kind, "kind mismatch for {}", c.label);
            assert_eq!(q.pattern.as_deref(), c.pattern, "pattern mismatch for {}", c.label);
        }
    }
}
