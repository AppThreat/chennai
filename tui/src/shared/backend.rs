use serde_json::Value;

/// Shared anti-hallucination block injected into every agent system prompt
/// (atom and all non-atom backends). The model has no reliable prior knowledge
/// of the specific codebase under analysis, so it must never name or characterize
/// the project from its training prior, the directory path, or resemblance to a
/// well-known project. Identity must be derived ONLY from tool output.
pub const PROJECT_IDENTITY_RULES: &str = r#"## Project identity and purpose (do NOT guess)
You have NO reliable prior knowledge of this specific codebase. Never state or
imply the project's name, owner, purpose, framework, domain, or "what it is" from
your training prior, from the directory/path name, or from resemblance to a
well-known open-source project. Those are guesses, and guessing is the one thing
chennai must never do.
Derive identity ONLY from tool output:
- the SBOM (bom_query): the root/metadata component name and version, component
  PURLs, and licenses are the most authoritative source of "what this is".
- package / module / namespace names, file paths, and entry points returned by
  the analysis tools (atom_query, golem_query, rusi/dosai queries, blint_*).
- exported symbols, HTTP endpoints, recovered strings, and declarations the tools
  report.
If a tool has not yet shown you a fact, you do not know it. When asked "what is
this project" or "what does it do", FIRST call the summary tool and bom_query,
then describe only what they returned. If the evidence is insufficient to name or
characterize the project, say so plainly ("the available analysis does not
identify the project name/purpose") rather than inventing one. Always attribute
identity claims to their source, e.g. "the SBOM root component is named X" or "an
entry point main() under cmd/server indicates a server binary" -- never a bare
assertion you cannot trace to a tool result."#;

/// Unified interface for all non-atom analysis backends.
///
/// Each backend (rusi/rust, golem/go, dosai/dotnet, blint/binary) implements this
/// trait so the caller can dispatch uniformly via `Box<dyn Backend>` instead of
/// pattern-matching a 4-variant enum.
pub trait Backend: Send + Sync {
    /// High-level summary of the analysis results.
    fn summary(&self) -> String;
    /// Query the backend by entity kind, with optional pattern and limit.
    fn query(&self, kind: &str, pattern: Option<&str>, limit: usize) -> String;
    /// Short identifier used for tool-name prefixing ("rusi", "golem", "dosai", "blint").
    fn backend_name(&self) -> &'static str;
    /// The set of JSON tool definitions to send to the LLM.
    fn tool_definitions(&self) -> Vec<Value>;
    /// Build the system prompt section that describes the analysis context.
    fn system_prompt(
        &self,
        summary_text: &str,
        bom_summary: Option<&str>,
        bom_components: Option<&str>,
        console_history: Option<&str>,
    ) -> String;
    /// Clone this backend into a new boxed trait object.
    fn clone_box(&self) -> Box<dyn Backend>;
}
