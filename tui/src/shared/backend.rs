use serde_json::Value;

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
