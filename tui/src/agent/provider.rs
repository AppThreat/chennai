//! Core abstractions for the LLM agent: provider trait, event types, and transcript messages.
//!
//! The [`LlmProvider`] trait abstracts over Anthropic and OpenAI-compatible APIs. Each
//! implementation handles its own wire format and SSE streaming, emitting [`AgentEvent`]s through
//! an [`EventSink`] for real-time TUI rendering while building the full [`TurnResult`] internally.

use serde_json::Value;
use std::sync::atomic::AtomicBool;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("API error (status {status}): {body}")]
    Api { status: u16, body: String },
    #[error("Stream error: {0}")]
    Stream(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

// ---------------------------------------------------------------------------
// Events sent from the agent worker to the TUI event loop
// ---------------------------------------------------------------------------

/// Events emitted by a streaming LLM provider call.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// A fragment of the model's reasoning (available only on certain providers).
    ThinkingDelta(String),
    /// A fragment of the assistant's text response.
    TextDelta(String),
    /// A tool call request from the model.
    ToolCall { id: String, name: String, input: Value },
    /// The result of executing a tool call, so the UI can attach it to the
    /// matching tool card. `content` is the (already truncated) text result.
    ToolResult { id: String, content: String, is_error: bool },
    /// Token usage for the current turn.
    Usage { input_tokens: u32, output_tokens: u32, cache_read_tokens: Option<u32> },
    /// The reason the model stopped (end_turn, tool_use, max_tokens, refusal).
    StopReason(String),
    /// An error from the provider or agent loop.
    Error(String),
    /// The agent loop has finished.
    Done,
    /// A flow result from the engine that the UI should display in the flow master/detail view.
    #[allow(dead_code)]
    FlowResult(Value),
}

// ---------------------------------------------------------------------------
// Content blocks (the building blocks of messages)
// ---------------------------------------------------------------------------

/// A single content block produced by the model.
///
/// `Thinking` carries the model's reasoning **and its cryptographic
/// `signature`**. On Anthropic models with adaptive/extended thinking enabled,
/// thinking blocks that appear in an assistant turn alongside `tool_use` MUST be
/// echoed back to the API verbatim — including the signature — on the next
/// request, or the API rejects the turn with a 400. Dropping or mutating the
/// signature breaks every multi-turn tool loop. See [`crate::agent::anthropic`].
#[derive(Debug, Clone)]
pub enum ContentBlock {
    Text(String),
    /// Summarized (or empty, when `display: "omitted"`) reasoning plus the
    /// opaque signature the API uses to validate the block on replay. The
    /// signature may be empty for providers that don't emit one (e.g. most
    /// OpenAI-compatible endpoints) — in that case it is simply omitted on the
    /// wire.
    Thinking { text: String, signature: String },
    /// Encrypted reasoning the API chose not to expose. The opaque `data` must
    /// be echoed back unchanged on replay, exactly like a signed thinking block.
    RedactedThinking { data: String },
    ToolUse { id: String, name: String, input: Value },
}

/// A message in the conversation transcript.
#[derive(Debug, Clone)]
pub struct Message {
    pub role: String,
    pub content: Vec<ContentBlock>,
    /// For tool_result messages, the id of the tool_use block this is a result for.
    pub tool_call_id: Option<String>,
    /// True when the tool execution returned an error.
    pub is_error: bool,
}

impl Message {
    pub fn user(text: &str) -> Self {
        Message { role: "user".into(), content: vec![ContentBlock::Text(text.into())], tool_call_id: None, is_error: false }
    }

    pub fn assistant(blocks: Vec<ContentBlock>) -> Self {
        Message { role: "assistant".into(), content: blocks, tool_call_id: None, is_error: false }
    }

    pub fn tool_result(tool_call_id: &str, content: &str, is_error: bool) -> Self {
        Message { role: "tool_result".into(), content: vec![ContentBlock::Text(content.into())], tool_call_id: Some(tool_call_id.into()), is_error }
    }

    /// Serialize to the provider-agnostic JSON format used internally.
    #[allow(dead_code)]
    pub fn to_json(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("role".into(), Value::String(self.role.clone()));
        if let Some(id) = &self.tool_call_id {
            map.insert("tool_call_id".into(), Value::String(id.clone()));
        }
        if self.is_error {
            map.insert("is_error".into(), Value::Bool(true));
        }
        if self.role == "tool_result" {
            // Tool results are always text content.
            let text = self.content.iter().filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            }).collect::<Vec<_>>().join("\n");
            map.insert("content".into(), Value::String(text));
        } else {
            let blocks: Vec<Value> = self.content.iter().map(content_block_to_json).collect();
            map.insert("content".into(), Value::Array(blocks));
        }
        Value::Object(map)
    }
}

#[allow(dead_code)]
fn content_block_to_json(block: &ContentBlock) -> Value {
    match block {
        ContentBlock::Text(t) => serde_json::json!({ "type": "text", "text": t }),
        ContentBlock::Thinking { text, signature } => serde_json::json!({
            "type": "thinking", "thinking": text, "signature": signature,
        }),
        ContentBlock::RedactedThinking { data } =>
            serde_json::json!({ "type": "redacted_thinking", "data": data }),
        ContentBlock::ToolUse { id, name, input } => serde_json::json!({
            "type": "tool_use",
            "id": id,
            "name": name,
            "input": input,
        }),
    }
}

// ---------------------------------------------------------------------------
// Turn request / result
// ---------------------------------------------------------------------------

/// Input for a single LLM turn.
pub struct TurnRequest<'a> {
    /// The system prompt (seeded once per agent session, cached).
    pub system: &'a str,
    /// JSON Schema tool definitions sent to the provider.
    pub tools: &'a [Value],
    /// The conversation transcript so far.
    pub messages: &'a [Message],
    /// Maximum tokens the model may generate in this turn.
    pub max_tokens: u32,
    /// When true, omit the `thinking` block from the request body for providers that support it.
    /// Useful for Anthropic-compatible endpoints (e.g. DeepSeek) that may not understand the
    /// Anthropic-specific `thinking` parameter.
    pub no_thinking: bool,
    /// Reasoning/output effort for Anthropic's `output_config.effort`
    /// (`low` | `medium` | `high` | `xhigh` | `max`). Ignored by providers that
    /// don't support it. Empty string means "don't send the field".
    pub effort: &'a str,
    /// Cooperative cancellation flag. Providers check this between streamed SSE
    /// chunks and abort the in-flight HTTP read (dropping the connection) when it
    /// flips to `true`, so the UI's `Esc`/cancel is responsive even mid-turn.
    pub cancel: &'a AtomicBool,
}

/// Result of a completed turn.
#[derive(Debug)]
pub struct TurnResult {
    pub content: Vec<ContentBlock>,
    pub stop_reason: String,
    #[allow(dead_code)]
    pub usage: Option<(u32, u32)>,
}

// ---------------------------------------------------------------------------
// Event sink trait
// ---------------------------------------------------------------------------

/// A sink that receives streaming [`AgentEvent`]s in real time.
pub trait EventSink {
    fn emit(&mut self, event: AgentEvent);
}

/// An [`EventSink`] that forwards events to an `mpsc::Sender`.
pub struct ChannelSink(pub std::sync::mpsc::Sender<AgentEvent>);

impl EventSink for ChannelSink {
    fn emit(&mut self, event: AgentEvent) {
        let _ = self.0.send(event);
    }
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// A provider that can stream LLM responses.
pub trait LlmProvider {
    /// Send a turn request and stream events to `sink`. Returns the accumulated turn result.
    fn stream_turn(&self, req: &TurnRequest, sink: &mut dyn EventSink) -> Result<TurnResult, ProviderError>;
}

// ---------------------------------------------------------------------------
// Shared retry / backoff helpers (used by both providers)
// ---------------------------------------------------------------------------

/// Maximum send attempts for transient failures (network drop, 429, 5xx).
pub const MAX_SEND_ATTEMPTS: u32 = 3;

/// True for HTTP statuses worth retrying with backoff.
pub fn is_retryable_status(status: u16) -> bool {
    status == 408 || status == 429 || status >= 500
}

/// Exponential backoff for attempt `n` (1-based): ~0.4s, 0.8s, 1.6s…
pub fn backoff_delay(attempt: u32) -> std::time::Duration {
    let millis = 400u64.saturating_mul(1u64 << attempt.saturating_sub(1).min(5));
    std::time::Duration::from_millis(millis.min(8_000))
}

/// Sleep for `dur`, but wake early (returning `true`) if cancellation is requested.
/// Polls in small steps so `Esc` stays responsive during backoff waits.
pub fn interruptible_sleep(dur: std::time::Duration, cancel: &AtomicBool) -> bool {
    use std::sync::atomic::Ordering;
    let step = std::time::Duration::from_millis(100);
    let mut slept = std::time::Duration::ZERO;
    while slept < dur {
        if cancel.load(Ordering::Relaxed) {
            return true;
        }
        std::thread::sleep(step.min(dur - slept));
        slept += step;
    }
    false
}
