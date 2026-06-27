//! Anthropic Messages API provider implementation.
//!
//! Communicates with the Anthropic API via raw HTTP (no SDK). Uses SSE streaming for real-time
//! event delivery. Supports the Messages API with `thinking` (adaptive, summarized), tool use,
//! and prompt caching.

use super::provider::{
    backoff_delay, interruptible_sleep, is_retryable_status, AgentEvent, ContentBlock, EventSink,
    LlmProvider, Message, ProviderError, TurnRequest, TurnResult, MAX_SEND_ATTEMPTS,
};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read};
use std::time::Duration;

/// Parse a `Retry-After` header (delta-seconds form) into a duration.
fn retry_after<T>(resp: &ureq::http::Response<T>) -> Option<Duration> {
    let secs: u64 = resp.headers().get("retry-after")?.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_secs(secs.min(60)))
}

const ANTHROPIC_API: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_TOKENS: u32 = 8192;

/// Hard backstop for a single streamed turn. A high-effort agentic turn on a
/// large atom can legitimately run for *minutes* (long-horizon reasoning plus
/// many tool round-trips), so this is deliberately generous — it exists only to
/// reap a wedged connection, not to bound normal work. User-initiated aborts are
/// handled separately and promptly via the per-chunk cancel check in
/// [`parse_sse_stream`], so we never rely on this timeout for responsiveness.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Normalize a user-supplied base URL so it always ends with `/v1/messages`.
/// Acceptable inputs: `https://api.deepseek.com`, `https://api.deepseek.com/anthropic`,
/// `https://api.deepseek.com/anthropic/v1/messages`.
fn normalize_anthropic_url(url: &str) -> String {
    let url = url.trim_end_matches('/');
    if url.ends_with("/v1/messages") {
        url.to_string()
    } else if url.ends_with("/v1") {
        format!("{url}/messages")
    } else {
        format!("{url}/v1/messages")
    }
}

/// Provider for the Anthropic Messages API.
pub struct AnthropicProvider {
    api_key: String,
    model: String,
    base_url: String,
}

impl AnthropicProvider {
    pub fn new(api_key: String, model: String) -> Self {
        AnthropicProvider { api_key, model, base_url: ANTHROPIC_API.into() }
    }

    pub fn with_base_url(api_key: String, model: String, base_url: String) -> Self {
        AnthropicProvider { api_key, model, base_url: normalize_anthropic_url(&base_url) }
    }

    /// Build a configured ureq Agent with timeout and no automatic status-code errors.
    fn agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(HTTP_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into()
    }
}

impl LlmProvider for AnthropicProvider {
    fn stream_turn(&self, req: &TurnRequest, sink: &mut dyn EventSink) -> Result<TurnResult, ProviderError> {
        let body = build_request_body(req, &self.model);
        let body_bytes = serde_json::to_vec(&body).map_err(|e| ProviderError::Protocol(e.to_string()))?;

        let agent = Self::agent();

        // Send with bounded retry on transient failures (network drop, 429, 5xx),
        // honouring Retry-After. Retries happen only before we start consuming the
        // stream, so they never replay partial output.
        let mut attempt = 0;
        let resp = loop {
            attempt += 1;
            if req.cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(ProviderError::Stream("cancelled".into()));
            }
            match agent
                .post(&self.base_url)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", ANTHROPIC_VERSION)
                .header("content-type", "application/json")
                .send(&body_bytes)
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if is_retryable_status(status) && attempt < MAX_SEND_ATTEMPTS {
                        let wait = retry_after(&resp).unwrap_or_else(|| backoff_delay(attempt));
                        if interruptible_sleep(wait, req.cancel) {
                            return Err(ProviderError::Stream("cancelled".into()));
                        }
                        continue;
                    }
                    break resp;
                }
                Err(e) => {
                    // Transport-level failure (DNS, connection refused, offline).
                    if attempt < MAX_SEND_ATTEMPTS {
                        if interruptible_sleep(backoff_delay(attempt), req.cancel) {
                            return Err(ProviderError::Stream("cancelled".into()));
                        }
                        continue;
                    }
                    return Err(ProviderError::Http(e.to_string()));
                }
            }
        };

        let status_code = resp.status().as_u16();
        if status_code >= 400 {
            let mut body = resp.into_body();
            let body_text = body.read_to_string().unwrap_or_default();
            return Err(ProviderError::Api { status: status_code, body: body_text });
        }

        let reader = resp.into_body().into_reader();
        parse_sse_stream(reader, sink, req.cancel)
    }
}

/// Build the JSON request body for the Anthropic Messages API.
fn build_request_body(req: &TurnRequest, model: &str) -> Value {
    let mut body = serde_json::Map::new();

    body.insert("model".into(), json!(model));
    body.insert("max_tokens".into(), json!(req.max_tokens.max(DEFAULT_MAX_TOKENS)));
    body.insert("stream".into(), json!(true));

    // Thinking config: skip when `no_thinking` is set (e.g. for Anthropic-compatible proxies
    // like DeepSeek that may not support the Anthropic-specific `thinking` parameter).
    if !req.no_thinking {
        body.insert("thinking".into(), json!({
            "type": "adaptive",
            "display": "summarized"
        }));
    }

    // Output effort (Anthropic `output_config.effort`: low|medium|high|xhigh|max).
    // This is the primary quality/cost lever on Opus 4.8 and is paired with
    // adaptive thinking. Skipped when empty or when thinking is disabled for an
    // Anthropic-compatible proxy that may not understand `output_config`.
    if !req.no_thinking && !req.effort.is_empty() {
        body.insert("output_config".into(), json!({ "effort": req.effort }));
    }

    // System prompt with cache control.
    body.insert("system".into(), json!([
        {
            "type": "text",
            "text": req.system,
            "cache_control": { "type": "ephemeral" }
        }
    ]));

    // Tools: convert from generic JSON Schema to Anthropic's format; add cache control on the last.
    let mut tools: Vec<Value> = req.tools.iter().map(|t| {
        json!({
            "name": t["name"],
            "description": t.get("description").and_then(|d| d.as_str()).unwrap_or(""),
            "input_schema": t.get("input_schema").or_else(|| t.get("schema")).cloned().unwrap_or(json!({"type":"object","properties":{}}))
        })
    }).collect();
    if let Some(o) = tools.last_mut().and_then(Value::as_object_mut) {
        o.insert("cache_control".into(), json!({ "type": "ephemeral" }));
    }
    body.insert("tools".into(), json!(tools));

    // Messages: convert internal transcript to Anthropic format. Consecutive tool_result
    // messages are merged into a single user message with multiple tool_result content blocks,
    // which the Anthropic API requires.
    let messages: Vec<Value> = {
        let mut merged: Vec<Value> = Vec::new();
        for msg in req.messages.iter().filter(|m| m.role != "system") {
            let anthropic_msg = message_to_anthropic(msg);
            if msg.role == "tool_result" {
                // Merge consecutive tool_result messages into the last user message.
                if let Some(last) = merged.last_mut()
                    && last["role"] == "user"
                        && let (Some(last_content), Some(new_content)) =
                            (last["content"].as_array_mut(), anthropic_msg["content"].as_array())
                        {
                            last_content.extend(new_content.iter().cloned());
                            continue;
                        }
            }
            merged.push(anthropic_msg);
        }
        merged
    };
    body.insert("messages".into(), json!(messages));

    Value::Object(body)
}

/// Convert an internal Message to the Anthropic messages API wire format.
fn message_to_anthropic(msg: &Message) -> Value {
    let mut obj = serde_json::Map::new();

    match msg.role.as_str() {
        "tool_result" => {
            obj.insert("role".into(), json!("user"));
            let text = msg.content.iter().filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            }).collect::<Vec<_>>().join("\n");
            obj.insert("content".into(), json!([{
                "type": "tool_result",
                "tool_use_id": msg.tool_call_id,
                "content": text,
                "is_error": msg.is_error,
            }]));
        }
        "assistant" => {
            obj.insert("role".into(), json!("assistant"));
            // Thinking blocks must be echoed back verbatim — including the
            // `signature` — when they precede a `tool_use` block, or the API
            // rejects the turn with a 400. A signature-less thinking block (from
            // a non-Anthropic provider) is emitted without the field. Block order
            // is preserved exactly as received from the stream.
            let blocks: Vec<Value> = msg.content.iter().map(|b| match b {
                ContentBlock::Text(t) => json!({ "type": "text", "text": t }),
                ContentBlock::Thinking { text, signature } => {
                    let mut block = serde_json::Map::new();
                    block.insert("type".into(), json!("thinking"));
                    block.insert("thinking".into(), json!(text));
                    if !signature.is_empty() {
                        block.insert("signature".into(), json!(signature));
                    }
                    Value::Object(block)
                }
                ContentBlock::RedactedThinking { data } =>
                    json!({ "type": "redacted_thinking", "data": data }),
                ContentBlock::ToolUse { id, name, input } => json!({
                    "type": "tool_use",
                    "id": id,
                    "name": name,
                    "input": input,
                }),
            }).collect();
            obj.insert("content".into(), json!(blocks));
        }
        "user" => {
            obj.insert("role".into(), json!("user"));
            let text = msg.content.iter().filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            }).collect::<Vec<_>>().join("\n");
            obj.insert("content".into(), json!([{ "type": "text", "text": text }]));
        }
        _ => {
            obj.insert("role".into(), json!(msg.role));
            let text = msg.content.iter().filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            }).collect::<Vec<_>>().join("\n");
            obj.insert("content".into(), json!(text));
        }
    }

    Value::Object(obj)
}

// ---------------------------------------------------------------------------
// SSE stream parsing
// ---------------------------------------------------------------------------

/// SSE event types from the Anthropic Messages API.
enum SseEvent {
    MessageStart,
    ContentBlockStart { index: usize, block: Value },
    ContentBlockDelta { index: usize, delta: Value },
    ContentBlockStop { index: usize },
    MessageDelta(Value),
    MessageStop,
    Ping,
}

/// Parse a single SSE line (event: or data:) and extract structured events.
fn parse_sse_line(line: &str) -> Option<SseEvent> {
    if line.starts_with("event: ") {
        return None; // event type line; next line is data
    }
    if let Some(data) = line.strip_prefix("data: ") {
        if data.trim().is_empty() {
            return None;
        }
        let json: Value = serde_json::from_str(data).ok()?;
        match json["type"].as_str()? {
            "message_start" => Some(SseEvent::MessageStart),
            "content_block_start" => {
                let index = json["index"].as_u64().unwrap_or(0) as usize;
                let block = json["content_block"].clone();
                Some(SseEvent::ContentBlockStart { index, block })
            }
            "content_block_delta" => {
                let index = json["index"].as_u64().unwrap_or(0) as usize;
                let delta = json["delta"].clone();
                Some(SseEvent::ContentBlockDelta { index, delta })
            }
            "content_block_stop" => {
                let index = json["index"].as_u64().unwrap_or(0) as usize;
                Some(SseEvent::ContentBlockStop { index })
            }
            "message_delta" => Some(SseEvent::MessageDelta(json)),
            "message_stop" => Some(SseEvent::MessageStop),
            "ping" => Some(SseEvent::Ping),
            _ => None,
        }
    } else {
        None
    }
}

/// Parse the full SSE stream from an HTTP response reader, accumulating content blocks and
/// emitting events to the sink. Returns the accumulated turn result.
fn parse_sse_stream<R: Read>(
    reader: R,
    sink: &mut dyn EventSink,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<TurnResult, ProviderError> {
    use std::sync::atomic::Ordering;
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    // During streaming, content blocks arrive by index. We accumulate them incrementally.
    // content_blocks[index] = (type, id, name, text_accumulator, json_accumulator)
    enum AccumBlock {
        Text(String),       // accumulating text
        /// Accumulating thinking text plus its signature. The signature arrives
        /// in `signature_delta` events (and occasionally on the start block) and
        /// must be preserved for replay — see [`ContentBlock::Thinking`].
        Thinking { text: String, signature: String },
        RedactedThinking { data: String },
        ToolUse { id: String, name: String, input: String }, // accumulating JSON string for input
    }

    let mut blocks: Vec<AccumBlock> = Vec::new();
    let mut stop_reason = String::from("end_turn");
    let mut usage = None;

    loop {
        // Cooperative cancellation: bail before the next (blocking) read so the
        // UI's Esc/cancel aborts the turn promptly. Dropping `buf_reader` on
        // return closes the underlying connection.
        if cancel.load(Ordering::Relaxed) {
            return Err(ProviderError::Stream("cancelled".into()));
        }

        line.clear();
        let bytes_read = buf_reader.read_line(&mut line)
            .map_err(|e| ProviderError::Stream(e.to_string()))?;
        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Some(event) = parse_sse_line(trimmed) else {
            continue;
        };

        match event {
            SseEvent::ContentBlockStart { index, block } => {
                // Ensure blocks vector is large enough.
                while blocks.len() <= index {
                    blocks.push(AccumBlock::Text(String::new()));
                }
                match block["type"].as_str() {
                    Some("text") => {
                        let text = block["text"].as_str().unwrap_or("");
                        blocks[index] = AccumBlock::Text(text.to_string());
                    }
                    Some("thinking") => {
                        let thinking = block["thinking"].as_str().unwrap_or("");
                        let signature = block["signature"].as_str().unwrap_or("").to_string();
                        blocks[index] = AccumBlock::Thinking { text: thinking.to_string(), signature };
                    }
                    Some("redacted_thinking") => {
                        let data = block["data"].as_str().unwrap_or("").to_string();
                        blocks[index] = AccumBlock::RedactedThinking { data };
                    }
                    Some("tool_use") => {
                        let id = block["id"].as_str().unwrap_or("").to_string();
                        let name = block["name"].as_str().unwrap_or("").to_string();
                        // The start block's `input` is normally an empty object
                        // `{}` and the real arguments stream in via
                        // `input_json_delta`. Seed the accumulator EMPTY in that
                        // case — seeding with "{}" would corrupt the JSON once
                        // deltas are appended (`{}{"k":"v"}`). Only when the start
                        // block already carries a populated object (some
                        // proxies/non-streaming shapes) do we keep it verbatim,
                        // and emit the tool call immediately.
                        let input_val = &block["input"];
                        let prepopulated = input_val
                            .as_object()
                            .map(|o| !o.is_empty())
                            .unwrap_or(false);
                        let input = if prepopulated { input_val.to_string() } else { String::new() };
                        // The ToolCall event is emitted once, at content_block_stop,
                        // after the full input has been accumulated.
                        blocks[index] = AccumBlock::ToolUse { id, name, input };
                    }
                    _ => {}
                }
            }

            SseEvent::ContentBlockDelta { index, delta } => {
                while blocks.len() <= index {
                    blocks.push(AccumBlock::Text(String::new()));
                }
                match delta["type"].as_str() {
                    Some("text_delta") => {
                        let text = delta["text"].as_str().unwrap_or("");
                        if let AccumBlock::Text(acc) = &mut blocks[index] {
                            acc.push_str(text);
                        }
                        sink.emit(AgentEvent::TextDelta(text.to_string()));
                    }
                    Some("thinking_delta") => {
                        let thinking = delta["thinking"].as_str().unwrap_or("");
                        if let AccumBlock::Thinking { text, .. } = &mut blocks[index] {
                            text.push_str(thinking);
                        }
                        sink.emit(AgentEvent::ThinkingDelta(thinking.to_string()));
                    }
                    Some("signature_delta") => {
                        // The signature is delivered as a delta and is required to
                        // replay the thinking block on the next turn.
                        let sig = delta["signature"].as_str().unwrap_or("");
                        if let AccumBlock::Thinking { signature, .. } = &mut blocks[index] {
                            signature.push_str(sig);
                        }
                    }
                    Some("input_json_delta") => {
                        let partial = delta["partial_json"].as_str().unwrap_or("");
                        if let AccumBlock::ToolUse { input, .. } = &mut blocks[index] {
                            input.push_str(partial);
                        }
                    }
                    _ => {}
                }
            }

            SseEvent::ContentBlockStop { index } => {
                // If this was a tool_use block, finalize and emit the tool call.
                // For tool_use, we send the event on start (not here) unless we're accumulating JSON.
                // Actually, we need to send the ToolCall event here after accumulating all deltas.
                if let Some(AccumBlock::ToolUse { id, name, input }) = &blocks.get(index)
                    && !id.is_empty() {
                        let parsed: Value = serde_json::from_str(input).unwrap_or(json!({}));
                        sink.emit(AgentEvent::ToolCall {
                            id: id.clone(),
                            name: name.clone(),
                            input: parsed,
                        });
                    }
            }

            SseEvent::MessageDelta(delta) => {
                if let Some(reason) = delta["delta"]["stop_reason"].as_str() {
                    stop_reason = reason.to_string();
                    sink.emit(AgentEvent::StopReason(stop_reason.clone()));
                }
                let usage_obj = delta.get("usage");
                if let Some(u) = usage_obj {
                    let input_tokens = u.get("input_tokens").and_then(Value::as_u64).unwrap_or(0) as u32;
                    let output_tokens = u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0) as u32;
                    let cache_read = u.get("cache_read_input_tokens").and_then(Value::as_u64).map(|v| v as u32);
                    usage = Some((input_tokens, output_tokens));
                    sink.emit(AgentEvent::Usage {
                        input_tokens,
                        output_tokens,
                        cache_read_tokens: cache_read,
                    });
                }
            }

            SseEvent::MessageStart => {
                // The message_start event carries the full message shape, but we process it
                // incrementally via content_block_start/delta/stop events.
            }

            SseEvent::MessageStop => {
                break;
            }

            SseEvent::Ping => {
                // Heartbeat; ignore.
            }
        }
    }

    // Convert accumulated blocks to TurnResult.
    let content_blocks: Vec<ContentBlock> = blocks.into_iter().map(|b| match b {
        AccumBlock::Text(t) => ContentBlock::Text(t),
        AccumBlock::Thinking { text, signature } => ContentBlock::Thinking { text, signature },
        AccumBlock::RedactedThinking { data } => ContentBlock::RedactedThinking { data },
        AccumBlock::ToolUse { id, name, input } => {
            let parsed: Value = serde_json::from_str(&input).unwrap_or(json!({}));
            ContentBlock::ToolUse { id, name, input: parsed }
        }
    }).collect();

    // A "refusal" is a *successful* HTTP 200 with empty/partial content. Return
    // it as a normal turn so the agent loop can end gracefully and keep the
    // session usable, rather than aborting with a hard error.
    Ok(TurnResult { content: content_blocks, stop_reason, usage })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock sink that collects events for testing.
    struct TestSink {
        events: Vec<AgentEvent>,
    }
    impl TestSink {
        fn new() -> Self { TestSink { events: Vec::new() } }
    }
    impl EventSink for TestSink {
        fn emit(&mut self, event: AgentEvent) {
            self.events.push(event);
        }
    }

    #[test]
    fn parse_sse_content_block_delta_text() {
        let event = parse_sse_line("data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}").unwrap();
        match event {
            SseEvent::ContentBlockDelta { index, delta } => {
                assert_eq!(index, 0);
                assert_eq!(delta["type"], "text_delta");
                assert_eq!(delta["text"], "Hello");
            }
            _ => panic!("wrong event type"),
        }
    }

    #[test]
    fn parse_sse_tool_use_start() {
        let event = parse_sse_line("data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_abc\",\"name\":\"atom_query\",\"input\":{\"kind\":\"files\"}}}").unwrap();
        match event {
            SseEvent::ContentBlockStart { index, block } => {
                assert_eq!(index, 0);
                assert_eq!(block["type"], "tool_use");
                assert_eq!(block["id"], "toolu_abc");
                assert_eq!(block["name"], "atom_query");
            }
            _ => panic!("wrong event type"),
        }
    }

    #[test]
    fn parse_sse_message_delta_with_usage() {
        let event = parse_sse_line("data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"input_tokens\":10,\"output_tokens\":25}}").unwrap();
        match event {
            SseEvent::MessageDelta(data) => {
                assert_eq!(data["delta"]["stop_reason"], "end_turn");
                assert_eq!(data["usage"]["input_tokens"], 10);
                assert_eq!(data["usage"]["output_tokens"], 25);
            }
            _ => panic!("wrong event type"),
        }
    }

    #[test]
    fn parse_sse_ignores_unknown_event_type() {
        assert!(parse_sse_line("data: {\"type\":\"unknown_event\"}").is_none());
    }

    #[test]
    fn parse_sse_message_stop() {
        let event = parse_sse_line("data: {\"type\":\"message_stop\"}").unwrap();
        assert!(matches!(event, SseEvent::MessageStop));
    }

    #[test]
    fn empty_line_returns_none() {
        assert!(parse_sse_line("").is_none());
    }

    #[test]
    fn non_data_line_returns_none() {
        assert!(parse_sse_line("event: ping").is_none());
    }

    use std::sync::atomic::AtomicBool;

    /// Build a minimal `TurnRequest` for body-shaping tests.
    fn req<'a>(
        system: &'a str,
        tools: &'a [Value],
        messages: &'a [Message],
        no_thinking: bool,
        effort: &'a str,
        cancel: &'a AtomicBool,
    ) -> TurnRequest<'a> {
        TurnRequest { system, tools, messages, max_tokens: 16000, no_thinking, effort, cancel }
    }

    #[test]
    fn request_body_has_thinking_effort_and_caching() {
        let cancel = AtomicBool::new(false);
        let tools = vec![
            json!({"name": "a", "description": "d", "input_schema": {"type": "object"}}),
            json!({"name": "b", "description": "d", "input_schema": {"type": "object"}}),
        ];
        let msgs = vec![Message::user("hello")];
        let body = build_request_body(
            &req("SYS", &tools, &msgs, false, "high", &cancel),
            "claude-opus-4-8",
        );

        assert_eq!(body["model"], "claude-opus-4-8");
        assert_eq!(body["max_tokens"], 16000);
        assert_eq!(body["stream"], true);
        assert_eq!(body["thinking"]["type"], "adaptive");
        assert_eq!(body["thinking"]["display"], "summarized");
        // effort is the primary quality lever (§1.3).
        assert_eq!(body["output_config"]["effort"], "high");
        // System block is cached.
        assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
        // Cache breakpoint is on the LAST tool only.
        let tool_arr = body["tools"].as_array().unwrap();
        assert!(tool_arr[0].get("cache_control").is_none());
        assert_eq!(tool_arr[1]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn no_thinking_omits_thinking_and_effort() {
        let cancel = AtomicBool::new(false);
        let msgs = vec![Message::user("hello")];
        let body = build_request_body(
            &req("SYS", &[], &msgs, true, "high", &cancel),
            "deepseek-chat",
        );
        // Anthropic-compatible proxies (DeepSeek) get neither field.
        assert!(body.get("thinking").is_none());
        assert!(body.get("output_config").is_none());
    }

    #[test]
    fn empty_effort_omits_output_config() {
        let cancel = AtomicBool::new(false);
        let msgs = vec![Message::user("hello")];
        let body = build_request_body(&req("SYS", &[], &msgs, false, "", &cancel), "claude-opus-4-8");
        assert!(body.get("output_config").is_none());
        // thinking is still present when not disabled.
        assert_eq!(body["thinking"]["type"], "adaptive");
    }

    #[test]
    fn assistant_thinking_block_roundtrips_with_signature() {
        // Regression for §1.1: a thinking block echoed before tool_use MUST keep
        // its signature, or the API 400s on the next turn.
        let cancel = AtomicBool::new(false);
        let msgs = vec![
            Message::user("trace a flow"),
            Message::assistant(vec![
                ContentBlock::Thinking { text: "let me think".into(), signature: "sig_abc".into() },
                ContentBlock::ToolUse {
                    id: "tu_1".into(),
                    name: "atom_flows".into(),
                    input: json!({"preset": "reachables"}),
                },
            ]),
            Message::tool_result("tu_1", "{\"total\":2}", false),
        ];
        let body = build_request_body(&req("SYS", &[], &msgs, false, "high", &cancel), "claude-opus-4-8");
        let assistant = &body["messages"][1];
        assert_eq!(assistant["role"], "assistant");
        let blocks = assistant["content"].as_array().unwrap();
        // Order preserved: thinking precedes tool_use.
        assert_eq!(blocks[0]["type"], "thinking");
        assert_eq!(blocks[0]["thinking"], "let me think");
        assert_eq!(blocks[0]["signature"], "sig_abc");
        assert_eq!(blocks[1]["type"], "tool_use");
        // Tool result merged into a following user message.
        assert_eq!(body["messages"][2]["content"][0]["type"], "tool_result");
    }

    #[test]
    fn thinking_block_without_signature_omits_field() {
        let cancel = AtomicBool::new(false);
        let msgs = vec![Message::assistant(vec![
            ContentBlock::Thinking { text: "t".into(), signature: String::new() },
        ])];
        let body = build_request_body(&req("SYS", &[], &msgs, false, "high", &cancel), "claude-opus-4-8");
        let block = &body["messages"][0]["content"][0];
        assert_eq!(block["type"], "thinking");
        assert!(block.get("signature").is_none());
    }

    #[test]
    fn sse_stream_captures_thinking_signature_and_tool_use() {
        // A full streamed turn: thinking text + signature_delta, then a tool_use.
        let stream = concat!(
            "data: {\"type\":\"message_start\",\"message\":{}}\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"reasoning\"}}\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig_xyz\"}}\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu_9\",\"name\":\"atom_query\",\"input\":{}}}\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"kind\\\":\\\"files\\\"}\"}}\n",
            "data: {\"type\":\"content_block_stop\",\"index\":1}\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":7}}\n",
            "data: {\"type\":\"message_stop\"}\n",
        );
        let cancel = AtomicBool::new(false);
        let mut sink = TestSink::new();
        let result = parse_sse_stream(stream.as_bytes(), &mut sink, &cancel).unwrap();

        assert_eq!(result.stop_reason, "tool_use");
        match &result.content[0] {
            ContentBlock::Thinking { text, signature } => {
                assert_eq!(text, "reasoning");
                assert_eq!(signature, "sig_xyz");
            }
            other => panic!("expected thinking block, got {other:?}"),
        }
        match &result.content[1] {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "tu_9");
                assert_eq!(name, "atom_query");
                assert_eq!(input["kind"], "files");
            }
            other => panic!("expected tool_use block, got {other:?}"),
        }
    }

    #[test]
    fn sse_stream_aborts_on_cancel() {
        let stream = "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n";
        let cancel = AtomicBool::new(true); // already cancelled
        let mut sink = TestSink::new();
        let err = parse_sse_stream(stream.as_bytes(), &mut sink, &cancel).unwrap_err();
        assert!(matches!(err, ProviderError::Stream(ref m) if m == "cancelled"));
    }

    #[test]
    fn normalize_url_various_inputs() {
        assert_eq!(normalize_anthropic_url("https://api.deepseek.com"), "https://api.deepseek.com/v1/messages");
        assert_eq!(normalize_anthropic_url("https://api.deepseek.com/anthropic"), "https://api.deepseek.com/anthropic/v1/messages");
        assert_eq!(normalize_anthropic_url("https://api.deepseek.com/anthropic/v1/messages"), "https://api.deepseek.com/anthropic/v1/messages");
        assert_eq!(normalize_anthropic_url("https://api.deepseek.com/v1"), "https://api.deepseek.com/v1/messages");
        assert_eq!(normalize_anthropic_url("https://api.anthropic.com/v1/messages"), "https://api.anthropic.com/v1/messages");
    }
}
