//! OpenAI-compatible Chat Completions API provider.
//!
//! Supports any OpenAI-compatible endpoint (OpenAI, Azure, Ollama, vLLM, llama.cpp, OpenRouter).
//! The `base_url` is configurable; the path `/v1/chat/completions` is appended automatically if
//! not already present in the URL.

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

const DEFAULT_MAX_TOKENS: u32 = 8192;
/// Generous hard backstop for a streamed turn; see the Anthropic provider's
/// `HTTP_TIMEOUT` for rationale. Prompt responsiveness comes from the per-chunk
/// cancel check in [`parse_sse_stream`], not this value.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Provider for any OpenAI-compatible Chat Completions API.
pub struct OpenAIProvider {
    api_key: String,
    model: String,
    base_url: String,
}

impl OpenAIProvider {
    pub fn new(api_key: String, model: String, base_url: Option<String>) -> Self {
        let base_url = base_url.unwrap_or_else(|| "https://api.openai.com".into());
        let base_url = normalize_base_url(&base_url);
        OpenAIProvider { api_key, model, base_url }
    }
}

/// Ensure the base URL ends with `/v1/chat/completions`.
fn normalize_base_url(url: &str) -> String {
    let url = url.trim_end_matches('/');
    if url.ends_with("/v1/chat/completions") {
        url.to_string()
    } else if url.ends_with("/v1") {
        format!("{url}/chat/completions")
    } else if url.ends_with("/chat/completions") && url.contains("/v1/") {
        url.to_string()
    } else {
        format!("{url}/v1/chat/completions")
    }
}

impl LlmProvider for OpenAIProvider {
    fn stream_turn(&self, req: &TurnRequest, sink: &mut dyn EventSink) -> Result<TurnResult, ProviderError> {
        let body = build_request_body(req, &self.model);
        let body_bytes = serde_json::to_vec(&body).map_err(|e| ProviderError::Protocol(e.to_string()))?;

        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(HTTP_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        // Send with bounded retry on transient failures — see the Anthropic
        // provider for rationale.
        let mut attempt = 0;
        let resp = loop {
            attempt += 1;
            if req.cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(ProviderError::Stream("cancelled".into()));
            }
            match agent
                .post(&self.base_url)
                .header("authorization", &format!("Bearer {}", self.api_key))
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

/// Build the JSON request body for the OpenAI Chat Completions API.
fn build_request_body(req: &TurnRequest, model: &str) -> Value {
    let mut body = serde_json::Map::new();

    body.insert("model".into(), json!(model));
    body.insert("max_tokens".into(), json!(req.max_tokens.max(DEFAULT_MAX_TOKENS)));
    body.insert("stream".into(), json!(true));

    // Tools: convert from generic JSON Schema to OpenAI's function format.
    let tools: Vec<Value> = req.tools.iter().map(|t| {
        json!({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description").and_then(|d| d.as_str()).unwrap_or(""),
                "parameters": t.get("input_schema").or_else(|| t.get("schema")).cloned().unwrap_or(json!({"type":"object","properties":{}}))
            }
        })
    }).collect();
    if !tools.is_empty() {
        body.insert("tools".into(), json!(tools));
    }

    // Messages: convert internal transcript to OpenAI format. The system prompt
    // is delivered as the first `system`-role message (OpenAI's convention) —
    // without this the grounding rule, atom summary, and DSL cheat-sheet are
    // silently dropped on the OpenAI-compatible path.
    let mut messages: Vec<Value> = Vec::with_capacity(req.messages.len() + 1);
    if !req.system.is_empty() {
        messages.push(json!({ "role": "system", "content": req.system }));
    }
    messages.extend(req.messages.iter().map(message_to_openai));
    body.insert("messages".into(), json!(messages));

    Value::Object(body)
}

/// Convert an internal Message to the OpenAI Chat Completions wire format.
fn message_to_openai(msg: &Message) -> Value {
    let mut obj = serde_json::Map::new();

    match msg.role.as_str() {
        "system" => {
            obj.insert("role".into(), json!("system"));
            let text = msg.content.iter().filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            }).collect::<Vec<_>>().join("\n");
            obj.insert("content".into(), json!(text));
        }
        "assistant" => {
            obj.insert("role".into(), json!("assistant"));
            let text = msg.content.iter().filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            }).collect::<Vec<_>>().join("");
            obj.insert("content".into(), json!(if text.is_empty() { None::<String> } else { Some(text) }));

            let tool_calls: Vec<Value> = msg.content.iter().filter_map(|b| match b {
                ContentBlock::ToolUse { id, name, input } => Some(json!({
                    "id": id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": input.to_string(),
                    }
                })),
                _ => None,
            }).collect();
            if !tool_calls.is_empty() {
                obj.insert("tool_calls".into(), json!(tool_calls));
            }
        }
        "tool_result" => {
            obj.insert("role".into(), json!("tool"));
            let text = msg.content.iter().filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            }).collect::<Vec<_>>().join("\n");
            // OpenAI's tool role has no `is_error` field, so signal failures
            // in-band — otherwise the model can't tell a failed call from an
            // empty success and won't self-correct.
            let content = if msg.is_error { format!("ERROR: {text}") } else { text };
            obj.insert("content".into(), json!(content));
            obj.insert("tool_call_id".into(), json!(msg.tool_call_id));
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
// SSE stream parsing (OpenAI format)
// ---------------------------------------------------------------------------

// OpenAI sends lines like:
//   data: {"id":"...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}
//   data: {"id":"...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":" World"},"finish_reason":null}]}
//   data: {"id":"...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_xxx","type":"function","function":{"name":"tool","arguments":""}}]},"finish_reason":null}]}
//   data: {"id":"...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}
//   data: [DONE]

/// Accumulated state for building a tool call from streaming deltas.
#[derive(Debug, Default)]
struct ToolCallAccum {
    id: String,
    name: String,
    arguments: String,
}

/// Parse the SSE stream from an OpenAI-compatible streaming response.
fn parse_sse_stream<R: Read>(
    reader: R,
    sink: &mut dyn EventSink,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<TurnResult, ProviderError> {
    use std::sync::atomic::Ordering;
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    let mut full_text = String::new();
    // Tool calls keyed by index (as returned by the API).
    let mut tool_calls: Vec<ToolCallAccum> = Vec::new();
    let mut stop_reason = String::new();
    let mut usage = None;

    loop {
        // Cooperative cancellation — see the Anthropic provider for rationale.
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

        // End-of-stream marker.
        if trimmed == "data: [DONE]" {
            break;
        }

        let Some(data) = trimmed.strip_prefix("data: ") else {
            continue;
        };

        let chunk: Value = serde_json::from_str(data)
            .map_err(|e| ProviderError::Stream(format!("invalid JSON in SSE: {e}")))?;

        let empty: Vec<Value> = Vec::new();
        let choices = chunk["choices"].as_array().unwrap_or(&empty);
        for choice in choices {
            let delta = &choice["delta"];
            let finish = choice["finish_reason"].as_str();

            // Content delta.
            if let Some(content) = delta.get("content").and_then(Value::as_str) {
                full_text.push_str(content);
                sink.emit(AgentEvent::TextDelta(content.to_string()));
            }

            // Role announcement (first chunk of an assistant turn).
            if let Some(role) = delta.get("role").and_then(Value::as_str)
                && role == "assistant" {
                    // Role marker; no text content yet.
                }

            // Tool calls delta.
            if let Some(tcs) = delta.get("tool_calls").and_then(Value::as_array) {
                for tc in tcs {
                    let idx = tc.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                    while tool_calls.len() <= idx {
                        tool_calls.push(ToolCallAccum::default());
                    }
                    if let Some(id) = tc.get("id").and_then(Value::as_str) {
                        tool_calls[idx].id = id.to_string();
                    }
                    if let Some(func) = tc.get("function") {
                        if let Some(name) = func.get("name").and_then(Value::as_str) {
                            tool_calls[idx].name = name.to_string();
                        }
                        if let Some(args) = func.get("arguments").and_then(Value::as_str) {
                            tool_calls[idx].arguments.push_str(args);
                        }
                    }
                }
            }

            // Finish reason.
            if let Some(reason) = finish
                && !reason.is_empty() && reason != "null" {
                    stop_reason = reason.to_string();
                    sink.emit(AgentEvent::StopReason(stop_reason.clone()));
                }
        }

        // Usage info (may appear in the final chunk for some providers).
        if let Some(u) = chunk.get("usage") {
            let input_tokens = u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0) as u32;
            let output_tokens = u.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0) as u32;
            usage = Some((input_tokens, output_tokens));
            sink.emit(AgentEvent::Usage {
                input_tokens,
                output_tokens,
                cache_read_tokens: None,
            });
        }
    }

    // Build content blocks from accumulated text and tool calls.
    let mut content: Vec<ContentBlock> = Vec::new();

    if !full_text.is_empty() {
        content.push(ContentBlock::Text(full_text));
    }

    for tc in &tool_calls {
        let parsed_input: Value = serde_json::from_str(&tc.arguments).unwrap_or(json!({}));
        let input_for_event = parsed_input.clone();
        content.push(ContentBlock::ToolUse {
            id: tc.id.clone(),
            name: tc.name.clone(),
            input: parsed_input,
        });
        sink.emit(AgentEvent::ToolCall {
            id: tc.id.clone(),
            name: tc.name.clone(),
            input: input_for_event,
        });
    }

    if stop_reason.is_empty() {
        stop_reason = if tool_calls.is_empty() { "stop".into() } else { "tool_calls".into() };
    }

    Ok(TurnResult { content, stop_reason, usage })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn request_body_prepends_system_prompt() {
        // Regression for §1.2: the OpenAI path previously dropped the system
        // prompt entirely.
        use super::super::provider::Message;
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let msgs = vec![Message::user("hello")];
        let req = TurnRequest {
            system: "GROUNDING RULES",
            tools: &[],
            messages: &msgs,
            max_tokens: 16000,
            no_thinking: false,
            effort: "high",
            cancel: &cancel,
        };
        let body = build_request_body(&req, "gpt-4o");
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "GROUNDING RULES");
        assert_eq!(messages[1]["role"], "user");
    }

    #[test]
    fn request_body_omits_empty_system_prompt() {
        use super::super::provider::Message;
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let msgs = vec![Message::user("hello")];
        let req = TurnRequest {
            system: "",
            tools: &[],
            messages: &msgs,
            max_tokens: 16000,
            no_thinking: false,
            effort: "",
            cancel: &cancel,
        };
        let body = build_request_body(&req, "gpt-4o");
        assert_eq!(body["messages"][0]["role"], "user");
    }

    #[test]
    fn normalize_base_url_handles_various_inputs() {
        assert_eq!(normalize_base_url("https://api.openai.com"), "https://api.openai.com/v1/chat/completions");
        assert_eq!(normalize_base_url("https://api.openai.com/v1"), "https://api.openai.com/v1/chat/completions");
        assert_eq!(normalize_base_url("https://api.openai.com/v1/"), "https://api.openai.com/v1/chat/completions");
        assert_eq!(normalize_base_url("https://api.openai.com/v1/chat/completions"), "https://api.openai.com/v1/chat/completions");
        assert_eq!(normalize_base_url("http://localhost:11434/v1"), "http://localhost:11434/v1/chat/completions");
    }

    #[test]
    fn parse_openai_sse_content_delta() {
        let data = "data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n";
        let reader = data.as_bytes();
        let mut sink = TestSink::new();
        let result = parse_sse_stream(reader, &mut sink, &std::sync::atomic::AtomicBool::new(false)).unwrap();
        assert!(sink.events.iter().any(|e| matches!(e, AgentEvent::TextDelta(t) if t == "Hello")));
        assert_eq!(result.content.len(), 1);
        if let ContentBlock::Text(t) = &result.content[0] {
            assert_eq!(t, "Hello");
        } else {
            panic!("expected text block");
        }
    }

    #[test]
    fn parse_openai_sse_tool_call() {
        let stream = format!(
            "data: {}\ndata: {}\ndata: {}\n",
            r#"{"id":"1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"atom_query","arguments":""}}]},"finish_reason":null}]}"#,
            r#"{"id":"1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"kind\":\"files\"}"}}]},"finish_reason":null}]}"#,
            r#"{"id":"1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        );
        let reader = stream.as_bytes();
        let mut sink = TestSink::new();
        let result = parse_sse_stream(reader, &mut sink, &std::sync::atomic::AtomicBool::new(false)).unwrap();
        assert_eq!(result.stop_reason, "tool_calls");
        assert_eq!(result.content.len(), 1);
        if let ContentBlock::ToolUse { id, name, input } = &result.content[0] {
            assert_eq!(id, "call_1");
            assert_eq!(name, "atom_query");
            assert_eq!(input["kind"], "files");
        } else {
            panic!("expected tool_use block");
        }
    }

    #[test]
    fn parse_openai_sse_done_marker_stops() {
        let data = "data: [DONE]\n";
        let reader = data.as_bytes();
        let mut sink = TestSink::new();
        let result = parse_sse_stream(reader, &mut sink, &std::sync::atomic::AtomicBool::new(false)).unwrap();
        assert!(result.content.is_empty());
    }

    #[test]
    fn parse_openai_sse_accumulates_text_across_chunks() {
        let stream = "data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\
                       data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\
                       data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" World\"},\"finish_reason\":null}]}\n\
                       data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n";
        let reader = stream.as_bytes();
        let mut sink = TestSink::new();
        let result = parse_sse_stream(reader, &mut sink, &std::sync::atomic::AtomicBool::new(false)).unwrap();
        assert_eq!(result.content.len(), 1);
        if let ContentBlock::Text(t) = &result.content[0] {
            assert_eq!(t, "Hello World");
        } else {
            panic!("expected text block");
        }
    }
}
