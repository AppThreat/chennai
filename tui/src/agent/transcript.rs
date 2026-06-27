//! Conversation transcript: manages the message list and provides provider-specific serialization.
//!
//! The transcript stores messages in a provider-agnostic format and can render them to JSON for
//! either the Anthropic Messages API or the OpenAI Chat Completions API wire format.

use super::provider::{ContentBlock, Message};
use serde_json::Value;

/// A conversation transcript — the sequence of user, assistant, and tool_result messages.
#[derive(Debug, Clone)]
pub struct Transcript {
    messages: Vec<Message>,
}

impl Transcript {
    pub fn new() -> Self {
        Transcript { messages: Vec::new() }
    }

    #[allow(dead_code)]
    pub fn with_initial(initial: Vec<Message>) -> Self {
        Transcript { messages: initial }
    }

    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    #[allow(dead_code)]
    pub fn push(&mut self, msg: Message) {
        self.messages.push(msg);
    }

    pub fn push_user(&mut self, text: &str) {
        self.messages.push(Message::user(text));
    }

    pub fn push_assistant(&mut self, blocks: Vec<ContentBlock>) {
        self.messages.push(Message::assistant(blocks));
    }

    pub fn push_tool_result(&mut self, call_id: &str, content: &str, is_error: bool) {
        self.messages.push(Message::tool_result(call_id, content, is_error));
    }

    /// Push multiple tool results as separate `tool_result` messages, each with its own
    /// `tool_call_id`.  The Anthropic wire format serialiser merges consecutive tool_result
    /// messages with the same `role` into a single user message containing multiple content
    /// blocks so the API never sees orphaned `tool_use` ids.
    #[allow(dead_code)]
    pub fn push_tool_results(&mut self, results: &[super::ToolExecResult]) {
        for result in results {
            self.push_tool_result(&result.call_id, &result.content, result.is_error);
        }
    }

    /// Serialize to the Anthropic Messages API wire format.
    #[allow(dead_code)]
    pub fn to_anthropic_json(&self) -> Vec<Value> {
        self.messages.iter()
            .filter(|m| m.role != "system")
            .map(|m| {
                let mut obj = serde_json::Map::new();
                let role = if m.role == "tool_result" { "user" } else { m.role.as_str() };
                obj.insert("role".into(), Value::String(role.into()));

                if m.role == "tool_result" {
                    let mut content = Vec::new();
                    let text = m.content.iter().filter_map(|b| match b {
                        ContentBlock::Text(t) => Some(t.as_str()),
                        _ => None,
                    }).collect::<Vec<_>>().join("\n");
                    content.push(serde_json::json!({
                        "type": "tool_result",
                        "tool_use_id": m.tool_call_id,
                        "content": text,
                        "is_error": m.is_error,
                    }));
                    obj.insert("content".into(), Value::Array(content));
                } else {
                    let blocks: Vec<Value> = m.content.iter().map(|b| match b {
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
                    }).collect();
                    obj.insert("content".into(), Value::Array(blocks));
                }
                Value::Object(obj)
            })
            .collect()
    }

    /// Serialize to the OpenAI Chat Completions API wire format.
    #[allow(dead_code)]
    pub fn to_openai_json(&self) -> Vec<Value> {
        self.messages.iter()
            .map(|m| {
                let mut obj = serde_json::Map::new();
                let role = if m.role == "tool_result" { "tool" } else { m.role.as_str() };
                obj.insert("role".into(), Value::String(role.into()));

                match m.role.as_str() {
                    "assistant" => {
                        let text = m.content.iter().filter_map(|b| match b {
                            ContentBlock::Text(t) => Some(t.clone()),
                            _ => None,
                        }).collect::<Vec<_>>().join("");
                        if !text.is_empty() {
                            obj.insert("content".into(), Value::String(text));
                        }
                        let tool_calls: Vec<Value> = m.content.iter().filter_map(|b| match b {
                            ContentBlock::ToolUse { id, name, input } => Some(serde_json::json!({
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
                            obj.insert("tool_calls".into(), Value::Array(tool_calls));
                        }
                    }
                    "tool" => {
                        let text = m.content.iter().filter_map(|b| match b {
                            ContentBlock::Text(t) => Some(t.as_str()),
                            _ => None,
                        }).collect::<Vec<_>>().join("\n");
                        obj.insert("content".into(), Value::String(text));
                        obj.insert("tool_call_id".into(), Value::String(m.tool_call_id.clone().unwrap_or_default()));
                    }
                    _ => {
                        let text = m.content.iter().filter_map(|b| match b {
                            ContentBlock::Text(t) => Some(t.as_str()),
                            _ => None,
                        }).collect::<Vec<_>>().join("\n");
                        obj.insert("content".into(), Value::String(text));
                    }
                }
                Value::Object(obj)
            })
            .collect()
    }

    /// Extract tool_use content blocks from the last assistant message.
    pub fn last_tool_calls(&self) -> Vec<(String, String, Value)> {
        self.messages.iter().rev().find(|m| m.role == "assistant")
            .map(|m| {
                m.content.iter().filter_map(|b| match b {
                    ContentBlock::ToolUse { id, name, input } =>
                        Some((id.clone(), name.clone(), input.clone())),
                    _ => None,
                }).collect()
            })
            .unwrap_or_default()
    }
}

impl Default for Transcript {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_transcript_serializes_to_empty_array() {
        let t = Transcript::new();
        assert!(t.to_anthropic_json().is_empty());
        assert!(t.to_openai_json().is_empty());
    }

    #[test]
    fn anthropic_tool_result_has_correct_shape() {
        let mut t = Transcript::new();
        t.push_user("hello");
        t.push_assistant(vec![
            ContentBlock::ToolUse { id: "tu_1".into(), name: "atom_query".into(), input: serde_json::json!({"kind": "files"}) },
        ]);
        t.push_tool_result("tu_1", r#"{"total":5}"#, false);

        let json = t.to_anthropic_json();
        assert_eq!(json.len(), 3);
        assert_eq!(json[2]["content"][0]["type"], "tool_result");
        assert_eq!(json[2]["content"][0]["tool_use_id"], "tu_1");
    }

    #[test]
    fn openai_tool_result_has_correct_role() {
        let mut t = Transcript::new();
        t.push_user("hello");
        t.push_assistant(vec![
            ContentBlock::ToolUse { id: "call_1".into(), name: "atom_query".into(), input: serde_json::json!({"kind": "methods"}) },
        ]);
        t.push_tool_result("call_1", r#"{"total":3}"#, false);

        let json = t.to_openai_json();
        assert_eq!(json.len(), 3);
        assert_eq!(json[1]["tool_calls"][0]["function"]["name"], "atom_query");
        assert_eq!(json[2]["role"], "tool");
    }
}
