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
    /// Soft chars-based budget for compaction. When the estimated token count
    /// (chars/4) of the transcript exceeds this threshold, old assistant↔tool
    /// cycles are compacted. Defaults to ~60% of a 128k context window.
    pub compaction_threshold: usize,
}

impl Transcript {
    pub fn new() -> Self {
        Transcript {
            messages: Vec::new(),
            compaction_threshold: 19_200,
        } // ~60% of 128k tokens as chars/4
    }

    #[allow(dead_code)]
    pub fn with_initial(initial: Vec<Message>) -> Self {
        Transcript {
            messages: initial,
            compaction_threshold: 19_200,
        }
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
        self.messages
            .push(Message::tool_result(call_id, content, is_error));
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

    /// Estimate the token count of all messages using a cheap `chars/4` heuristic.
    /// No tokenizer dependency is required.
    pub fn estimated_tokens(&self) -> usize {
        self.messages
            .iter()
            .map(|m| {
                m.content
                    .iter()
                    .map(|b| match b {
                        ContentBlock::Text(t) => t.len(),
                        ContentBlock::Thinking { text, .. } => text.len(),
                        ContentBlock::RedactedThinking { data } => data.len(),
                        ContentBlock::ToolUse { name, input, .. } => {
                            name.len() + input.to_string().len()
                        }
                    })
                    .sum::<usize>()
            })
            .sum::<usize>()
            / 4
    }

    /// The Process Note marker prefix — user messages whose text starts with this
    /// are recognised as Process Note injections and are never compacted.
    pub const PROCESS_NOTE_PREFIX: &'static str = "## Process Note";

    /// Compact the transcript when estimated tokens exceed the soft budget.
    ///
    /// Compaction works on whole assistant→tool_result cycles and preserves the
    /// original message order:
    /// 1. If estimated tokens are ≤ `compaction_threshold`, return unchanged.
    /// 2. Split the transcript into ordered segments: each `assistant` message plus
    ///    every consecutive `tool_result` that follows it forms one cycle; any other
    ///    message (a user turn, an injected note) passes through in place.
    /// 3. The most recent `keep_recent_cycles` cycles are kept verbatim; every older
    ///    cycle is replaced, in place, by a single `user`-role synopsis message
    ///    (`[compacted: <id> → <N>B, <preview>…]`). Because a cycle is dropped as a
    ///    unit, the assistant's `tool_use` block and its matching `tool_result` are
    ///    always removed together, and any signed `Thinking`/`RedactedThinking`
    ///    blocks in a retained cycle are preserved unchanged.
    /// 4. User messages (including the injected working note) are never compacted.
    pub fn compact(&mut self, keep_recent_cycles: usize) {
        if self.estimated_tokens() <= self.compaction_threshold {
            return;
        }

        // Build a synopsis from the tool_result messages of a cycle.
        let cycle_synopsis = |msgs: &[Message]| -> String {
            let mut entries: Vec<String> = Vec::new();
            for msg in msgs {
                if msg.role != "tool_result" {
                    continue;
                }
                let call_id = msg.tool_call_id.as_deref().unwrap_or("?");
                let total_bytes: usize = msg
                    .content
                    .iter()
                    .filter_map(|b| {
                        if let ContentBlock::Text(t) = b {
                            Some(t.len())
                        } else {
                            None
                        }
                    })
                    .sum();
                let preview: String = msg
                    .content
                    .iter()
                    .filter_map(|b| {
                        if let ContentBlock::Text(t) = b {
                            Some(t.chars().take(120).collect::<String>())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                entries.push(format!("{call_id} → {total_bytes}B, {preview}"));
            }
            if entries.is_empty() {
                "[compacted: (no results)]".to_string()
            } else {
                format!("[compacted: {}]", entries.join(" | "))
            }
        };

        // 1. Parse into ordered segments (cycles and pass-through messages).
        enum Segment {
            PassThrough(Message),
            Cycle {
                assistant: Message,
                tool_results: Vec<Message>,
            },
        }
        let mut segments: Vec<Segment> = Vec::new();
        let mut i = 0;
        while i < self.messages.len() {
            if self.messages[i].role == "assistant" {
                let assistant = self.messages[i].clone();
                i += 1;
                let mut tool_results = Vec::new();
                while i < self.messages.len() && self.messages[i].role == "tool_result" {
                    tool_results.push(self.messages[i].clone());
                    i += 1;
                }
                segments.push(Segment::Cycle {
                    assistant,
                    tool_results,
                });
            } else {
                segments.push(Segment::PassThrough(self.messages[i].clone()));
                i += 1;
            }
        }

        // 2. The last `keep_recent_cycles` cycles are kept; earlier cycles are compacted.
        let total_cycles = segments
            .iter()
            .filter(|s| matches!(s, Segment::Cycle { .. }))
            .count();
        let keep_count = keep_recent_cycles.min(total_cycles);
        let compact_before = total_cycles - keep_count;

        // 3. Rebuild in original order.
        let mut new_messages: Vec<Message> = Vec::new();
        let mut cycle_idx = 0;
        for seg in segments {
            match seg {
                Segment::PassThrough(m) => new_messages.push(m),
                Segment::Cycle {
                    assistant,
                    tool_results,
                } => {
                    if cycle_idx < compact_before {
                        new_messages.push(Message::user(&cycle_synopsis(&tool_results)));
                    } else {
                        new_messages.push(assistant);
                        new_messages.extend(tool_results);
                    }
                    cycle_idx += 1;
                }
            }
        }

        self.messages = new_messages;
    }

    /// Remove any user message whose first text block starts with the given prefix.
    /// Used to refresh the Process Note injection in-place.
    pub fn remove_user_messages_starting_with(&mut self, prefix: &str) {
        self.messages.retain(|m| {
            if m.role != "user" {
                return true;
            }
            !m.content.iter().any(|b| match b {
                ContentBlock::Text(t) => t.starts_with(prefix),
                _ => false,
            })
        });
    }

    /// Check whether every `tool_use` id has a matching `tool_result` id and vice versa.
    /// Returns `true` when pairing holds.
    #[allow(dead_code)]
    pub fn check_pairing_invariant(&self) -> bool {
        let tool_use_ids: std::collections::BTreeSet<&str> = self
            .messages
            .iter()
            .filter(|m| m.role == "assistant")
            .flat_map(|m| m.content.iter())
            .filter_map(|b| {
                if let ContentBlock::ToolUse { id, .. } = b {
                    Some(id.as_str())
                } else {
                    None
                }
            })
            .collect();
        let tool_result_ids: std::collections::BTreeSet<&str> = self
            .messages
            .iter()
            .filter(|m| m.role == "tool_result")
            .filter_map(|m| m.tool_call_id.as_deref())
            .collect();
        tool_use_ids == tool_result_ids
    }

    /// Serialize to the Anthropic Messages API wire format.
    #[allow(dead_code)]
    pub fn to_anthropic_json(&self) -> Vec<Value> {
        self.messages
            .iter()
            .filter(|m| m.role != "system")
            .map(|m| {
                let mut obj = serde_json::Map::new();
                let role = if m.role == "tool_result" {
                    "user"
                } else {
                    m.role.as_str()
                };
                obj.insert("role".into(), Value::String(role.into()));

                if m.role == "tool_result" {
                    let mut content = Vec::new();
                    let text = m
                        .content
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::Text(t) => Some(t.as_str()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    content.push(serde_json::json!({
                        "type": "tool_result",
                        "tool_use_id": m.tool_call_id,
                        "content": text,
                        "is_error": m.is_error,
                    }));
                    obj.insert("content".into(), Value::Array(content));
                } else {
                    let blocks: Vec<Value> = m
                        .content
                        .iter()
                        .map(|b| match b {
                            ContentBlock::Text(t) => {
                                serde_json::json!({ "type": "text", "text": t })
                            }
                            ContentBlock::Thinking { text, signature } => serde_json::json!({
                                "type": "thinking", "thinking": text, "signature": signature,
                            }),
                            ContentBlock::RedactedThinking { data } => {
                                serde_json::json!({ "type": "redacted_thinking", "data": data })
                            }
                            ContentBlock::ToolUse { id, name, input } => serde_json::json!({
                                "type": "tool_use",
                                "id": id,
                                "name": name,
                                "input": input,
                            }),
                        })
                        .collect();
                    obj.insert("content".into(), Value::Array(blocks));
                }
                Value::Object(obj)
            })
            .collect()
    }

    /// Serialize to the OpenAI Chat Completions API wire format.
    #[allow(dead_code)]
    pub fn to_openai_json(&self) -> Vec<Value> {
        self.messages
            .iter()
            .map(|m| {
                let mut obj = serde_json::Map::new();
                let role = if m.role == "tool_result" {
                    "tool"
                } else {
                    m.role.as_str()
                };
                obj.insert("role".into(), Value::String(role.into()));

                match m.role.as_str() {
                    "assistant" => {
                        let text = m
                            .content
                            .iter()
                            .filter_map(|b| match b {
                                ContentBlock::Text(t) => Some(t.clone()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("");
                        if !text.is_empty() {
                            obj.insert("content".into(), Value::String(text));
                        }
                        let tool_calls: Vec<Value> = m
                            .content
                            .iter()
                            .filter_map(|b| match b {
                                ContentBlock::ToolUse { id, name, input } => {
                                    Some(serde_json::json!({
                                        "id": id,
                                        "type": "function",
                                        "function": {
                                            "name": name,
                                            "arguments": input.to_string(),
                                        }
                                    }))
                                }
                                _ => None,
                            })
                            .collect();
                        if !tool_calls.is_empty() {
                            obj.insert("tool_calls".into(), Value::Array(tool_calls));
                        }
                    }
                    "tool" => {
                        let text = m
                            .content
                            .iter()
                            .filter_map(|b| match b {
                                ContentBlock::Text(t) => Some(t.as_str()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        obj.insert("content".into(), Value::String(text));
                        obj.insert(
                            "tool_call_id".into(),
                            Value::String(m.tool_call_id.clone().unwrap_or_default()),
                        );
                    }
                    _ => {
                        let text = m
                            .content
                            .iter()
                            .filter_map(|b| match b {
                                ContentBlock::Text(t) => Some(t.as_str()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        obj.insert("content".into(), Value::String(text));
                    }
                }
                Value::Object(obj)
            })
            .collect()
    }

    /// Extract tool_use content blocks from the last assistant message.
    pub fn last_tool_calls(&self) -> Vec<(String, String, Value)> {
        self.messages
            .iter()
            .rev()
            .find(|m| m.role == "assistant")
            .map(|m| {
                m.content
                    .iter()
                    .filter_map(|b| match b {
                        ContentBlock::ToolUse { id, name, input } => {
                            Some((id.clone(), name.clone(), input.clone()))
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
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
        t.push_assistant(vec![ContentBlock::ToolUse {
            id: "tu_1".into(),
            name: "atom_query".into(),
            input: serde_json::json!({"kind": "files"}),
        }]);
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
        t.push_assistant(vec![ContentBlock::ToolUse {
            id: "call_1".into(),
            name: "atom_query".into(),
            input: serde_json::json!({"kind": "methods"}),
        }]);
        t.push_tool_result("call_1", r#"{"total":3}"#, false);

        let json = t.to_openai_json();
        assert_eq!(json.len(), 3);
        assert_eq!(json[1]["tool_calls"][0]["function"]["name"], "atom_query");
        assert_eq!(json[2]["role"], "tool");
    }

    // -----------------------------------------------------------------------
    // Compaction tests
    // -----------------------------------------------------------------------

    /// Helper: build a transcript with a leading user message and `n` cycles,
    /// each producing a tool_result of `result_bytes` length.
    fn build_transcript(cycles: usize, result_bytes: usize) -> Transcript {
        let mut t = Transcript::new();
        t.compaction_threshold = 100_000; // high so we manually trigger below
        t.push_user("Analyze this codebase for security issues.");
        for i in 0..cycles {
            t.push_assistant(vec![
                ContentBlock::Thinking {
                    text: format!("Let me think about cycle {i}…"),
                    signature: "sig".into(),
                },
                ContentBlock::ToolUse {
                    id: format!("tu_{i}"),
                    name: if i % 2 == 0 {
                        "atom_query".into()
                    } else {
                        "ripgrep".into()
                    },
                    input: serde_json::json!({"kind": "files"}),
                },
            ]);
            let body = "x".repeat(result_bytes);
            t.push_tool_result(&format!("tu_{i}"), &body, false);
        }
        t
    }

    #[test]
    fn transcript_under_budget_is_unchanged() {
        let mut t = build_transcript(3, 100);
        t.compaction_threshold = 100_000;
        let before = t.messages.len();
        t.compact(1);
        assert_eq!(
            t.messages.len(),
            before,
            "under-budget transcript must not be changed"
        );
        // First user message unchanged.
        assert_eq!(
            t.messages[0].content[0],
            ContentBlock::Text("Analyze this codebase for security issues.".into())
        );
    }

    #[test]
    fn compaction_preserves_recent_cycles_verbatim() {
        let mut t = build_transcript(5, 2000);
        t.compaction_threshold = 0; // force compaction
        t.compact(2);

        // There should be: 1 initial user + (5-2)=3 compacted synopses + 2 recent cycles
        // Each recent cycle = 1 assistant + 1 tool_result = 2 messages
        let expected_len = 1 + 3 + (2 * 2);
        assert_eq!(
            t.messages.len(),
            expected_len,
            "wrong message count after compact"
        );

        // The recent cycles should be verbatim (assistant with Thinking + ToolUse, then tool_result).
        let last_assistant = &t.messages[t.messages.len() - 4]; // second-to-last cycle assistant
        let last_tool_use = last_assistant
            .content
            .iter()
            .find(|b| matches!(b, ContentBlock::ToolUse { .. }))
            .unwrap();
        assert_eq!(
            last_tool_use,
            &ContentBlock::ToolUse {
                id: "tu_3".into(),
                name: "ripgrep".into(),
                input: serde_json::json!({"kind": "files"}),
            },
            "recent cycle tool_use should be intact"
        );
    }

    #[test]
    fn old_cycles_replaced_by_synopsis() {
        let mut t = build_transcript(4, 5000);
        t.compaction_threshold = 0;
        t.compact(1);

        // After the initial user message and 3 compacted cycles, the 4th message
        // should be a synopsis user message.
        let synopsis_msg = &t.messages[1];
        assert_eq!(synopsis_msg.role, "user");
        let text = match &synopsis_msg.content[0] {
            ContentBlock::Text(t) => t.as_str(),
            _ => "wrong block type",
        };
        assert!(
            text.starts_with("[compacted:"),
            "old cycle should be a compacted synopsis, got: {text}"
        );
        assert!(
            text.contains("tu_0"),
            "synopsis should include tool call id"
        );
    }

    #[test]
    fn compaction_pairing_invariant_holds() {
        let mut t = build_transcript(6, 8000);
        t.compaction_threshold = 0;
        t.compact(2);

        assert!(
            t.check_pairing_invariant(),
            "every tool_use id must match a tool_result id after compaction"
        );
    }

    #[test]
    fn process_note_survives_compaction() {
        let mut t = Transcript::new();
        t.compaction_threshold = 0;
        t.push_user("Analyze this.");
        // The Process Note is a user message whose text starts with the prefix.
        t.push_user("## Process Note\n**Confirmed:**\n  - SQL injection in search\n**Next steps:**\n  - Verify auth check");
        t.push_assistant(vec![ContentBlock::ToolUse {
            id: "tu_0".into(),
            name: "atom_query".into(),
            input: serde_json::json!({"kind": "files"}),
        }]);
        t.push_tool_result("tu_0", "x".repeat(5000).as_str(), false);

        t.compact(1);

        // The Process Note user message should still be present.
        let process_note_found = t.messages.iter().any(|m| {
            m.content.iter().any(|b| match b {
                ContentBlock::Text(text) => text.contains("Process Note"),
                _ => false,
            })
        });
        assert!(process_note_found, "Process Note should survive compaction");
    }

    #[test]
    fn compaction_preserves_position_of_mid_transcript_user_message() {
        // A follow-up user turn (or an injected note) that sits between cycles must
        // keep its position after compaction — it must not be reordered ahead of the
        // earlier cycles it followed.
        let mut t = Transcript::new();
        t.compaction_threshold = 0; // force compaction
        t.push_user("first question");
        t.push_assistant(vec![ContentBlock::ToolUse {
            id: "tu_0".into(),
            name: "atom_query".into(),
            input: serde_json::json!({}),
        }]);
        t.push_tool_result("tu_0", &"x".repeat(3000), false);
        t.push_user("SECOND question"); // mid-transcript user turn
        t.push_assistant(vec![ContentBlock::ToolUse {
            id: "tu_1".into(),
            name: "ripgrep".into(),
            input: serde_json::json!({}),
        }]);
        t.push_tool_result("tu_1", &"y".repeat(3000), false);

        t.compact(1); // keep only the most recent cycle verbatim

        // The second question must still appear AFTER the first cycle's synopsis,
        // not hoisted to the front.
        let text_at = |idx: usize| -> String {
            match &t.messages[idx].content[0] {
                ContentBlock::Text(s) => s.clone(),
                _ => String::new(),
            }
        };
        assert_eq!(text_at(0), "first question");
        assert!(
            text_at(1).starts_with("[compacted:"),
            "first cycle should be compacted"
        );
        assert_eq!(
            text_at(2),
            "SECOND question",
            "mid-transcript user turn must keep its position"
        );
        assert!(t.check_pairing_invariant());
    }

    #[test]
    fn compact_empty_transcript_is_noop() {
        let mut t = Transcript::new();
        t.compaction_threshold = 0;
        t.compact(1);
        assert!(t.messages.is_empty());
        assert!(t.check_pairing_invariant());
    }

    #[test]
    fn single_cycle_without_compact_is_unchanged() {
        let mut t = Transcript::new();
        t.compaction_threshold = 100_000;
        t.push_user("hello");
        t.push_assistant(vec![ContentBlock::ToolUse {
            id: "t1".into(),
            name: "atom_query".into(),
            input: serde_json::json!({}),
        }]);
        t.push_tool_result("t1", "ok", false);
        let before_len = t.messages.len();
        t.compact(1);
        assert_eq!(t.messages.len(), before_len);
        assert!(t.check_pairing_invariant());
    }

    #[test]
    fn estimated_tokens_returns_reasonable_value() {
        let mut t = Transcript::new();
        t.push_user("Hello world"); // 11 chars / 4 ≈ 2 tokens
        let est = t.estimated_tokens();
        assert!(est < 5, "short text should estimate <5 tokens, got {est}");

        // Big text should estimate proportionally.
        t.push_user(&"x".repeat(4000));
        let est2 = t.estimated_tokens();
        assert!(
            est2 > 900,
            "~4000 chars should estimate ~1000 tokens, got {est2}"
        );
    }

    #[test]
    fn pairing_invariant_false_when_unmatched() {
        let mut t = Transcript::new();
        t.push_user("query");
        t.push_assistant(vec![ContentBlock::ToolUse {
            id: "tu_1".into(),
            name: "atom_query".into(),
            input: serde_json::json!({}),
        }]);
        // No tool_result for tu_1.
        assert!(!t.check_pairing_invariant());
    }

    #[test]
    fn pairing_invariant_true_when_matched() {
        let mut t = Transcript::new();
        t.push_user("query");
        t.push_assistant(vec![ContentBlock::ToolUse {
            id: "tu_1".into(),
            name: "atom_query".into(),
            input: serde_json::json!({}),
        }]);
        t.push_tool_result("tu_1", "result", false);
        assert!(t.check_pairing_invariant());
    }
}
