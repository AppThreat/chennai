//! Serde structs mirroring the engine's NDJSON protocol responses.

use serde::Deserialize;

/// A clickable starter question shown in the empty Output panel.
#[derive(Debug, Clone)]
pub struct StarterQuestion {
    /// Short display label (shown to the user).
    pub label: String,
    /// Full command text sent to the agent/REPL when clicked.
    pub command: String,
}

/// A single row of the atom summary table.
#[derive(Debug, Clone, Deserialize)]
pub struct SummaryRow {
    pub label: String,
    pub count: i64,
}

/// Payload of a `summary` response.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Summary {
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub rows: Vec<SummaryRow>,
}

/// Payload of an `open` response. Fields are validated on deserialization even though the TUI
/// currently surfaces the atom metadata through the subsequent `summary` response.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Default)]
pub struct OpenInfo {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub language: String,
}

/// A single styled cell of a query result. `k` (kind) drives column styling in the TUI.
#[derive(Debug, Clone, Deserialize)]
pub struct Cell {
    pub v: String,
    #[serde(default)]
    pub k: String,
}

/// A single step in a data flow, as emitted by the engine's `flows` command. `kind` is one of
/// `source` / `propagation` / `sanitizer` / `external` / `sink` and drives icon + colour.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FlowStep {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub label: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: i64,
    /// The tainted/tracked symbol, highlighted in the detail view.
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A single data flow: an ordered list of steps from a source to a sink.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Flow {
    #[serde(default)]
    #[allow(dead_code)]
    pub id: i64,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub sink: String,
    #[serde(default, rename = "sourceTags")]
    pub source_tags: Vec<String>,
    #[serde(default, rename = "sinkTags")]
    pub sink_tags: Vec<String>,
    /// Any step is a validation/sanitisation mitigation.
    #[serde(default)]
    pub mitigated: bool,
    /// Any step carries a package-url tag (flow attributable to a known dependency).
    #[serde(default, rename = "hasPurl")]
    pub has_purl: bool,
    #[serde(default)]
    pub length: i64,
    /// Set when this flow is a sub-path of a longer flow (the id of that flow).
    #[serde(default, rename = "subFlowOf")]
    pub sub_flow_of: Option<i64>,
    #[serde(default)]
    pub steps: Vec<FlowStep>,
}

/// Payload of a `flows` response: a set of data flows.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FlowSet {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    #[allow(dead_code)]
    pub shown: i64,
    #[serde(default)]
    #[allow(dead_code)]
    pub offset: i64,
    #[serde(default)]
    pub flows: Vec<Flow>,
}

/// Payload of a `complete` response: REPL autocomplete candidates.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Completions {
    #[serde(default)]
    pub completions: Vec<String>,
}

/// A single property shown in the node detail panel.
#[derive(Debug, Clone, Deserialize)]
pub struct Prop {
    pub label: String,
    pub value: String,
}

/// A node in the call tree returned by the engine for a method detail.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CallTreeNode {
    #[serde(default)]
    pub label: String,
    /// 1-based depth from the root method (root itself is depth 0, not included).
    #[serde(default)]
    pub depth: usize,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: String,
}

/// Payload of a `detail` response: properties + child table/calltree + optional source code.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NodeDetail {
    #[serde(default)]
    pub props: Vec<Prop>,
    #[serde(default, rename = "childTitle")]
    pub child_title: String,
    #[serde(default, rename = "childColumns")]
    pub child_columns: Vec<String>,
    #[serde(default, rename = "childRows")]
    pub child_rows: Vec<Vec<Cell>>,
    /// Callee call-graph tree (flat list with depth), present only for method details.
    #[serde(default, rename = "callTree")]
    pub call_tree: Vec<CallTreeNode>,
    #[serde(default)]
    pub code: Option<String>,
}

/// Payload of a `query` response: a generic, paged table.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ResultTable {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub columns: Vec<String>,
    #[serde(default)]
    pub rows: Vec<Vec<Cell>>,
    #[serde(default)]
    pub total: i64,
    /// Window offset reported by the engine; retained for future incremental paging.
    #[serde(default)]
    #[allow(dead_code)]
    pub offset: i64,
}
