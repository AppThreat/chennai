//! Render engine JSON responses as compact Markdown for agent tool results.
//!
//! LLMs parse Markdown tables and lists far better than the double-escaped JSON
//! that `to_string_pretty` produces inside a tool-result string, and Markdown
//! spends fewer tokens (column names once in the header instead of on every
//! row, no `\"` quoting). We render the tabular/structured engine shapes as
//! Markdown and fall back to JSON for anything we don't model.

use serde_json::Value;

/// Convert an engine response into Markdown. `cmd` is the engine command
/// (`summary`, `query`, `eval`, `algo`, `flows`, `detail`). Returns `None` when
/// the shape isn't one we render — the caller then falls back to pretty JSON.
pub fn render_engine_result(cmd: &str, data: &Value) -> Option<String> {
    match cmd {
        "summary" => render_summary(data),
        "query" | "eval" | "algo" => render_table(data),
        "flows" => render_flows(data),
        "detail" => render_detail(data),
        _ => None,
    }
}

/// Extract the display text of a query cell. Engine cells are `{"v": "...",
/// "k": "..."}` objects (`k` drives TUI styling and is irrelevant to the LLM);
/// fall back to the raw value for plain scalars.
fn cell_text(v: &Value) -> String {
    match v {
        Value::Object(o) => o.get("v").map(scalar_text).unwrap_or_default(),
        other => scalar_text(other),
    }
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Escape a value for use inside a Markdown table cell: pipes would break the
/// column structure and newlines would break the row, so neutralise both.
fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ").replace('\r', "")
}

/// Build a GitHub-flavoured Markdown table from string column headers and rows
/// of pre-stringified cells. Cells are not padded — alignment whitespace would
/// only waste tokens for the model.
fn markdown_table(columns: &[String], rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    out.push_str("| ");
    out.push_str(&columns.iter().map(|c| md_cell(c)).collect::<Vec<_>>().join(" | "));
    out.push_str(" |\n|");
    for _ in columns {
        out.push_str(" --- |");
    }
    out.push('\n');
    for row in rows {
        out.push_str("| ");
        out.push_str(&row.iter().map(|c| md_cell(c)).collect::<Vec<_>>().join(" | "));
        out.push_str(" |\n");
    }
    out
}

fn render_summary(data: &Value) -> Option<String> {
    let rows = data.get("rows")?.as_array()?;
    let mut out = String::new();
    let lang = data.get("language").and_then(Value::as_str).unwrap_or("");
    let ver = data.get("version").and_then(Value::as_str).unwrap_or("");
    if !lang.is_empty() || !ver.is_empty() {
        out.push_str(&format!("**Language:** {lang}  **Version:** {ver}\n\n"));
    }
    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                scalar_text(r.get("label").unwrap_or(&Value::Null)),
                scalar_text(r.get("count").unwrap_or(&Value::Null)),
            ]
        })
        .collect();
    out.push_str(&markdown_table(
        &["Metric".to_string(), "Count".to_string()],
        &table_rows,
    ));
    Some(out)
}

fn render_table(data: &Value) -> Option<String> {
    let columns: Vec<String> = data
        .get("columns")?
        .as_array()?
        .iter()
        .map(scalar_text)
        .collect();
    if columns.is_empty() {
        return None;
    }
    let rows = data.get("rows")?.as_array()?;
    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            row.as_array()
                .map(|cells| cells.iter().map(cell_text).collect())
                .unwrap_or_default()
        })
        .collect();

    let mut out = String::new();
    let title = data.get("title").and_then(Value::as_str).unwrap_or("");
    if !title.is_empty() {
        out.push_str(&format!("**{title}**\n\n"));
    }
    if table_rows.is_empty() {
        out.push_str("(no rows)\n");
    } else {
        out.push_str(&markdown_table(&columns, &table_rows));
    }
    let total = data.get("total").and_then(Value::as_i64).unwrap_or(table_rows.len() as i64);
    if total > table_rows.len() as i64 {
        out.push_str(&format!(
            "\n_Showing {} of {} row(s). Use offset/limit to page._\n",
            table_rows.len(),
            total
        ));
    }
    Some(out)
}

fn render_flows(data: &Value) -> Option<String> {
    let flows = data.get("flows")?.as_array()?;
    let mut out = String::new();
    let title = data.get("title").and_then(Value::as_str).unwrap_or("Data flows");
    let total = data.get("total").and_then(Value::as_i64).unwrap_or(flows.len() as i64);
    out.push_str(&format!("**{title}** — {} flow(s) shown of {total}\n", flows.len()));
    if flows.is_empty() {
        return Some(out);
    }

    for (i, flow) in flows.iter().enumerate() {
        let source = flow.get("source").and_then(Value::as_str).unwrap_or("");
        let sink = flow.get("sink").and_then(Value::as_str).unwrap_or("");
        out.push_str(&format!("\n### Flow {}: {} → {}\n", i + 1, source, sink));

        let mut tags = Vec::new();
        if flow.get("mitigated").and_then(Value::as_bool).unwrap_or(false) {
            tags.push("mitigated/sanitized");
        }
        if flow.get("hasPurl").and_then(Value::as_bool).unwrap_or(false) {
            tags.push("attributable-to-dependency");
        }
        if !tags.is_empty() {
            out.push_str(&format!("_{}_\n", tags.join(", ")));
        }

        let steps = flow.get("steps").and_then(Value::as_array).cloned().unwrap_or_default();
        let step_rows: Vec<Vec<String>> = steps
            .iter()
            .map(|s| {
                let file = s.get("file").and_then(Value::as_str).unwrap_or("");
                let line = s.get("line").and_then(Value::as_i64).unwrap_or(0);
                let loc = if file.is_empty() { String::new() } else { format!("{file}:{line}") };
                vec![
                    scalar_text(s.get("kind").unwrap_or(&Value::Null)),
                    scalar_text(s.get("method").unwrap_or(&Value::Null)),
                    loc,
                    scalar_text(s.get("symbol").unwrap_or(&Value::Null)),
                    scalar_text(s.get("code").unwrap_or(&Value::Null)),
                ]
            })
            .collect();
        out.push_str(&markdown_table(
            &[
                "kind".to_string(),
                "method".to_string(),
                "location".to_string(),
                "symbol".to_string(),
                "code".to_string(),
            ],
            &step_rows,
        ));
    }
    Some(out)
}

fn render_detail(data: &Value) -> Option<String> {
    // Only treat this as a detail payload if it has at least one of the known
    // detail sections; otherwise let the caller fall back to JSON.
    if !["props", "childRows", "callTree", "code"].iter().any(|k| data.get(k).is_some()) {
        return None;
    }
    let mut out = String::new();

    if let Some(props) = data.get("props").and_then(Value::as_array) {
        for p in props {
            let label = p.get("label").and_then(Value::as_str).unwrap_or("");
            let value = p.get("value").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("- **{label}:** {value}\n"));
        }
    }

    let child_cols: Vec<String> = data
        .get("childColumns")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(scalar_text).collect())
        .unwrap_or_default();
    if let Some(child_rows) = data.get("childRows").and_then(Value::as_array)
        && !child_cols.is_empty()
        && !child_rows.is_empty()
    {
        let title = data.get("childTitle").and_then(Value::as_str).unwrap_or("");
        out.push_str(&format!("\n**{}**\n\n", if title.is_empty() { "Children" } else { title }));
        let rows: Vec<Vec<String>> = child_rows
            .iter()
            .map(|row| {
                row.as_array()
                    .map(|cells| cells.iter().map(cell_text).collect())
                    .unwrap_or_default()
            })
            .collect();
        out.push_str(&markdown_table(&child_cols, &rows));
    }

    if let Some(tree) = data.get("callTree").and_then(Value::as_array)
        && !tree.is_empty()
    {
        out.push_str("\n**Call tree**\n\n");
        for node in tree {
            let depth = node.get("depth").and_then(Value::as_u64).unwrap_or(0) as usize;
            let label = node.get("label").and_then(Value::as_str).unwrap_or("");
            let file = node.get("file").and_then(Value::as_str).unwrap_or("");
            let line = node.get("line").and_then(Value::as_str).unwrap_or("");
            let loc = if file.is_empty() { String::new() } else { format!("  ({file}:{line})") };
            out.push_str(&format!("{}- {label}{loc}\n", "  ".repeat(depth.saturating_sub(1))));
        }
    }

    if let Some(code) = data.get("code").and_then(Value::as_str)
        && !code.is_empty()
    {
        out.push_str("\n```\n");
        out.push_str(code);
        if !code.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("```\n");
    }

    if out.trim().is_empty() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn table_renders_cells_without_k() {
        let data = json!({
            "title": "Methods",
            "columns": ["name", "file"],
            "rows": [
                [{"v": "main", "k": "name"}, {"v": "a.rs", "k": "path"}],
                [{"v": "run", "k": "name"}, {"v": "b.rs", "k": "path"}]
            ],
            "total": 5
        });
        let md = render_table(&data).unwrap();
        assert!(md.contains("| name | file |"));
        assert!(md.contains("| main | a.rs |"));
        assert!(md.contains("Showing 2 of 5"));
        assert!(!md.contains("\"k\""));
    }

    #[test]
    fn table_escapes_pipes_and_newlines() {
        let data = json!({
            "columns": ["code"],
            "rows": [[{"v": "a | b\nc"}]],
            "total": 1
        });
        let md = render_table(&data).unwrap();
        assert!(md.contains("a \\| b c"));
    }

    #[test]
    fn table_without_columns_falls_back() {
        assert!(render_table(&json!({"rows": []})).is_none());
    }

    #[test]
    fn flows_group_per_path() {
        let data = json!({
            "title": "Data flows",
            "total": 1,
            "flows": [{
                "source": "req",
                "sink": "exec",
                "mitigated": false,
                "steps": [
                    {"kind": "source", "method": "handle", "file": "h.rs", "line": 3, "symbol": "x", "code": "x = req()"},
                    {"kind": "sink", "method": "run", "file": "r.rs", "line": 9, "symbol": "x", "code": "exec(x)"}
                ]
            }]
        });
        let md = render_flows(&data).unwrap();
        assert!(md.contains("### Flow 1: req → exec"));
        assert!(md.contains("h.rs:3"));
        assert!(md.contains("| sink | run | r.rs:9 |"));
    }

    #[test]
    fn detail_renders_props_and_code() {
        let data = json!({
            "props": [{"label": "Name", "value": "main"}],
            "code": "fn main() {}"
        });
        let md = render_detail(&data).unwrap();
        assert!(md.contains("- **Name:** main"));
        assert!(md.contains("```\nfn main() {}\n```"));
    }

    #[test]
    fn unknown_cmd_falls_back() {
        assert!(render_engine_result("open", &json!({})).is_none());
    }
}
