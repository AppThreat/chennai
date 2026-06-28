//! Rendering: three stacked panels (Summary, REPL, Output) plus a status bar.

pub mod theme;

use crate::app::{AgentEntry, App, Panel};
use crate::model::Cell as ModelCell;
use theme::Theme;

use ratatui::layout::{Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Table,
};
use ratatui::Frame;

const REPL_PROMPT: &str = "chennai> ";

pub fn render(frame: &mut Frame, app: &mut App, theme: &Theme) {
    // Once a result is showing, the Summary panel collapses to a single line to give the result
    // more room; it expands again whenever it has focus (Tab or a click lands on it).
    let summary_collapsed =
        app.focus != Panel::Summary && (app.output.is_some() || app.flows.is_some());
    let summary_constraint = if summary_collapsed {
        Constraint::Length(1)
    } else {
        Constraint::Percentage(42)
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            summary_constraint,    // summary (collapsible)
            Constraint::Length(7), // repl
            Constraint::Min(6),    // output
            Constraint::Length(1), // status
        ])
        .split(frame.area());

    app.panel_rects.clear();
    app.panel_rects.push((Panel::Summary, chunks[0]));
    app.panel_rects.push((Panel::Repl, chunks[1]));
    app.panel_rects.push((Panel::Output, chunks[2]));

    if summary_collapsed {
        render_summary_collapsed(frame, app, theme, chunks[0]);
    } else {
        render_summary(frame, app, theme, chunks[0]);
    }
    render_repl(frame, app, theme, chunks[1]);
    render_output(frame, app, theme, chunks[2]);
    render_status(frame, app, theme, chunks[3]);
    // Drawn last so it overlays the panels below the REPL input.
    render_completion_popup(frame, app, theme);
}

fn panel_block<'a>(title: String, focused: bool, theme: &Theme) -> Block<'a> {
    let border = if focused { theme.accent } else { theme.muted };
    Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(border))
        .title_style(
            Style::default()
                .fg(if focused { theme.accent } else { theme.header })
                .add_modifier(Modifier::BOLD),
        )
}

/// Render a vertical scrollbar on the right edge of `area` when content overflows.
fn render_scrollbar(frame: &mut Frame, area: Rect, theme: &Theme, len: usize, pos: usize, viewport: usize) {
    if len <= viewport {
        return;
    }
    let mut state = ScrollbarState::new(len).position(pos).viewport_content_length(viewport);
    let bar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .style(Style::default().fg(theme.muted));
    frame.render_stateful_widget(bar, area.inner(Margin { vertical: 1, horizontal: 0 }), &mut state);
}

fn header_row<'a>(cols: &[&str], theme: &Theme) -> Row<'a> {
    Row::new(
        cols.iter()
            .map(|c| Cell::from(c.to_string()).style(Style::default().fg(theme.header).add_modifier(Modifier::BOLD)))
            .collect::<Vec<_>>(),
    )
}

fn row_style(selected: bool, focused: bool, theme: &Theme) -> Style {
    if selected {
        let bg = if focused { theme.selection_bg } else { theme.muted_selection_bg };
        Style::default().bg(bg).fg(theme.fg)
    } else {
        Style::default().fg(theme.fg)
    }
}

fn render_summary(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    let focused = app.focus == Panel::Summary;
    let block = panel_block(
        format!(" Atom Summary — {} {} ({}) ", app.summary.language, app.summary.version, app.atom_path),
        focused,
        theme,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let viewport = inner.height.saturating_sub(1) as usize; // minus header
    app.summary_state.visible = viewport;
    // Region occupied by data rows (below the header) — used for mouse hit-testing.
    app.summary_rows_area = Some(Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: viewport as u16,
    });

    let len = app.summary.rows.len();
    let scroll = app.summary_state.scroll;
    let end = (scroll + viewport).min(len);

    let rows: Vec<Row> = app.summary.rows[scroll..end]
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let sel = scroll + i == app.summary_state.selected;
            Row::new(vec![
                Cell::from(r.label.clone()),
                Cell::from(Span::styled(r.count.to_string(), Style::default().fg(theme.accent))),
            ])
            .style(row_style(sel, focused, theme))
        })
        .collect();

    let table = Table::new(rows, [Constraint::Fill(3), Constraint::Fill(1)])
        .header(header_row(&["Node Type", "Count"], theme))
        .column_spacing(2);
    frame.render_widget(table, inner);
    render_scrollbar(frame, area, theme, len, scroll, viewport);
}

/// One-line summary shown when the panel is collapsed: language + a few top counts + a hint.
fn render_summary_collapsed(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    app.summary_rows_area = None; // no rows to hit-test while collapsed
    let counts = app
        .summary
        .rows
        .iter()
        .take(4)
        .map(|r| format!("{} {}", r.label, r.count))
        .collect::<Vec<_>>()
        .join(" · ");
    let line = Line::from(vec![
        Span::styled("▸ Atom Summary ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("— {} {} ", app.summary.language, app.summary.version),
            Style::default().fg(theme.header),
        ),
        Span::styled(counts, Style::default().fg(theme.fg)),
        Span::styled("  (Tab/click to expand)", Style::default().fg(theme.muted)),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_repl(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    let focused = app.focus == Panel::Repl;
    let title = if app.agent_enabled {
        " Ask agent (Enter to ask, ↑/↓ history) ".to_string()
    } else {
        " REPL (Enter to run, ↑/↓ history) ".to_string()
    };
    let block = panel_block(title, focused, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 {
        return;
    }

    let input_y = inner.y + inner.height - 1;
    let hist_h = (inner.height - 1) as usize;

    // Scrollback: show the most recent `hist_h` executed commands.
    let entries = &app.repl.entries;
    let start = entries.len().saturating_sub(hist_h);
    let lines: Vec<Line> = entries[start..]
        .iter()
        .map(|e| {
            let status_color = if e.ok { theme.num } else { theme.error };
            Line::from(vec![
                Span::styled(REPL_PROMPT, Style::default().fg(theme.muted)),
                Span::styled(e.input.clone(), Style::default().fg(theme.accent)),
                Span::raw("  "),
                Span::styled(e.status.clone(), Style::default().fg(status_color)),
            ])
        })
        .collect();
    let hist = Paragraph::new(lines);
    frame.render_widget(
        hist,
        Rect { x: inner.x, y: inner.y, width: inner.width, height: hist_h as u16 },
    );

    // Input line.
    let text = app.repl.text();
    let input = Paragraph::new(Line::from(vec![
        Span::styled(REPL_PROMPT, Style::default().fg(theme.header).add_modifier(Modifier::BOLD)),
        Span::styled(text, Style::default().fg(theme.fg)),
    ]));
    frame.render_widget(input, Rect { x: inner.x, y: input_y, width: inner.width, height: 1 });

    let caret_x = inner.x + REPL_PROMPT.chars().count() as u16 + app.repl.cursor() as u16;
    app.repl_caret = Some((caret_x.min(inner.x + inner.width.saturating_sub(1)), input_y));
    if focused && app.repl.completion.is_none()
        && caret_x < inner.x + inner.width {
            frame.set_cursor_position((caret_x, input_y));
        }
}

/// Render the autocomplete popup anchored under the REPL caret, when open.
fn render_completion_popup(frame: &mut Frame, app: &App, theme: &Theme) {
    let Some(comp) = app.repl.completion.as_ref() else {
        return;
    };
    let Some((cx, cy)) = app.repl_caret else {
        return;
    };
    let area = frame.area();

    // Popup dimensions, clamped to the screen.
    let max_items = 8usize;
    let visible = comp.items.len().min(max_items);
    let width = comp
        .items
        .iter()
        .map(|s| s.chars().count())
        .max()
        .unwrap_or(8)
        .clamp(8, 40) as u16
        + 2;
    let height = visible as u16 + 2;

    // Prefer below the caret; flip above if there is not enough room.
    let x = cx.min(area.width.saturating_sub(width));
    let y = if cy + 1 + height <= area.height {
        cy + 1
    } else {
        cy.saturating_sub(height)
    };
    let popup = Rect { x, y, width, height };

    // Scroll the candidate window to keep the selection visible.
    let scroll = comp.selected.saturating_sub(visible.saturating_sub(1));
    let lines: Vec<Line> = comp.items[scroll..scroll + visible]
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let sel = scroll + i == comp.selected;
            let style = if sel {
                Style::default().bg(theme.selection_bg).fg(theme.fg).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.code)
            };
            Line::from(Span::styled(item.clone(), style))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.accent))
        .title(format!(" {} ", comp.items.len()))
        .title_style(Style::default().fg(theme.muted));
    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(lines).block(block), popup);
}

fn style_for_kind(kind: &str, theme: &Theme) -> Style {
    match kind {
        "name" => Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        "code" => Style::default().fg(theme.code),
        "path" => Style::default().fg(theme.link).add_modifier(Modifier::UNDERLINED),
        "num" => Style::default().fg(theme.num),
        _ => Style::default().fg(theme.fg),
    }
}

fn column_weight(name: &str) -> u16 {
    match name {
        "Code" | "Full Name" | "Symbol" | "Imported Entity" => 4,
        "File" | "Name" | "Value" => 2,
        "Line Count" | "Methods" | "Size" | "Count" => 1,
        _ => 2,
    }
}

fn render_output(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    let focused = app.focus == Panel::Output;
    app.table_header_cells.clear();

    // Agent transcript view takes priority when agent is or was active.
    if app.agent_active || (!app.agent_transcript.is_empty() && app.output.is_none() && app.flows.is_none()) {
        render_agent_transcript(frame, app, theme, area, focused);
        return;
    }

    // A flow result takes over the Output panel as a master/detail view.
    if app.flows.is_some() {
        render_flows(frame, app, theme, area, focused);
        return;
    }

    // When a node detail panel is open, split horizontally 60/40.
    if app.detail.is_some() {
        let halves = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);
        render_output_table(frame, app, theme, halves[0]);
        render_node_detail(frame, app, theme, halves[1]);
        return;
    }

    render_output_table(frame, app, theme, area);
}

fn render_output_table(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    let focused = app.focus == Panel::Output && !app.detail_focused;

    // Title includes the live filter (with a caret while editing) and the visible/total counts.
    let title = match &app.output {
        Some(t) => {
            let filter = if app.table_filter_edit {
                format!("  /{}_", app.table_filter)
            } else if !app.table_filter.is_empty() {
                format!("  /{}", app.table_filter)
            } else {
                String::new()
            };
            format!(
                " Output — {} ({}/{}){} ",
                t.title,
                app.table_visible.len(),
                t.rows.len(),
                filter
            )
        }
        None => " Output (run a command) ".to_string(),
    };
    let block = panel_block(title, focused, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(table) = app.output.as_ref() else {
        let hint = Paragraph::new(vec![
            Line::from(Span::styled(
                "Select a Summary row (Enter / double-click) or type a query in the REPL.",
                Style::default().fg(theme.muted),
            )),
            Line::from(Span::styled(
                "Press r for data flows · / to filter · 1-9 to sort by column.",
                Style::default().fg(theme.muted),
            )),
        ]);
        frame.render_widget(hint, inner);
        return;
    };

    let viewport = inner.height.saturating_sub(1) as usize; // minus header
    app.output_state.visible = viewport;
    let len = app.table_visible.len();
    let scroll = app.output_state.scroll;
    let end = (scroll + viewport).min(len);

    // Header labels carry a sort arrow on the active sort column.
    let col_names: Vec<String> = table
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| match app.table_sort {
            Some((sc, asc)) if sc == i => format!("{c} {}", if asc { "▲" } else { "▼" }),
            _ => c.clone(),
        })
        .collect();
    let col_refs: Vec<&str> = col_names.iter().map(String::as_str).collect();
    let constraints: Vec<Constraint> =
        table.columns.iter().map(|c| Constraint::Fill(column_weight(c))).collect();

    // Mirror the Table's column layout so header clicks can be mapped to a column for sorting.
    let col_rects = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints.clone())
        .spacing(1)
        .split(inner);
    app.table_header_cells = col_rects
        .iter()
        .map(|r| Rect { x: r.x, y: inner.y, width: r.width, height: 1 })
        .collect();

    let rows: Vec<Row> = app.table_visible[scroll..end]
        .iter()
        .enumerate()
        .map(|(i, &row_idx)| {
            let sel = scroll + i == app.output_state.selected;
            let cs: Vec<Cell> = table.rows[row_idx]
                .iter()
                .map(|cell: &ModelCell| {
                    Cell::from(Span::styled(cell.v.clone(), style_for_kind(&cell.k, theme)))
                })
                .collect();
            Row::new(cs).style(row_style(sel, focused, theme))
        })
        .collect();

    let widget = Table::new(rows, constraints)
        .header(header_row(&col_refs, theme))
        .column_spacing(1);
    frame.render_widget(widget, inner);
    render_scrollbar(frame, area, theme, len, scroll, viewport);
}

fn render_node_detail(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    let focused = app.focus == Panel::Output && app.detail_focused;
    let detail = match app.detail.as_ref() {
        Some(d) => d.clone(),
        None => return,
    };

    let title = if detail.child_title.is_empty() {
        " Detail ".to_string()
    } else {
        format!(" Detail — {} ", detail.child_title)
    };
    let block = panel_block(title, focused, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let props_height = (detail.props.len() as u16 + 1).min(inner.height / 3);
    let has_code = detail.code.is_some();
    let constraints = if has_code {
        vec![
            Constraint::Length(props_height),
            Constraint::Percentage(40),
            Constraint::Min(3),
        ]
    } else {
        vec![
            Constraint::Length(props_height),
            Constraint::Min(3),
        ]
    };
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let prop_lines: Vec<Line> = detail.props.iter().map(|p| {
        Line::from(vec![
            Span::styled(format!("{}: ", p.label), Style::default().fg(theme.muted)),
            Span::styled(p.value.clone(), Style::default().fg(theme.fg)),
        ])
    }).collect();
    frame.render_widget(Paragraph::new(prop_lines), sections[0]);

    let child_area = sections[1];
    app.detail_child_area = Some(child_area); // for mouse hit-testing
    let child_rows_count = detail.child_rows.len();
    let child_viewport = child_area.height.saturating_sub(1) as usize; // minus header
    app.detail_child_visible = child_viewport;
    let child_scroll = if child_rows_count > 0 {
        app.detail_child_scroll.min(child_rows_count - 1)
    } else { 0 };
    app.detail_child_scroll = child_scroll;
    let end = (child_scroll + child_viewport).min(child_rows_count);

    let has_call_tree = !detail.call_tree.is_empty();
    if has_call_tree {
        // Render call-graph tree instead of a flat table.
        let tree_nodes = &detail.call_tree;
        let tree_total = tree_nodes.len();
        let tree_scroll = if tree_total > 0 {
            app.detail_child_scroll.min(tree_total - 1)
        } else { 0 };
        app.detail_child_scroll = tree_scroll;
        let tree_end = (tree_scroll + child_viewport).min(tree_total);

        let tree_lines: Vec<Line> = if tree_scroll < tree_end {
            tree_nodes[tree_scroll..tree_end].iter().map(|node| {
                let indent = "│   ".repeat(node.depth.saturating_sub(1));
                let connector = if node.depth == 0 { "" } else { "├─ " };
                let loc = if !node.file.is_empty() {
                    let short_file = node.file.rsplit('/').next().unwrap_or(&node.file);
                    if node.line.is_empty() {
                        format!("  {}", short_file)
                    } else {
                        format!("  {}:{}", short_file, node.line)
                    }
                } else {
                    String::new()
                };
                // Shorten label: keep last two segments of full name
                let short_label = {
                    let parts: Vec<&str> = node.label.split('.').collect();
                    if parts.len() > 2 {
                        format!("…{}", parts[parts.len()-2..].join("."))
                    } else {
                        node.label.clone()
                    }
                };
                let label_style = if node.depth == 0 {
                    Style::default().fg(theme.header).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.accent)
                };
                Line::from(vec![
                    Span::styled(format!("{}{}", indent, connector), Style::default().fg(theme.muted)),
                    Span::styled(short_label, label_style),
                    Span::styled(loc, Style::default().fg(theme.muted)),
                ])
            }).collect()
        } else {
            vec![]
        };

        frame.render_widget(Paragraph::new(tree_lines), child_area);
        render_scrollbar(frame, child_area, theme, tree_total, tree_scroll, child_viewport);
    } else if !detail.child_columns.is_empty() && child_rows_count > 0 {
        let col_refs: Vec<&str> = detail.child_columns.iter().map(String::as_str).collect();
        let constraints_child: Vec<Constraint> =
            detail.child_columns.iter().map(|c| Constraint::Fill(column_weight(c))).collect();

        let rows: Vec<Row> = if child_scroll < end {
            detail.child_rows[child_scroll..end].iter().map(|row| {
                let cs: Vec<Cell> = row.iter().map(|cell: &ModelCell| {
                    Cell::from(Span::styled(cell.v.clone(), style_for_kind(&cell.k, theme)))
                }).collect();
                Row::new(cs)
            }).collect()
        } else {
            vec![]
        };

        let child_table = Table::new(rows, constraints_child)
            .header(header_row(&col_refs, theme))
            .column_spacing(1);
        frame.render_widget(child_table, child_area);
        render_scrollbar(frame, child_area, theme, child_rows_count, child_scroll, child_viewport);
    } else if child_rows_count == 0 && !detail.child_title.is_empty() && !has_call_tree {
        let hint = Paragraph::new(Line::from(Span::styled(
            format!("No {}.", detail.child_title.to_lowercase()),
            Style::default().fg(theme.muted),
        )));
        frame.render_widget(hint, child_area);
    }

    if has_code {
        let code_area = sections[2];
        app.detail_code_area = Some(code_area); // for mouse hit-testing
        if let Some(code) = &detail.code {
            let code_lines: Vec<&str> = code.lines().collect();
            let code_total = code_lines.len();
            // Inner height after the TOP border title row.
            let code_viewport = code_area.height.saturating_sub(1) as usize;
            app.detail_code_visible = code_viewport;
            let code_scroll = if code_total > 0 {
                app.detail_code_scroll.min(code_total - 1)
            } else { 0 };
            app.detail_code_scroll = code_scroll;
            let code_end = (code_scroll + code_viewport).min(code_total);

            let rendered_lines: Vec<Line> = if code_scroll < code_end {
                code_lines[code_scroll..code_end]
                    .iter()
                    .enumerate()
                    .map(|(i, ln)| {
                        Line::from(vec![
                            Span::styled(
                                format!("{:4} ", code_scroll + i + 1),
                                Style::default().fg(theme.muted),
                            ),
                            Span::styled(ln.to_string(), Style::default().fg(theme.fg)),
                        ])
                    })
                    .collect()
            } else {
                vec![]
            };
            let code_block = Block::default()
                .borders(Borders::TOP)
                .title(" Source ")
                .border_style(Style::default().fg(theme.muted))
                .title_style(Style::default().fg(theme.header));
            let code_inner = code_block.inner(code_area);
            frame.render_widget(code_block, code_area);
            frame.render_widget(Paragraph::new(rendered_lines), code_inner);
            render_scrollbar(frame, code_area, theme, code_total, code_scroll, code_viewport);
        }
    }
}

/// Icon + colour for a flow step kind.
fn step_decoration(kind: &str, theme: &Theme) -> (&'static str, Style) {
    match kind {
        "source" => ("⊙", Style::default().fg(theme.header).add_modifier(Modifier::BOLD)),
        "sink" => ("◎", Style::default().fg(theme.error).add_modifier(Modifier::BOLD)),
        "sanitizer" => ("✓", Style::default().fg(theme.num).add_modifier(Modifier::BOLD)),
        "external" => ("⌘", Style::default().fg(theme.accent)),
        _ => ("·", Style::default().fg(theme.muted)),
    }
}

/// Render the data-flow master/detail view inside `area`: a flow list on the left, the selected
/// flow's ordered steps on the right.
fn render_flows(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect, focused: bool) {
    let fs = app.flows.as_ref().expect("render_flows called without a flow set");
    let shown = app.flow_visible.len();
    let title = format!(
        " Flows — {} ({} shown / {} total{}{}) ",
        fs.title,
        shown,
        fs.total,
        if app.show_subflows { "" } else { " · sub-flows hidden" },
        if app.hide_mitigated { " · mitigated hidden" } else { "" },
    );
    let block = panel_block(title, focused, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if shown == 0 {
        // Distinguish "engine returned nothing" from "filters hid everything".
        let msg = if fs.total == 0 {
            "No Reachable Flows found. Check if cdxgen SBOMs were included during atom generation."
        } else {
            "No flows match the current filters. Press s to show sub-flows or m to show mitigated."
        };
        let hint = Paragraph::new(Line::from(Span::styled(msg, Style::default().fg(theme.muted))));
        frame.render_widget(hint, inner);
        return;
    }

    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(inner);
    let master = halves[0];
    let detail = halves[1];

    render_flow_master(frame, app, theme, master, focused);
    render_flow_detail(frame, app, theme, detail);
}

// (detail rendering lives in render_flow_detail below)

fn render_flow_master(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect, focused: bool) {
    let viewport = area.height as usize;
    app.flow_state.visible = viewport;
    app.flow_rows_area = Some(area);

    let fs = app.flows.as_ref().unwrap();
    let len = app.flow_visible.len();
    let scroll = app.flow_state.scroll;
    let end = (scroll + viewport).min(len);

    // Split the available width between the source and sink labels (minus badges/arrow/length).
    let budget = (area.width as usize).saturating_sub(14);
    let half = (budget / 2).max(8);

    let lines: Vec<Line> = app.flow_visible[scroll..end]
        .iter()
        .enumerate()
        .map(|(i, &fi)| {
            let f = &fs.flows[fi];
            let sel = scroll + i == app.flow_state.selected;
            let badge = if f.mitigated { "✓" } else { " " };
            let badge_style = if f.mitigated {
                Style::default().fg(theme.num).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.muted)
            };
            let sub = if f.sub_flow_of.is_some() { "↳" } else { " " };
            // ◆ marks flows attributable to a package (purl-tagged), i.e. "reachable".
            let purl = if f.has_purl { "◆" } else { " " };
            let src = truncate(&f.source, half);
            let sink = truncate(&f.sink, half);
            let line = Line::from(vec![
                Span::styled(format!("{sub}{badge} "), badge_style),
                Span::styled(format!("{purl} "), Style::default().fg(theme.accent)),
                Span::styled(src, Style::default().fg(theme.header)),
                Span::styled(" → ", Style::default().fg(theme.muted)),
                Span::styled(sink, Style::default().fg(theme.error)),
                Span::styled(format!("  [{}]", f.length), Style::default().fg(theme.muted)),
            ]);
            line.style(row_style(sel, focused, theme))
        })
        .collect();

    frame.render_widget(Paragraph::new(lines), area);
    render_scrollbar(frame, area, theme, len, scroll, viewport);
}

/// Span list for a single flow step (optionally indented under an expanded group header).
fn step_spans<'a>(step: &crate::model::FlowStep, theme: &Theme, indent: bool) -> Vec<Span<'a>> {
    let (icon, icon_style) = step_decoration(&step.kind, theme);
    let lead = if indent { "    " } else { "" };
    let mut spans = vec![
        Span::styled(format!("{lead}{icon} "), icon_style),
        Span::styled(
            format!("{}:{} ", truncate(&step.file, 24), step.line),
            Style::default().fg(theme.link),
        ),
        Span::styled(format!("{} ", truncate(&step.method, 16)), Style::default().fg(theme.muted)),
    ];
    if !step.symbol.is_empty() {
        spans.push(Span::styled(
            format!("{} ", step.symbol),
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        ));
    }
    spans.push(Span::styled(truncate(&step.code, 56), Style::default().fg(theme.code)));
    if !step.tags.is_empty() {
        spans.push(Span::styled(format!("  [{}]", step.tags.join(",")), Style::default().fg(theme.num)));
    }
    spans
}

/// Kind precedence for choosing the icon of a collapsed group (most significant kind wins).
fn kind_rank(kind: &str) -> u8 {
    match kind {
        "sink" => 0,
        "source" => 1,
        "sanitizer" => 2,
        "external" => 3,
        _ => 4,
    }
}

fn render_flow_detail(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect) {
    app.flow_detail_area = Some(area);
    app.flow_detail_groups.clear();

    let Some(flow) = app.selected_flow().cloned() else {
        return;
    };
    // Reset per-flow expansion state and scroll when the selected flow changes.
    if app.flow_detail_id != Some(flow.id) {
        app.expanded_lines.clear();
        app.flow_detail_id = Some(flow.id);
        app.flow_detail_scroll = 0;
    }

    let tag_str = |tags: &[String]| {
        if tags.is_empty() { String::new() } else { format!("  [{}]", tags.join(", ")) }
    };

    // Build ALL lines unconditionally (scroll window applied below).
    let mut all_lines: Vec<Line> = Vec::new();
    // Group-header positions in the all_lines index (mapped to screen Y after scroll).
    let mut group_positions: Vec<(usize, (String, i64))> = Vec::new();

    all_lines.push(Line::from(vec![
        Span::styled("Source: ", Style::default().fg(theme.muted)),
        Span::styled(truncate(&flow.source, 50), Style::default().fg(theme.header)),
        Span::styled(tag_str(&flow.source_tags), Style::default().fg(theme.num)),
    ]));
    all_lines.push(Line::from(vec![
        Span::styled("Sink:   ", Style::default().fg(theme.muted)),
        Span::styled(truncate(&flow.sink, 50), Style::default().fg(theme.error)),
        Span::styled(tag_str(&flow.sink_tags), Style::default().fg(theme.num)),
    ]));
    if flow.mitigated {
        all_lines.push(Line::from(Span::styled(
            "✓ This flow has a validation/sanitisation step.",
            Style::default().fg(theme.num).add_modifier(Modifier::BOLD),
        )));
    }
    all_lines.push(Line::from(Span::raw("")));

    // Group consecutive steps sharing (file, line); collapse multi-step groups by default.
    let mut groups: Vec<Vec<&crate::model::FlowStep>> = Vec::new();
    for step in &flow.steps {
        match groups.last_mut() {
            Some(g) if g[0].file == step.file && g[0].line == step.line => g.push(step),
            _ => groups.push(vec![step]),
        }
    }

    for group in &groups {
        if group.len() == 1 {
            all_lines.push(Line::from(step_spans(group[0], theme, false)));
            continue;
        }

        let key = (group[0].file.clone(), group[0].line);
        let expanded = app.expanded_lines.contains(&key);
        let rep = group
            .iter()
            .min_by_key(|s| (kind_rank(&s.kind), -(s.code.chars().count() as i64)))
            .unwrap();
        let (icon, icon_style) = step_decoration(&rep.kind, theme);
        let caret = if expanded { "▾" } else { "▸" };

        group_positions.push((all_lines.len(), key.clone()));
        all_lines.push(Line::from(vec![
            Span::styled(format!("{caret} "), Style::default().fg(theme.muted)),
            Span::styled(icon.to_string() + " ", icon_style),
            Span::styled(
                format!("{}:{} ", truncate(&rep.file, 24), rep.line),
                Style::default().fg(theme.link),
            ),
            Span::styled(format!("({}) ", group.len()), Style::default().fg(theme.muted)),
            Span::styled(truncate(&rep.code, 50), Style::default().fg(theme.code)),
        ]));

        if expanded {
            for step in group {
                all_lines.push(Line::from(step_spans(step, theme, true)));
            }
        }
    }

    let total    = all_lines.len();
    let viewport = area.height as usize;
    app.flow_detail_total   = total;
    app.flow_detail_visible = viewport;

    let scroll = if total > 0 { app.flow_detail_scroll.min(total - 1) } else { 0 };
    app.flow_detail_scroll = scroll;
    let end = (scroll + viewport).min(total);

    // Map group-header positions to screen Y for click-to-expand hit-testing.
    for (line_idx, key) in group_positions {
        if line_idx >= scroll && line_idx < end {
            app.flow_detail_groups.push((area.y + (line_idx - scroll) as u16, key));
        }
    }

    let visible: Vec<Line> = all_lines.into_iter().skip(scroll).take(viewport).collect();
    frame.render_widget(Paragraph::new(visible), area);
    render_scrollbar(frame, area, theme, total, scroll, viewport);
}

// ---------------------------------------------------------------------------
// Agent transcript view
// ---------------------------------------------------------------------------

/// Braille spinner frames for the "running" indicator.
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn render_agent_transcript(frame: &mut Frame, app: &mut App, theme: &Theme, area: Rect, focused: bool) {
    let title = if app.agent_active {
        // Advance the spinner each frame while the agent is working.
        app.agent_spinner = app.agent_spinner.wrapping_add(1);
        let spin = SPINNER_FRAMES[(app.agent_spinner / 2) % SPINNER_FRAMES.len()];
        format!(" Agent Transcript {spin} running… ")
    } else {
        " Agent Transcript ".to_string()
    };
    let block = panel_block(title, focused, theme);
    let outer_inner = block.inner(area);
    frame.render_widget(block, area);

    if outer_inner.height == 0 || outer_inner.width == 0 { return; }

    // Reserve the bottom row for a progress/usage footer once a run has started.
    let show_footer = app.agent_active || !app.agent_transcript.is_empty();
    let (inner, footer) = if show_footer && outer_inner.height >= 2 {
        (
            Rect { height: outer_inner.height - 1, ..outer_inner },
            Some(Rect { y: outer_inner.y + outer_inner.height - 1, height: 1, ..outer_inner }),
        )
    } else {
        (outer_inner, None)
    };
    if let Some(footer_area) = footer {
        frame.render_widget(Paragraph::new(agent_footer_line(app, theme)), footer_area);
    }

    // Record the content area for mouse scroll hit-testing.
    app.agent_transcript_area = Some(inner);

    if inner.height == 0 || inner.width == 0 { return; }

    let viewport = inner.height as usize;
    let total = app.agent_transcript.len();
    if total > 0 && app.agent_scroll >= total {
        app.agent_scroll = total.saturating_sub(1);
    }

    if total == 0 {
        let hint = if app.agent_active {
            "Waiting for agent response…"
        } else {
            "Type a question in the REPL or use a /slash command to start the agent.\n\nExample: /security-review, /explain, what does this codebase do?"
        };
        let hint_lines: Vec<Line> = hint.lines().map(|l| {
            Line::from(Span::styled(l.to_string(), Style::default().fg(theme.muted)))
        }).collect();
        frame.render_widget(Paragraph::new(hint_lines), inner);
        return;
    }

    // Build visible lines from the scroll position upward to fill the viewport.
    // First, determine the scroll position in "entry units" by counting lines backward.
    let target_entry = app.agent_scroll.min(total.saturating_sub(1));

    // Pre-compute line counts for each entry to enable efficient scrolling.
    let line_counts: Vec<usize> = app.agent_transcript.iter().map(entry_line_count).collect();
    let total_lines: usize = line_counts.iter().sum();

    // Convert entry-level scroll to line-level scroll.
    let mut line_scroll = 0usize;
    for (i, &lc) in line_counts.iter().enumerate() {
        if i == target_entry { break; }
        line_scroll += lc;
    }
    // Center the target entry in the viewport.
    line_scroll = line_scroll.saturating_sub(viewport / 3);

    // Build the full line list, then slice.
    let all_lines: Vec<Line> = build_agent_lines(app, theme, &line_counts, inner.width as usize);

    let visible: Vec<Line> = if total_lines > viewport && line_scroll + viewport < total_lines {
        all_lines[line_scroll..line_scroll + viewport].to_vec()
    } else if total_lines > viewport {
        all_lines[total_lines.saturating_sub(viewport)..].to_vec()
    } else {
        all_lines
    };

    frame.render_widget(Paragraph::new(visible), inner);
    render_scrollbar(frame, area, theme, total_lines, line_scroll, viewport);
}

/// Build the full list of rendered lines from the agent transcript.
fn build_agent_lines<'a>(app: &'a App, theme: &Theme, _line_counts: &[usize], width: usize) -> Vec<Line<'a>> {
    let mut lines: Vec<Line> = Vec::new();
    for entry in &app.agent_transcript {
        match entry {
            AgentEntry::Text(text) => {
                // Render the assistant prose as lightweight markdown. Exactly one
                // rendered Line per source line keeps the scroll math (which uses
                // `entry_line_count`) in sync.
                let mut in_code = false;
                for line in text.split('\n') {
                    if let Some(lang) = line.trim_start().strip_prefix("```") {
                        in_code = !in_code;
                        let label = if in_code && !lang.trim().is_empty() {
                            format!("``` {}", lang.trim())
                        } else {
                            "```".to_string()
                        };
                        lines.push(Line::from(Span::styled(label, Style::default().fg(theme.muted))));
                    } else if in_code {
                        lines.push(Line::from(vec![
                            Span::styled("│ ", Style::default().fg(theme.muted)),
                            Span::styled(line.to_string(), Style::default().fg(theme.code)),
                        ]));
                    } else {
                        lines.push(render_markdown_line(line, theme));
                    }
                }
            }
            AgentEntry::Thinking(text) => {
                if app.agent_thinking_expanded {
                    for line in text.split('\n') {
                        lines.push(Line::from(vec![
                            Span::styled("💭 ", Style::default().fg(theme.muted)),
                            Span::styled(line.to_string(), Style::default().fg(theme.muted)),
                        ]));
                    }
                } else {
                    let preview: String = text.chars().take(120).collect();
                    let label = if text.len() > 120 { format!("{}…", preview) } else { preview };
                    lines.push(Line::from(vec![
                        Span::styled("💭 ", Style::default().fg(theme.muted)),
                        Span::styled(label, Style::default().fg(theme.muted)),
                    ]));
                }
            }
            AgentEntry::ToolCall { name, input, result, is_error, .. } => {
                let input_str = serde_json::to_string(input).unwrap_or_default();
                let preview: String = input_str.chars().take(width.saturating_sub(8)).collect();
                lines.push(Line::from(vec![
                    Span::styled("⚙ ", Style::default().fg(theme.accent)),
                    Span::styled(name.clone(), Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("({preview})"), Style::default().fg(theme.muted)),
                ]));
                if let Some(res) = result {
                    let res_preview: String = res.chars().take(width.saturating_sub(4)).collect();
                    let res_style = if *is_error { Style::default().fg(theme.error) } else { Style::default().fg(theme.num) };
                    lines.push(Line::from(vec![
                        Span::styled("  └─ ", Style::default().fg(theme.muted)),
                        Span::styled(if *is_error { "error: " } else { "" }, Style::default().fg(theme.error)),
                        Span::styled(res_preview, res_style),
                    ]));
                }
            }
            AgentEntry::Error(msg) => {
                lines.push(Line::from(Span::styled(format!("✗ {msg}"), Style::default().fg(theme.error))));
            }
            AgentEntry::Usage { input_tokens, output_tokens } => {
                lines.push(Line::from(Span::styled(
                    format!("  {input_tokens} in / {output_tokens} out"),
                    Style::default().fg(theme.muted),
                )));
            }
            AgentEntry::StopReason(reason) => {
                lines.push(Line::from(Span::styled(
                    format!("  stop: {reason}"),
                    Style::default().fg(theme.muted),
                )));
            }
            AgentEntry::Done => {
                lines.push(Line::from(Span::styled("  ✓ done", Style::default().fg(theme.num))));
            }
        }
    }
    lines
}

/// One-line progress/usage footer for the agent panel: spinner + current tool
/// while running, a running token meter, and key hints.
fn agent_footer_line<'a>(app: &App, theme: &Theme) -> Line<'a> {
    let mut spans: Vec<Span> = Vec::new();
    if app.agent_active {
        let spin = SPINNER_FRAMES[(app.agent_spinner / 2) % SPINNER_FRAMES.len()];
        spans.push(Span::styled(format!("{spin} working "), Style::default().fg(theme.accent)));
        if let Some(tool) = &app.agent_last_tool {
            spans.push(Span::styled(format!("· ⚙ {tool} "), Style::default().fg(theme.muted)));
        }
    } else {
        spans.push(Span::styled("✓ done ", Style::default().fg(theme.num)));
    }
    if app.agent_total_in > 0 || app.agent_total_out > 0 {
        spans.push(Span::styled(
            format!("· Σ {} in / {} out ", app.agent_total_in, app.agent_total_out),
            Style::default().fg(theme.muted),
        ));
    }
    let hint = if app.agent_active { "· [c] cancel" } else { "· [t] thinking" };
    spans.push(Span::styled(hint.to_string(), Style::default().fg(theme.muted)));
    Line::from(spans)
}

/// Render one non-code markdown line: headings, bullet lists, and inline
/// `**bold**` / `` `code` `` spans. Produces exactly one [`Line`].
fn render_markdown_line<'a>(line: &str, theme: &Theme) -> Line<'a> {
    let trimmed = line.trim_start();
    let heading = |text: &str, level: u8| -> Line<'a> {
        let marker = match level { 1 => "▌ ", 2 => "▌ ", _ => "· " };
        Line::from(vec![
            Span::styled(marker.to_string(), Style::default().fg(theme.accent)),
            Span::styled(
                text.to_string(),
                Style::default().fg(theme.header).add_modifier(Modifier::BOLD),
            ),
        ])
    };
    if let Some(h) = trimmed.strip_prefix("### ") { return heading(h, 3); }
    if let Some(h) = trimmed.strip_prefix("## ") { return heading(h, 2); }
    if let Some(h) = trimmed.strip_prefix("# ") { return heading(h, 1); }

    // Bullet list (preserve indentation).
    let indent_len = line.len() - trimmed.len();
    if let Some(rest) = trimmed.strip_prefix("- ").or_else(|| trimmed.strip_prefix("* ")) {
        let mut spans = vec![Span::styled(
            format!("{}• ", &line[..indent_len]),
            Style::default().fg(theme.accent),
        )];
        spans.extend(inline_spans(rest, Style::default().fg(theme.fg), theme));
        return Line::from(spans);
    }
    Line::from(inline_spans(line, Style::default().fg(theme.fg), theme))
}

/// Split a line into styled spans, honouring `**bold**` and `` `code` ``.
/// (Markers are ASCII, so byte-offset slicing stays on char boundaries.)
fn inline_spans<'a>(text: &str, base: Style, theme: &Theme) -> Vec<Span<'a>> {
    let code_style = Style::default().fg(theme.code).bg(theme.muted_selection_bg);
    let bold = base.add_modifier(Modifier::BOLD);
    let mut spans: Vec<Span> = Vec::new();
    let mut buf = String::new();
    let mut i = 0;
    while i < text.len() {
        if text[i..].starts_with("**")
            && let Some(end) = text[i + 2..].find("**") {
                if !buf.is_empty() {
                    spans.push(Span::styled(std::mem::take(&mut buf), base));
                }
                spans.push(Span::styled(text[i + 2..i + 2 + end].to_string(), bold));
                i = i + 2 + end + 2;
                continue;
            }
        if text.as_bytes()[i] == b'`'
            && let Some(end) = text[i + 1..].find('`') {
                if !buf.is_empty() {
                    spans.push(Span::styled(std::mem::take(&mut buf), base));
                }
                spans.push(Span::styled(text[i + 1..i + 1 + end].to_string(), code_style));
                i = i + 1 + end + 1;
                continue;
            }
        let ch_len = text[i..].chars().next().map(char::len_utf8).unwrap_or(1);
        buf.push_str(&text[i..i + ch_len]);
        i += ch_len;
    }
    if !buf.is_empty() {
        spans.push(Span::styled(buf, base));
    }
    if spans.is_empty() {
        spans.push(Span::styled(String::new(), base));
    }
    spans
}

/// Number of rendered lines a transcript entry occupies.
fn entry_line_count(entry: &AgentEntry) -> usize {
    match entry {
        AgentEntry::Text(t) => t.split('\n').count().max(1),
        AgentEntry::Thinking(_) => 1,
        AgentEntry::ToolCall { result, .. } => {
            1 + if result.is_some() { 1 } else { 0 }
        }
        AgentEntry::Error(_) | AgentEntry::Usage { .. } | AgentEntry::StopReason(_) | AgentEntry::Done => 1,
    }
}

/// Truncate a string to `max` display chars, appending an ellipsis when shortened.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn render_status(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let text = if app.status.is_empty() {
        "q quit · Tab panel · ↑/↓ move · Enter run · d data flows · r reachable · / filter · 1-9 sort · s/m toggles"
            .to_string()
    } else {
        app.status.clone()
    };
    let p = Paragraph::new(Line::from(Span::styled(text, Style::default().fg(theme.muted))));
    frame.render_widget(p, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::model::{Cell, ResultTable, Summary, SummaryRow};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn rendered_text(app: &mut App) -> String {
        let theme = Theme::dark();
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, app, &theme)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    #[test]
    fn renders_three_panels_with_repl_prompt() {
        let summary = Summary {
            language: "JSSRC".into(),
            version: "0.1".into(),
            rows: vec![
                SummaryRow { label: "Files".into(), count: 8 },
                SummaryRow { label: "Methods".into(), count: 349 },
            ],
        };
        let mut app = App::new(None, "js-app.atom".into(), summary);
        let text = rendered_text(&mut app);
        assert!(text.contains("Summary"));
        assert!(text.contains("REPL"));
        assert!(text.contains("Output"));
        assert!(text.contains("chennai>"));
        assert!(text.contains("Files"));
        assert!(text.contains("349"));
    }

    #[test]
    fn renders_output_table_with_line_count_column() {
        let mut app = App::new(None, "x.atom".into(), Summary::default());
        app.output = Some(ResultTable {
            title: "Methods".into(),
            columns: vec!["Name".into(), "File".into(), "Line Count".into()],
            rows: vec![vec![
                Cell { v: "main".into(), k: "name".into() },
                Cell { v: "a.c".into(), k: "path".into() },
                Cell { v: "12".into(), k: "num".into() },
            ]],
            total: 1,
            offset: 0,
        });
        app.recompute_table_view();
        app.focus = Panel::Output;
        let text = rendered_text(&mut app);
        assert!(text.contains("Output — Methods"));
        assert!(text.contains("Line Count"));
        assert!(text.contains("main"));
        assert!(text.contains("a.c"));
    }

    fn methods_table_app() -> App {
        use crate::model::{Cell, ResultTable};
        let row = |n: &str, lc: &str| {
            vec![
                Cell { v: n.into(), k: "name".into() },
                Cell { v: lc.into(), k: "num".into() },
            ]
        };
        let mut app = App::new(None, "x.atom".into(), Summary::default());
        app.output = Some(ResultTable {
            title: "Methods".into(),
            columns: vec!["Name".into(), "Line Count".into()],
            rows: vec![row("charlie", "30"), row("alpha", "100"), row("bravo", "9")],
            total: 3,
            offset: 0,
        });
        app.recompute_table_view();
        app.focus = Panel::Output;
        app
    }

    #[test]
    fn table_filter_narrows_visible_rows() {
        let mut app = methods_table_app();
        assert_eq!(app.table_visible.len(), 3);
        app.start_table_filter();
        for c in "alp".chars() {
            app.table_filter_input(c);
        }
        assert_eq!(app.table_visible.len(), 1);
        let text = rendered_text(&mut app);
        assert!(text.contains("alpha"));
        assert!(!text.contains("charlie"));
        assert!(text.contains("/alp"));
    }

    #[test]
    fn clicking_a_column_header_sorts_by_it() {
        let mut app = methods_table_app();
        // Render once so the header-cell rects are populated.
        let _ = rendered_text(&mut app);
        assert!(!app.table_header_cells.is_empty());
        // Click within the second column's header cell.
        let cell = app.table_header_cells[1];
        app.on_click(cell.x + 1, cell.y);
        assert_eq!(app.table_sort, Some((1, true)));
        let order: Vec<&str> =
            app.table_visible.iter().map(|&i| app.output.as_ref().unwrap().rows[i][1].v.as_str()).collect();
        assert_eq!(order, vec!["9", "30", "100"]);
        // Clicking the same header again flips the direction.
        app.on_click(cell.x + 1, cell.y);
        assert_eq!(app.table_sort, Some((1, false)));
    }

    #[test]
    fn table_sort_orders_rows_numerically_and_lexically() {
        let mut app = methods_table_app();
        // Sort by Line Count (column 1): numeric, ascending → 9, 30, 100.
        app.sort_by_column(1);
        let order: Vec<&str> =
            app.table_visible.iter().map(|&i| app.output.as_ref().unwrap().rows[i][1].v.as_str()).collect();
        assert_eq!(order, vec!["9", "30", "100"]);
        // Toggle to descending.
        app.sort_by_column(1);
        let order: Vec<&str> =
            app.table_visible.iter().map(|&i| app.output.as_ref().unwrap().rows[i][1].v.as_str()).collect();
        assert_eq!(order, vec!["100", "30", "9"]);
        // Sort by Name (column 0): lexicographic ascending.
        app.sort_by_column(0);
        let names: Vec<&str> =
            app.table_visible.iter().map(|&i| app.output.as_ref().unwrap().rows[i][0].v.as_str()).collect();
        assert_eq!(names, vec!["alpha", "bravo", "charlie"]);
    }

    fn flow_app() -> App {
        use crate::model::{Flow, FlowSet, FlowStep};
        let mut app = App::new(None, "x.atom".into(), Summary::default());
        let step = |kind: &str, sym: &str| FlowStep {
            kind: kind.into(),
            code: format!("{sym}_code"),
            method: "handler".into(),
            file: "views.py".into(),
            line: 10,
            symbol: sym.into(),
            tags: if kind == "source" { vec!["framework-input".into()] } else { vec![] },
            ..Default::default()
        };
        let main = Flow {
            id: 0,
            source: "request".into(),
            sink: "execute(q)".into(),
            source_tags: vec!["framework-input".into()],
            sink_tags: vec!["framework-output".into()],
            mitigated: true,
            has_purl: true,
            length: 3,
            sub_flow_of: None,
            steps: vec![step("source", "request"), step("sanitizer", "clean"), step("sink", "q")],
        };
        let sub = Flow {
            id: 1,
            source: "request".into(),
            sink: "execute(q)".into(),
            length: 2,
            sub_flow_of: Some(0),
            steps: vec![step("source", "request"), step("sink", "q")],
            ..Default::default()
        };
        app.flows = Some(FlowSet {
            title: "Reachable flows".into(),
            total: 2,
            shown: 2,
            offset: 0,
            flows: vec![main, sub],
        });
        app.focus = Panel::Output;
        // Mirror what dispatch_flows does.
        app.toggle_subflows(); // show
        app.toggle_subflows(); // hide again -> exercises recompute; leaves sub-flows hidden
        app
    }

    #[test]
    fn flow_view_renders_master_and_detail_with_subflows_hidden() {
        let mut app = flow_app();
        // Sub-flows hidden by default: only the main flow is visible.
        assert_eq!(app.flow_visible.len(), 1);
        let text = rendered_text(&mut app);
        assert!(text.contains("Flows"));
        assert!(text.contains("request"));
        assert!(text.contains("execute(q)"));
        // Detail caption + tags + mitigation banner.
        assert!(text.contains("Source:"));
        assert!(text.contains("framework-input"));
        assert!(text.contains("validation/sanitisation"));
    }

    #[test]
    fn detail_collapses_repeating_lines_and_expands_on_click() {
        use crate::model::{Flow, FlowSet, FlowStep};
        let step = |kind: &str, line: i64, code: &str| FlowStep {
            kind: kind.into(),
            code: code.into(),
            method: "h".into(),
            file: "views.py".into(),
            line,
            symbol: "x".into(),
            ..Default::default()
        };
        let flow = Flow {
            id: 7,
            source: "req".into(),
            sink: "exec".into(),
            length: 5,
            steps: vec![
                step("source", 10, "src"),
                step("propagation", 20, "mid_a"),
                step("propagation", 20, "mid_b"),
                step("propagation", 20, "mid_c"),
                step("sink", 30, "snk"),
            ],
            ..Default::default()
        };
        let mut app = App::new(None, "x.atom".into(), Summary::default());
        app.flows = Some(FlowSet { title: "F".into(), total: 1, shown: 1, offset: 0, flows: vec![flow] });
        app.flow_visible = vec![0];
        app.focus = Panel::Output;

        // Collapsed by default: the 3 line-20 steps show as a "(3)" group, individual codes hidden.
        let text = rendered_text(&mut app);
        assert!(text.contains("(3)"));
        assert!(!text.contains("mid_b"));

        // Expanding the line-20 group reveals the individual steps.
        app.expanded_lines.insert(("views.py".to_string(), 20));
        let text = rendered_text(&mut app);
        assert!(text.contains("mid_a"));
        assert!(text.contains("mid_c"));
    }

    #[test]
    fn toggling_subflows_and_mitigated_changes_visible_count() {
        let mut app = flow_app();
        assert_eq!(app.flow_visible.len(), 1); // sub-flow hidden
        app.toggle_subflows();
        assert_eq!(app.flow_visible.len(), 2); // sub-flow now shown
        app.toggle_mitigated();
        // Hiding mitigated removes the (mitigated) main flow, leaving the sub-flow.
        assert_eq!(app.flow_visible.len(), 1);
    }

    #[test]
    fn summary_collapses_when_result_shown_and_unfocused() {
        use crate::model::{Cell, ResultTable, SummaryRow};
        let summary = Summary {
            language: "PYTHONSRC".into(),
            version: "1".into(),
            rows: vec![SummaryRow { label: "Files".into(), count: 1484 }],
        };
        let mut app = App::new(None, "x.atom".into(), summary);
        app.output = Some(ResultTable {
            title: "Methods".into(),
            columns: vec!["Name".into()],
            rows: vec![vec![Cell { v: "main".into(), k: "name".into() }]],
            total: 1,
            offset: 0,
        });
        app.recompute_table_view();

        // Output focused → summary collapses to the one-line hint, no full table header.
        app.focus = Panel::Output;
        let text = rendered_text(&mut app);
        assert!(text.contains("Tab/click to expand"));
        assert!(!text.contains("Node Type"));

        // Focusing the summary expands it again.
        app.focus = Panel::Summary;
        let text = rendered_text(&mut app);
        assert!(text.contains("Node Type"));
        assert!(!text.contains("Tab/click to expand"));
    }

    #[test]
    fn renders_repl_scrollback() {
        let mut app = App::new(None, "x.atom".into(), Summary::default());
        app.repl.record("atom.file", "Files: 8 of 8 row(s)".into(), true);
        let text = rendered_text(&mut app);
        assert!(text.contains("atom.file"));
    }
}
