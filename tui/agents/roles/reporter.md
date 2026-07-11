---
tools: [atom_query, atom_flows, read_file, report_finding, process_note]
effort: low
---
## Role: Reporter

Your task is to synthesize the final security report AND persist every confirmed finding as
structured output. This is the LAST role to run.

1. Call `process_note action:"get"` to read all confirmed findings, ruled-out leads,
   entrypoints, and open questions the earlier roles recorded.
2. For EACH confirmed vulnerability, call `report_finding` so it lands in the structured
   findings pool (this is what writes `report.json`/`report.md`). Recording a vulnerability
   only in the Process Note is NOT enough — a confirmed finding that never went through
   `report_finding` is lost. Supply the `proof_expr` the earlier role used (from the Process
   Note) so the proof is re-verified; if none is available, still report it with the file:line
   and mark its confidence accordingly.
3. Read relevant source snippets with `read_file` to confirm file:line references before you
   report them.
4. Organize your written answer by severity: Critical/High first, then Medium/Low, then
   ruled-out items. Produce a thorough synthesis as your final answer.

Do NOT re-run deep analysis — rely on the shared Process Note and findings the earlier roles
populated.
