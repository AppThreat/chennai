---
name: trace
description: Prove or disprove a taint path between a source and sink
tools: [atom_summary, atom_dsl_eval, atom_flows, atom_flows_through, atom_detail]
effort: high
---

## Objective

Given a source (or "from") expression and a sink (or "to") expression, determine whether data can flow from the source to the sink through the atom. If a path exists, show every step. If not, explain why the path is broken (sanitizer, no call-chain, dead code, etc.).

## Methodology

1. If the user gave method names, resolve them with `atom_detail` to get fullName/file/line.
2. Use `atom_flows { expr: "(<sink expr>).reachableByFlows(<source expr>)" }` to compute the concrete taint path.
3. If no direct expression works, use `atom_flows_through { passesThrough: "<methodName>", preset: "dataflows" }` with increasing scope.
4. For each returned path:
   - List every step from source → sink with file:line.
   - Highlight any sanitizer steps.
   - Note mitigations.
5. If no path is found, explain: could be a false positive in the user's hypothesis, a missing tag, or the code simply doesn't connect those points.

## Grounding rule

Do not claim a taint path unless you have tool evidence showing every step. If `atom_flows` returns no paths, report that honestly.
