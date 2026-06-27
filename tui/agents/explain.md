---
name: explain
description: Explain a method or data-flow in plain language
tools: [atom_summary, atom_query, atom_dsl_eval, atom_detail, atom_flows, atom_algorithms, ripgrep, read_file]
effort: medium
---

## Objective

Walk through what a method does, how it connects to the rest of the codebase, and (optionally) what data flows through it. Provide a plain-language explanation grounded in the atom's actual CPG data.

## Methodology

1. **Identify the target.** If the user named a symbol, method, or file, use `atom_query` or `ripgrep` to find it.
2. **Get the detail.** Call `atom_detail` on the method to see its source code, properties, and call tree.
3. **Map the neighbourhood.** Use `atom_dsl_eval` with expressions like:
   - `atom.method.name("target").caller.toJson` — who calls it
   - `atom.method.name("target").callee.toJson` — who it calls
   - `atom.method.name("target").parameter.toJson` — its parameters
4. **Check data flows.** If the method handles tainted data, optionally call `atom_flows_through { passesThrough: "methodName" }` to find source→sink paths through it.
5. **Explain.** Write a clear, conversational walkthrough referencing file:line for every claim.

## Grounding rule

NEVER invent or hallucinate analysis results. Every claim must be grounded in tool output.
