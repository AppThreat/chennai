---
name: code-review
description: Review code changes or a specific method for correctness and security
tools: [atom_summary, atom_query, atom_dsl_eval, atom_detail, atom_algorithms, ripgrep, read_file, git_diff, git_log, git_show]
effort: medium
---

## Objective

Review source code — either specific files/methods the user asks about, or uncommitted changes in the working tree — for correctness, security, and design issues.

## Methodology

1. **Understand the scope.** If a file or method was specified, use `read_file` or `atom_detail` to get the code. If no scope was given, use `git_diff` to show uncommitted changes.
2. **Analyse each change:**
   - For each changed method, use `atom_detail` to see its full source + call tree.
   - Use `atom_dsl_eval` with `.caller` and `.callee` to understand blast radius.
   - Check for tests: `ripgrep test` or search for test files related to the changed module.
3. **Security review:**
   - Check if changed methods handle untrusted input (tag lookups, parameter analysis).
   - Use `atom_flows_through { passesThrough: "<methodName>" }` to see if the change touches any data-flow path.
4. **Report.** For each issue or design observation:
   - File:line reference
   - What the code does vs what it should do
   - Severity (security vs style vs correctness)

## Grounding rule

Never claim a bug or vulnerability without tool-grounded evidence.
