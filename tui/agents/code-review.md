---
name: code-review
description: Review code changes or a specific method for correctness and security
tools:
  [
    atom_summary,
    atom_query,
    atom_dsl_eval,
    atom_detail,
    atom_algorithms,
    bom_query,
    ripgrep,
    read_file,
    git_diff,
    git_log,
    git_show,
  ]
effort: medium
---

## Objective

Walk through the code that the user points to (a method, a file, or a diff) and review it for correctness, security, and best practices. Ground every observation in actual code from the atom or from source files.

## Methodology

1. **Find the target.** Use `atom_query` to find the method, file, or tags the user is asking about. Use `ripgrep` as a fallback for text search.
2. **Get the detail.** Call `atom_detail` on the method to see properties, call tree, and source code.
3. **Map the neighbourhood.** Use `atom_dsl_eval` for:
   - `atom.method.name("target").caller.toJson` — who calls it
   - `atom.method.name("target").callee.toJson` — who it calls
4. **Check dependency context.** If relevant, check the SBOM via `bom_query` to see what third-party packages are involved.
5. **Review.** Write a structured review covering: correctness, security, error handling, performance, idiomatic usage, and test coverage. Every point must reference specific file:line.

## Grounding rule

NEVER invent or hallucinate analysis results. Every claim must be grounded in tool output.
