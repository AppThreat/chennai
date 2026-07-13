# Custom Sub-Agent Roles

The orchestrator supports project-defined sub-agent roles that run alongside (or
replace) the built-in roles — no Rust rebuild required.

## How it works

Drop markdown files with YAML frontmatter into a project-local directory:

```
<your-project>/.chen/agents/roles/<role-name>.md
```

The orchestrator discovers them automatically at runtime. Each file defines a
role name, an optional tool allowlist, an effort override, a turn budget, and a
description for the orchestrator's role menu.

## Role file format

```markdown
---
description: Short one-line description shown in the orchestrator's role menu.
tools: [atom_query, ripgrep, read_file, report_finding, process_note]
effort: high
max_turns: 20
---
## Role: Your Role Name

Instructions for the sub-agent go here. This is the prompt body that seeds
the sub-agent's transcript.
```

### Frontmatter fields

| Field         | Type           | Required | Description |
|---------------|----------------|----------|-------------|
| `description` | string         | No       | One-line summary for the orchestrator's role menu. Falls back to the first body line if omitted. |
| `tools`       | list of strings| No       | Tool-name allowlist. `None` grants all tools. |
| `effort`      | string         | No       | Provider effort override (`low`, `medium`, `high`, `xhigh`, `max`). |
| `max_turns`   | integer        | No       | Per-run turn budget. Clamped to a hard ceiling of 40. Defaults to 10 for custom roles. |

### Name rules

Role names must match `^[a-z0-9][a-z0-9-]{0,63}$`:
- Lowercase letters, digits, and hyphens only.
- Must start with a letter or digit (no leading hyphen).
- 1–64 characters.
- Files with invalid names are silently ignored.

## Precedence

When the same role name exists in multiple locations, the highest-precedence
source wins:

1. **Project-local** — `<source_root>/.chen/agents/roles/<name>.md`
2. **User-global** — `~/.config/chennai/agents/roles/<name>.md`
3. **Built-in** — compiled into the binary (recon, sink-hunter, taint-prover, auth-boundary, supply-chain, reporter)

## Project orchestration manifest

Optional file at `<source_root>/.chen/agents/orchestrate.toml` for coarse knobs:

```toml
max_subagents = 6
turn_budget = 120
token_budget = 200000
roles = ["recon", "sink-hunter", "my-crypto-auditor"]
orchestrator_prompt = "agents/orchestrator.md"
```

| Field                  | Description |
|------------------------|-------------|
| `max_subagents`        | Tighten the sub-agent cap. May only *lower* the CLI/env value, never raise it. |
| `turn_budget`          | Tighten the advisory global turn budget (lower-only). |
| `token_budget`         | Tighten the advisory global token budget (lower-only; also hard-capped at 256K). |
| `roles`                | Restrict the role menu to this ordered subset. |
| `orchestrator_prompt`  | Path to a project-specific orchestrator prompt (relative to source root; `..` and absolute paths are rejected). |

All fields are optional. Partial manifests work — unknown keys are ignored.
Because the manifest lives inside the audited repository, budget knobs can only
*tighten* the limits you set on the command line — a repo can never raise your
sub-agent count or token spend.
The manifest cannot *initiate* an orchestrated run; it only configures the
shape of one already engaged via `--orchestrate`, `CHENNAI_ORCHESTRATE`, or
`/orchestrate`.

## Built-in roles (always available)

| Role           | Purpose |
|----------------|---------|
| `recon`        | Maps codebase structure, entrypoints, and tags. |
| `sink-hunter`  | Finds dangerous sinks and proves they are reachable. |
| `taint-prover` | Proves end-to-end taint paths from source to sink. |
| `auth-boundary`| Analyzes authentication and authorization coverage. |
| `supply-chain` | Audits dependencies for known vulnerabilities. |
| `reporter`     | Compiles findings into a final report. |

## Example

See `tui/agents/examples/crypto-auditor.md` for a complete example role that
audits cryptographic implementations.

To use it in your project:

```bash
mkdir -p .chen/agents/roles
cp path/to/crypto-auditor.md .chen/agents/roles/
chennai --orchestrate /path/to/your/project
```

Or from the TUI REPL:

```
/orchestrate Audit the crypto usage in this codebase
```
