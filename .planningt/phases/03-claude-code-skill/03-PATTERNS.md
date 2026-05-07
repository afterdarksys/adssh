# Phase 3: Claude Code Skill - Pattern Map

**Mapped:** 2026-05-07
**Files analyzed:** 3 new files
**Analogs found:** 2 / 3 (1 has no direct codebase analog)

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `.claude/skills/adssh/SKILL.md` | skill/trigger-doc | request-response (trigger → orient) | `~/.claude/skills/careful/SKILL.md` | exact (same role, same trigger-based pattern) |
| `.claude/adssh-reference.md` | reference-doc | N/A (consumed by Claude at load time) | `~/.claude/skills/gsd-execute-phase/SKILL.md` | partial (loaded-context pattern via `@` references) |
| `.mcp.json` | config | N/A (process startup config) | None in codebase | no analog |

---

## Pattern Assignments

### `.claude/skills/adssh/SKILL.md` (skill, trigger-based)

**Analog:** `/Users/ryan/.claude/skills/careful/SKILL.md`

**Frontmatter pattern** (lines 1–24 of analog):
```yaml
---
name: adssh
description: |
  Operate adssh sessions via MCP: session management, Starlark scripting,
  cloud queries, container execution, and audit log review. Invoke with /adssh.
triggers:
  - /adssh
  - adssh
# No allowed-tools restriction per D-02
---
```

Key observations from `careful/SKILL.md`:
- `name:` is a plain slug (no slashes)
- `description:` uses block scalar (`|`) — multiline is supported
- `triggers:` is a YAML list — multiple trigger phrases allowed
- `allowed-tools:` restricts Claude's tool set when skill is active — D-02 says to OMIT this key entirely for adssh
- `hooks:` and `version:` are optional — not needed for adssh skill

**Skill body pattern** — after frontmatter, write standard Markdown that Claude reads on trigger. From `careful/SKILL.md` the body immediately establishes the active mode and lists behaviors. Apply the same structure:

```markdown
# /adssh — adssh Session Operator

adssh MCP is now **active**. Execute the connect + orient sequence:

1. Confirm the `adssh` MCP server is available in tools list
2. Call `list_sessions` — enumerate active SSH sessions
3. Report: session count, session IDs (or "no active sessions"), and available tools

If `list_sessions` returns an MCP error, the server is not connected.
Tell the user to verify `.mcp.json` is present and `adssh-mcp` binary is built.

@.claude/adssh-reference.md
```

The `@.claude/adssh-reference.md` line at the end of the body loads the companion reference into context when the trigger fires (pattern from `gsd-execute-phase/SKILL.md` lines 35–36 which uses `@$HOME/.claude/...` references).

---

### `.claude/adssh-reference.md` (reference-doc, always-loaded on trigger)

**Analog:** `~/.claude/skills/gsd-execute-phase/SKILL.md` (loaded-context pattern)

The `gsd-execute-phase/SKILL.md` uses `@` file references in the skill body to load workflow context on trigger. The adssh reference doc follows the same approach — it is referenced from SKILL.md body via `@.claude/adssh-reference.md` so it loads when `/adssh` fires.

**Document structure** (derived from D-01 through D-11 + verified tool schemas):

```
## MCP Setup (Fresh Developer Walkthrough)
  - Build: `go build ./cmd/adssh-mcp`
  - Configure: .mcp.json with env-var form (primary) + CLI-flag form (alternative)
  - Environment variables table (all ADSSH_* vars)
  - Policy: create ~/.adssh/policy.rego with dev allow-all snippet

## Policy System
  - PolicyContext fields (input.user, input.groups, input.command, input.args, input.time, input.session_id)
  - For MCP tool calls: command = tool name, args = [], session_id = ""
  - Real allow/deny rule examples from policy/examples/
  - Dev quickstart snippet
  - Policy awareness (D-10): "access denied" = Rego blocked it; use audit_log filter="denied"

## Tool Selection Decision Rule (D-09)
  - Decision table: eval_starlark vs run_shell vs cloud_query vs others

## Tool Reference (6 tools, D-07)
  - Per tool: parameter table + one concrete realistic usage example

## Workflows (D-08)
  - 2-3 end-to-end DevOps scenarios chaining tools

## Audit Trail (D-11)
  - Every call is logged; use audit_log to review; filter by tool name

## Common Pitfalls
  - cloud_query cannot pass arguments (use eval_starlark instead)
  - Starlark globals are shared state (treat as read-only)
  - Missing policy file = allow-all fallback (confirm "Policy loaded from" in log)
  - container_exec requires Docker daemon
  - run_shell uses mvdan/sh POSIX shell, not bash
```

---

### `.mcp.json` (config, process startup)

**Analog:** None in codebase — no existing `.mcp.json` in project.

**Pattern source:** RESEARCH.md verified pattern + `cmd/adssh-mcp/main.go` lines 26–37 (flag parsing: `--policy`, `--api-key`).

**Env-var form (primary per D-05):**
```json
{
  "mcpServers": {
    "adssh": {
      "command": "/absolute/path/to/adssh-mcp",
      "env": {
        "ADSSH_MCP_API_KEY": "${ADSSH_MCP_API_KEY}",
        "ADSSH_POLICY": "${HOME}/.adssh/policy.rego"
      }
    }
  }
}
```

**CLI-flag form (alternative per D-05):**
```json
{
  "mcpServers": {
    "adssh": {
      "command": "/absolute/path/to/adssh-mcp",
      "args": ["--policy", "${HOME}/.adssh/policy.rego"]
    }
  }
}
```

Note: `adssh-mcp` binary currently exists at `./adssh-mcp` (project root). The `.mcp.json` should use an absolute path (e.g., `${PWD}/adssh-mcp`) to be robust.

---

## Shared Patterns

### Verified Tool Schemas (from RESEARCH.md — source-verified)

These exact schemas must appear verbatim in `.claude/adssh-reference.md`. Do not derive parameter names from inference — use these confirmed values.

**eval_starlark**
- Parameter: `code` (string, required)
- Returns: plain text `output: <print output>\nresult: <return value>`
- Starlark globals: `aws`, `gcp`, `oci`, `cloud`, `git`, `github`, `containers`, `crypto`, `net`, `re`, `sys`, `data`, `sec`, `i18n`
- Globals are shared state across all eval calls (initialized once at server startup)

**run_shell**
- Parameter: `command` (string, required)
- Returns: plain text `exit_code: <int>\nstdout: <string>\nstderr: <string>`
- Uses `mvdan.cc/sh/v3` — POSIX shell, not bash; `[[`, bash arrays, `(( ))` may fail

**list_sessions**
- Parameters: none
- Returns: JSON array of strings e.g. `["session-abc123"]` or `[]`

**cloud_query**
- Parameters: `namespace` (string, required: `aws`|`gcp`|`oci`|`cloud`), `function` (string, required)
- Returns: string representation of Starlark return value
- CRITICAL: calls function with NO arguments — use `eval_starlark` when arguments are needed

**container_exec**
- Parameters: `image` (string, required), `cmd` (string, required — JSON array or single string)
- Returns: JSON `{"session_id": "...", "exit_code": 0, "stdout": "...", "stderr": "...", "duration_ms": 1234}`
- Also writes `~/.adssh/container_audit.jsonl`
- Requires Docker daemon running

**audit_log**
- Parameters: `limit` (number, optional, default 50), `filter` (string, optional, no default)
- Returns: newline-separated log lines, or `(no audit log entries)` if file absent
- Pattern for denied calls: `filter="denied"` (policyGate logs denials as "access denied")

### Policy Context (from `security/policy.go` — source-verified)

Rego `input` document fields for MCP tool calls:

| Field | Type | Value for MCP calls |
|-------|------|---------------------|
| `input.user` | string | OS user |
| `input.groups` | []string | OS groups |
| `input.command` | string | Tool name (e.g., `"eval_starlark"`) |
| `input.args` | []string | Always `[]` for MCP calls |
| `input.time` | string | RFC3339 UTC timestamp |
| `input.session_id` | string | Always `""` for MCP calls |

Required Rego package structure (from `policy/default.rego` lines 4–6):
```rego
package adssh.authz
default allow = true
default deny_reason = ""
```

Allow/deny rule pattern from `policy/examples/restrict_sudo.rego`:
```rego
package adssh.authz
default allow = true
default deny_reason = ""

allow = false {
    input.command == "run_shell"    # deny specific tool by name
}
deny_reason = "shell execution not permitted" {
    input.command == "run_shell"
}
```

Group-based deny pattern from `policy/examples/ops_group_only.rego`:
```rego
package adssh.authz
default allow = false
default deny_reason = "only members of the ops group may run commands"

allow {
    some group in input.groups
    group == "ops"
}
```

### Env Vars (from `config/env.go` — source-verified)

| Env Var | Default | Purpose |
|---------|---------|---------|
| `ADSSH_MCP_API_KEY` | (none) | API key (read in `main.go` line 26) |
| `ADSSH_POLICY` | `~/.adssh/policy.rego` | Rego policy file path |
| `ADSSH_AUDIT_LOG` | `~/.adssh/audit.log` | Audit log file path |
| `ADSSH_RESTRICTED` | `0` | Sandboxed mode (`1`/`true`/`yes` to enable) |
| `ADSSH_SERVE` | (none) | SSH server listen address |
| `ADSSH_HOST_KEY` | `~/.adssh/host_key` | SSH host key path |
| `ADSSH_AUTHORIZED_KEYS` | `~/.adssh/authorized_keys` | SSH authorized keys path |
| `ADSSH_PROFILE` | `~/.adsshprofile` | Login profile script |
| `ADSSH_RC` | `~/.adsshrc` | Interactive RC script |
| `ADSSH_AUDIT_URL` | (none) | Webhook URL for SIEM logging |
| `ADSSH_AUDIT_TOKEN` | (none) | Bearer token for audit webhook |
| `ADSSH_ENTITLEMENTS` | (none) | Legacy YAML entitlements (deprecated) |

### Startup Sequence (from `main.go` lines 21–58)

The reference doc's setup walkthrough should match this exact startup sequence:
1. Load config from `ADSSH_*` env vars (`config.LoadFromEnv()`)
2. Parse CLI flags `--policy` and `--api-key` (override env vars if provided)
3. Init audit logging (`security.InitAuditLog`)
4. Load Rego policy (`security.LoadPolicy`) — missing file = allow-all (no error)
5. Build Starlark globals once (shared across all eval calls)
6. Start MCP server

Startup confirmation: look for `"Policy loaded from <path>"` in the audit log after starting.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `.mcp.json` | config | N/A | No MCP server config files exist in this project yet; use RESEARCH.md pattern |

---

## Metadata

**Analog search scope:** `~/.claude/skills/` (existing skill examples), `cmd/adssh-mcp/` (source truth for tool schemas), `policy/` (Rego patterns), `config/env.go` (env vars)
**Files read:** `careful/SKILL.md`, `gsd-execute-phase/SKILL.md`, `main.go`, `policy/default.rego`, `policy/examples/ops_group_only.rego`, `policy/examples/restrict_sudo.rego`
**Pattern extraction date:** 2026-05-07
