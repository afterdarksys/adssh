# Phase 3: Claude Code Skill - Context

**Gathered:** 2026-05-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Write the Claude Code skill for operating adssh: a trigger-based `SKILL.md` at `.claude/skills/adssh/SKILL.md` (activates via `/adssh`) plus a companion reference document always loaded into context. The skill teaches Claude how to connect to the adssh MCP server, operate all 6 tools, and understand the policy/audit system.

**Deliverables:**
1. `.claude/skills/adssh/SKILL.md` — trigger-based skill with `/adssh` slash command (connect + orient behavior)
2. A companion reference document (e.g. `.claude/adssh-reference.md` or included inline) that is always loaded when working in adssh

**Out of scope:** Changes to the MCP server binary, new MCP tools, policy engine changes, ADSSHA agent definition (Phase 4).

</domain>

<decisions>
## Implementation Decisions

### Skill Format
- **D-01:** Implement **both** a trigger-based skill AND a companion reference — not one or the other.
- **D-02:** SKILL.md frontmatter should declare `name: adssh`, trigger on `/adssh`, and allow **all tools** (no allowed-tools restriction).
- **D-03:** When `/adssh` is invoked, Claude should: check MCP connection status, list active SSH sessions, and give a situational briefing so it's ready to operate — "connect + orient" mode.

### MCP Setup Documentation
- **D-04:** Primary reader of the setup section is a **developer setting up fresh** — include full walkthrough (build binary, configure `.mcp.json`, set env vars, point to policy file).
- **D-05:** Show **both** the env-var approach (primary) and CLI flags (as alternative) for `.mcp.json` configuration. Env vars are preferred (no secrets in args array).
- **D-06:** Include a **full policy walkthrough** — explain the PolicyContext structure, show a real allow/deny rule example, reference `policy/examples/` for more complex rules. Include a dev quickstart allow-all snippet so devs can get started immediately.

### Example Style
- **D-07:** Each of the 6 MCP tools gets: parameter table + one concrete realistic usage example.
- **D-08:** Include a separate **Workflows section** with **2-3 end-to-end DevOps scenarios** that show tools chaining together (e.g. list sessions → eval_starlark for cloud query → container_exec to investigate → audit_log to review).

### Tool Selection Guidance
- **D-09:** Include an explicit **tool selection decision rule**:
  - Use `eval_starlark` when you need cloud namespace access (`aws.`, `gcp.`, `oci.`), Starlark builtins, or want to compose results programmatically
  - Use `run_shell` for POSIX pipelines, grep, file operations, system commands, and anything that's easier to express as a shell one-liner
  - Use `cloud_query` directly for single cloud namespace function calls (simpler than eval_starlark for one-off cloud ops)
- **D-10:** Include a **policy awareness section**: all tools are policy-gated by Rego before execution; "access denied" means a Rego rule blocked it; use `audit_log` with `filter="denied"` to see what was blocked; policy file is at `~/.adssh/policy.rego` and can be updated.
- **D-11:** Include an **audit trail awareness note**: every tool call is logged; Claude can use `audit_log` to review recent activity and filter by tool name to see its own history.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### MCP Server (built in Phase 2)
- `cmd/adssh-mcp/server.go` — Tool registration with policyGate wrapper; all 6 tools and their parameter schemas
- `cmd/adssh-mcp/main.go` — Binary startup flags (`--policy`, `--api-key`) and env var list
- `cmd/adssh-mcp/tools_eval.go` — eval_starlark implementation (what it returns: output + result)
- `cmd/adssh-mcp/tools_shell.go` — run_shell implementation (what it returns: exit_code + stdout + stderr)
- `cmd/adssh-mcp/tools_sessions.go` — list_sessions implementation
- `cmd/adssh-mcp/tools_cloud.go` — cloud_query implementation (namespace + function parameters)
- `cmd/adssh-mcp/tools_container.go` — container_exec implementation (image + cmd parameters, returns session_id + exit_code + stdout + stderr + duration_ms)
- `cmd/adssh-mcp/tools_audit.go` — audit_log implementation (limit + filter parameters)

### Configuration
- `config/env.go` — Full list of ADSSH_* environment variables with defaults

### Policy Engine
- `policy/default.rego` — Default policy file that ships with adssh (reference for setup section)
- `policy/examples/` — Example Rego policies showing real allow/deny rules
- `security/policy.go` — PolicyContext structure (User, Groups, Command, Args, SessionID, Time fields)

### Existing Skill Examples (for format reference)
- `~/.claude/skills/careful/SKILL.md` — Example of a trigger-based skill with hooks
- `~/.claude/skills/gsd-execute-phase/SKILL.md` — Example of a more complex skill with objectives

### Phase Context
- `.planning/phases/02-mcp-server/02-CONTEXT.md` — Phase 2 decisions (MCP tool list, policy integration approach)
- `.planning/REQUIREMENTS.md` §SKILL-01, SKILL-02, SKILL-03 — Requirements this phase must satisfy

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `cmd/adssh-mcp/server.go` — Complete tool registry with all 6 tool names, descriptions, and parameter schemas — copy these verbatim into the skill's tool reference section
- `config/env.go` — Authoritative list of all ADSSH_* env vars with defaults — use for setup walkthrough
- `policy/default.rego` — Existing default policy to reference in the setup section
- `policy/examples/` — Real Rego examples for the policy walkthrough

### Established Patterns
- MCP server is a standalone binary: `cmd/adssh-mcp/main.go` → `adssh-mcp`
- All tool calls: `policyGate` checks Rego → tool executes → `security.LogCommand()` logs
- Starlark globals are shared across all tool calls (initialized once at server startup)
- Cloud namespaces available in eval_starlark: `aws`, `gcp`, `oci`, `git`, `github`, `containers`

### Integration Points
- `.claude/skills/` directory needs to be created (doesn't exist yet in the project)
- Skill is consumed by Claude Code's skill system — must follow SKILL.md frontmatter format
- `.mcp.json` (or `.claude/settings.json` `mcpServers` block) is where Claude Code registers the adssh-mcp binary

</code_context>

<specifics>
## Specific Ideas

- Binary name is `adssh-mcp` (built from `cmd/adssh-mcp/`)
- Default policy path: `~/.adssh/policy.rego`
- Default audit log path: `~/.adssh/audit.log`
- API key via env: `ADSSH_MCP_API_KEY`
- The connect + orient action for `/adssh` should call `list_sessions` to show what's active
- Workflows section should include realistic DevOps scenarios — e.g.: (1) inspect SSH sessions + run AWS cost query, (2) run shell command + investigate with ephemeral container, (3) review audit log after a policy denial
- Policy walkthrough should include a minimal allow-all dev policy:
  ```rego
  package adssh.authz
  default allow = true
  ```

</specifics>

<deferred>
## Deferred Ideas

- None — discussion stayed within phase scope.

</deferred>

---

*Phase: 3-Claude Code Skill*
*Context gathered: 2026-05-07*
