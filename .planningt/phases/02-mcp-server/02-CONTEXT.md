# Phase 2: MCP Server - Context

**Gathered:** 2026-05-06
**Status:** Ready for planning
**Mode:** Auto-generated (discuss skipped via workflow.skip_discuss)

<domain>
## Phase Boundary

Build `cmd/adssh-mcp/` — a standalone binary that exposes adssh's Starlark environment and shell capabilities over the Model Context Protocol (MCP). Claude Code (or any MCP client) connects to this server and can execute Starlark, run POSIX shell commands, query cloud namespaces, inspect SSH sessions, run audited container commands, and read recent audit log entries — all evaluated by the Rego policy engine before execution.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — discuss phase was skipped per user setting. Use ROADMAP phase goal, success criteria, requirements (MCP-01 through MCP-08), and codebase conventions to guide decisions.

Key constraints from PROJECT.md and REQUIREMENTS.md:
- MCP library: `mark3labs/mcp-go` (project-approved dependency)
- Rego/OPA must evaluate every tool invocation before execution (MCP-08)
- API key auth is sufficient for v1 — no OAuth/SSO (explicitly out of scope)
- Binary is standalone: `cmd/adssh-mcp/main.go`
- MCP tools to implement: `eval_starlark`, `run_shell`, `list_sessions`, `cloud_query`, `container_exec`, `audit_log`

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `security/policy.go` — `EvaluatePolicy()` + `BuildPolicyContext()` for Rego evaluation
- `security/audit.go` — `LogCommand()`, `LogEvent()`, `LogPolicyDecision()` for audit trail
- `security/interceptor.go` — `BashInterceptor()` for shell command interception
- `starlarkext/starlarkext.go` — `SetupExtensions()` to wire Starlark namespaces
- `sys/session.go` — `GetSession()`, `ListSessions()` for SSH session registry
- `config/env.go` — `AppConfig` and `LoadFromEnv()` for configuration

### Established Patterns
- Starlark thread is created per evaluation (not persistent across tool calls)
- Policy evaluation uses `PolicyContext{User, Groups, Command, Args, SessionID, Time}`
- Audit logging via global `auditLogger` initialized in `InitAuditLog()`
- All cloud namespaces are Starlark dicts set up by `SetupExtensions()`

### Integration Points
- MCP server calls into `starlarkext.SetupExtensions()` to get the Starlark env
- Each tool invocation: build `PolicyContext` → `EvaluatePolicy()` → execute → `LogCommand()`
- `run_shell` wraps `mvdan.cc/sh` runner with `BashInterceptor` (same as REPL)
- `list_sessions` calls `sys.ListSessions()` to get active SSH sessions
- `container_exec` delegates to `containers` namespace in Starlark env
- `audit_log` tails / reads from the ADSSH_AUDIT_LOG file path

</code_context>

<specifics>
## Specific Ideas

- `adssh-mcp` should support `--policy` flag to specify a Rego policy path (same as main adssh)
- `adssh-mcp --api-key` or env `ADSSH_MCP_API_KEY` for authentication
- Tool schemas should include clear JSON parameter descriptions for Claude's tool selection
- MCP server should initialize Starlark globals once at startup, not per-call (share state)
- `eval_starlark` returns both output (stdout) and result value as separate fields
- `run_shell` returns exit code, stdout, and stderr as separate fields
- `audit_log` accepts `limit` parameter (default 50) and optional `filter` string

</specifics>

<deferred>
## Deferred Ideas

- Streaming output for long-running commands (deferred — not in v1 MCP spec)
- Per-session Starlark state isolation (deferred — share global state for v1 simplicity)
- mTLS for MCP transport (deferred — API key sufficient for v1)

</deferred>
