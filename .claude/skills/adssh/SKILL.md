---
name: adssh
description: |
  Operate adssh sessions via MCP: session management, Starlark scripting,
  cloud queries, container execution, and audit log review. Invoke with /adssh.
triggers:
  - /adssh
  - adssh
---

# /adssh -- adssh Session Operator

adssh MCP is now **active**. Execute the connect + orient sequence:

1. Confirm the `adssh` MCP server is available in your tools list
2. Call `list_sessions` to enumerate active SSH sessions
3. Report a situational briefing:
   - Number of active sessions and their IDs (or "no active sessions")
   - Available adssh tools: eval_starlark, run_shell, list_sessions, cloud_query, container_exec, audit_log
   - Ready status: "adssh operator ready"

If `list_sessions` returns an MCP error, the server is not connected.
Tell the user to verify:
- `.mcp.json` is present in the project root with the adssh server entry
- `adssh-mcp` binary is built (`go build -o adssh-mcp ./cmd/adssh-mcp`)
- Required env vars are set (at minimum `ADSSH_POLICY` pointing to a .rego file)

## Quick Reference

**Tool selection:**
- Cloud operations with arguments: `eval_starlark`
- Simple zero-arg cloud function: `cloud_query`
- Shell one-liners, file ops, grep/awk: `run_shell`
- Ephemeral container commands: `container_exec`
- Review activity or debug denials: `audit_log`

**Policy awareness:** All tool calls are gated by Rego policy. "access denied" means a policy rule blocked it. Use `audit_log` with `filter="denied"` to investigate.

**Audit trail:** Every tool call is logged. Use `audit_log` to review your history.

@.claude/adssh-reference.md
