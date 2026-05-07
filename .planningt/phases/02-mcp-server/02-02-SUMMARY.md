---
phase: 02-mcp-server
plan: "02"
subsystem: cmd/adssh-mcp
tags: [mcp, sessions, cloud, containers, audit, security, policy]
dependency_graph:
  requires: [security/audit.go, sys/session.go, starlarkext/containers.go, config/env.go, cmd/adssh-mcp/server.go]
  provides: [list_sessions MCP tool, cloud_query MCP tool, container_exec MCP tool, audit_log MCP tool]
  affects: [cmd/adssh-mcp binary, Claude Code MCP client integration]
tech_stack:
  added: []
  patterns: [policyGate middleware, Docker ephemeral container lifecycle, Starlark dict namespace access, audit JSONL append]
key_files:
  created:
    - cmd/adssh-mcp/tools_sessions.go
    - cmd/adssh-mcp/tools_cloud.go
    - cmd/adssh-mcp/tools_container.go
    - cmd/adssh-mcp/tools_audit.go
  modified:
    - cmd/adssh-mcp/server.go
decisions:
  - "Used req.GetFloat/GetString accessor methods instead of directly indexing req.Params.Arguments (typed as any)"
  - "container_exec writes to same container_audit.jsonl path as starlarkext/containers.go for consistent audit trail"
  - "audit_log uses substring filter only (no regex) to prevent regex injection - matches threat model T-02-09"
metrics:
  duration: "~2 minutes"
  completed: "2026-05-07"
  tasks_completed: 2
  files_created: 4
  files_modified: 1
---

# Phase 2 Plan 02: Remaining MCP Tools Summary

**One-liner:** Four new policyGate-wrapped MCP tools (list_sessions, cloud_query, container_exec, audit_log) completing the six-tool MCP surface for full Claude Code integration with adssh.

## What Was Built

Added four MCP tool handler files and updated `server.go` to register all six tools.

### list_sessions (tools_sessions.go)

Calls `sys.ListSessions()` from the global session registry and marshals the result as a JSON array. Returns an empty array `[]` when no sessions are active. Calls `security.LogCommand("MCP:list_sessions", "")` for audit trail.

### cloud_query (tools_cloud.go)

Accepts `namespace` and `function` parameters. Validates the namespace exists in the shared Starlark `globals` dict and is a `*starlark.Dict`. Validates the function key exists and is a `starlark.Callable`. Creates a fresh `starlark.Thread{Name: "mcp-cloud"}` per call (never reused). Returns the Starlark result's `.String()` representation. Calls `security.LogCommand("MCP:cloud_query", ...)` on both success and error paths.

### container_exec (tools_container.go)

Accepts `image` (Docker image name) and `cmd` (JSON array or whitespace-delimited string). Generates a random session ID, creates a Docker client via `client.NewClientWithOpts(client.FromEnv, ...)`, pulls the image, creates a labeled ephemeral container (`adssh.managed=true`), starts it, waits for exit, captures stdout/stderr via `stdcopy.StdCopy`, removes the container, and writes an audit record to `~/.adssh/container_audit.jsonl` (same path and JSONL format as `starlarkext/containers.go`). Returns structured JSON with `session_id`, `exit_code`, `stdout`, `stderr`, `duration_ms`.

### audit_log (tools_audit.go)

Accepts `limit` (default 50, via `req.GetFloat`) and optional `filter` (substring, via `req.GetString`). Reads `cfg.AuditLogPath` with `os.ReadFile`, splits on newlines, applies substring filter if provided, tails to last `limit` lines. Returns `(no audit log entries)` text if the file does not exist. Calls `security.LogCommand("MCP:audit_log", ...)`.

### server.go updates

All four tools registered with `mcp.NewTool(...)` + `policyGate(...)`. Full tool schema with parameter descriptions. All six tools (eval_starlark, run_shell, list_sessions, cloud_query, container_exec, audit_log) are now policyGate-wrapped.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | bc2862f | feat(02-02): add list_sessions, cloud_query, container_exec, and audit_log tool handlers |
| 2 | 1b6f479 | feat(02-02): register list_sessions, cloud_query, container_exec, audit_log in server.go |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] req.Params.Arguments direct indexing fails at compile time**
- **Found during:** Task 1 (build verification)
- **Issue:** `tools_audit.go` used `req.Params.Arguments["limit"]` and `req.Params.Arguments["filter"]` but `Arguments` is typed as `any` (not `map[string]any`), causing compile errors.
- **Fix:** Replaced with `req.GetFloat("limit", 50)` and `req.GetString("filter", "")` — the idiomatic accessor methods provided by the mcp-go library (`CallToolRequest.GetFloat`, `CallToolRequest.GetString`).
- **Files modified:** cmd/adssh-mcp/tools_audit.go
- **Commit:** bc2862f (fix applied before commit)

## Threat Model Coverage

All `mitigate` dispositions from the plan's threat register are implemented:

| Threat ID | Mitigation | Status |
|-----------|-----------|--------|
| T-02-07 (Tampering - cloud namespace injection) | Namespace validated against globals dict; callable type-checked before Call; policyGate wraps entire handler | Implemented |
| T-02-08 (Elevation - container arbitrary images) | policyGate evaluates Rego before execution; containers ephemeral with adssh.managed labels; removed after exit | Implemented |
| T-02-09 (Information Disclosure - audit log) | policyGate on audit_log tool; filter is substring only (no regex injection surface) | Implemented |

`accept` dispositions (T-02-10 image supply chain, T-02-11 container resource limits) acknowledged per plan.

## Known Stubs

None. All tools are fully wired: policyGate -> Rego -> handler -> sys/docker/file/starlark -> audit log.

## Threat Flags

None. No new network endpoints. All trust boundaries addressed in plan threat model.

## Self-Check: PASSED

| Check | Result |
|-------|--------|
| cmd/adssh-mcp/tools_sessions.go exists | FOUND |
| cmd/adssh-mcp/tools_cloud.go exists | FOUND |
| cmd/adssh-mcp/tools_container.go exists | FOUND |
| cmd/adssh-mcp/tools_audit.go exists | FOUND |
| cmd/adssh-mcp/server.go modified | FOUND |
| Commit bc2862f exists | FOUND |
| Commit 1b6f479 exists | FOUND |
| go build ./cmd/adssh-mcp/ | PASSED |
| go vet ./cmd/adssh-mcp/ | PASSED |
| grep -c 'mcp.NewTool(' server.go == 6 | PASSED |
| handleListSessions in tools_sessions.go | FOUND |
| handleCloudQuery in tools_cloud.go | FOUND |
| handleContainerExec in tools_container.go | FOUND |
| handleAuditLog in tools_audit.go | FOUND |
