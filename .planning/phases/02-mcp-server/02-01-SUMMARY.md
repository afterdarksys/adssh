---
phase: 02-mcp-server
plan: "01"
subsystem: cmd/adssh-mcp
tags: [mcp, starlark, shell, security, policy]
dependency_graph:
  requires: [security/policy.go, security/audit.go, security/interceptor.go, starlarkext/starlarkext.go, config/env.go]
  provides: [cmd/adssh-mcp binary, eval_starlark MCP tool, run_shell MCP tool]
  affects: [Claude Code MCP client integration]
tech_stack:
  added: [github.com/mark3labs/mcp-go v0.52.0]
  patterns: [stdio MCP transport, policyGate middleware wrapper, thread-per-call Starlark, separate stdout/stderr buffers]
key_files:
  created:
    - cmd/adssh-mcp/main.go
    - cmd/adssh-mcp/server.go
    - cmd/adssh-mcp/tools_eval.go
    - cmd/adssh-mcp/tools_shell.go
  modified:
    - go.mod
    - go.sum
decisions:
  - "Combined Tasks 1 and 2 into single commit because tool files were required for binary to link at build time"
  - "policyGate is a reusable middleware wrapper so Rego enforcement is DRY across all tools"
  - "stdio transport used because Claude Code spawns MCP server as subprocess"
  - "API key accepted but not enforced at transport layer; Rego handles per-call authz"
metrics:
  duration: "~8 minutes"
  completed: "2026-05-07"
  tasks_completed: 2
  files_created: 4
  files_modified: 2
---

# Phase 2 Plan 01: MCP Server Core and Execution Tools Summary

**One-liner:** stdio MCP server binary with eval_starlark and run_shell tools, both Rego policy-gated via policyGate middleware using mark3labs/mcp-go.

## What Was Built

Created the `adssh-mcp` binary in `cmd/adssh-mcp/` — a stdio MCP server that Claude Code connects to as a subprocess. The binary exposes two tools through a policy-enforced interface:

- **eval_starlark**: Executes Starlark code in the shared adssh environment. Uses `starlark.ExecFile` for multi-statement support, thread-per-call isolation, and captures print output separately from return values.
- **run_shell**: Executes POSIX shell commands via mvdan.cc/sh with separate stdout/stderr buffers, BashInterceptor for per-subcommand Rego enforcement, and VirtualOpenHandler for file access control.

Both tools pass through `policyGate` — a reusable middleware wrapper that calls `security.EvaluatePolicy` before any execution, logs the policy decision via `security.LogPolicyDecision`, and returns structured error results on denial.

## Startup Init Sequence

`main.go` follows the established codebase pattern:
1. `config.LoadFromEnv()` — load ADSSH_* env vars
2. Parse `--policy` and `--api-key` flags (override env)
3. `security.InitAuditLog()` — init audit trail
4. `security.LoadPolicy()` — load Rego policy engine
5. `starlarkext.SetupExtensions()` — build shared Starlark globals
6. `serveMCP()` — register tools, start stdio transport

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1+2 combined | b871cbc | feat(02-01): add mcp-go dependency and create adssh-mcp binary core |

## Deviations from Plan

### Combined Tasks

**1. [Rule 3 - Blocking] Tasks 1 and 2 implemented in single commit**
- **Found during:** Task 1
- **Issue:** The `server.go` references `handleEvalStarlark` and `handleRunShell` by name. Without those functions defined in `tools_eval.go` and `tools_shell.go`, the package fails to link. Task 1 alone could not produce a compilable binary.
- **Fix:** Created all four files together so `go build ./cmd/adssh-mcp/` could be verified as a single unit.
- **Files modified:** cmd/adssh-mcp/tools_eval.go, cmd/adssh-mcp/tools_shell.go
- **Commit:** b871cbc

## Threat Model Coverage

All `mitigate` dispositions from the plan's threat register are implemented:

| Threat ID | Mitigation | Status |
|-----------|-----------|--------|
| T-02-01 (Spoofing) | ADSSH_MCP_API_KEY env var accepted; policyGate calls EvaluatePolicy with user identity | Implemented |
| T-02-02 (Tampering) | BashInterceptor in handleRunShell evaluates Rego on each subcommand | Implemented |
| T-02-03 (Elevation) | Every tool invocation passes policyGate before execution | Implemented |
| T-02-06 (Repudiation) | LogCommand + LogPolicyDecision called in every handler and policyGate | Implemented |

`accept` dispositions (T-02-04 globals by design, T-02-05 no timeouts in v1) acknowledged.

## Known Stubs

None. All tools are fully wired: policyGate -> Rego -> handler -> starlark/shell execution -> audit log.

## Threat Flags

None. No new network endpoints beyond the stdio transport specified in the plan. All trust boundaries (MCP client input, shell exec, Starlark VM) are addressed in the plan's threat model.

## Self-Check: PASSED

| Check | Result |
|-------|--------|
| cmd/adssh-mcp/main.go exists | FOUND |
| cmd/adssh-mcp/server.go exists | FOUND |
| cmd/adssh-mcp/tools_eval.go exists | FOUND |
| cmd/adssh-mcp/tools_shell.go exists | FOUND |
| Commit b871cbc exists | FOUND |
| go build ./cmd/adssh-mcp/ | PASSED |
| go vet ./cmd/adssh-mcp/ | PASSED |
