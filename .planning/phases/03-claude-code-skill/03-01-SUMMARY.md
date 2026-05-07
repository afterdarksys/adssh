---
phase: 03-claude-code-skill
plan: "01"
subsystem: documentation
tags: [skill, mcp, reference, documentation]
dependency_graph:
  requires:
    - .planning/phases/02-mcp-server/02-01-SUMMARY.md
    - .planning/phases/02-mcp-server/02-02-SUMMARY.md
  provides:
    - .claude/adssh-reference.md
  affects:
    - .claude/skills/adssh/SKILL.md (plan 03-02 will reference this)
tech_stack:
  added: []
  patterns:
    - Claude Code skill companion reference document
    - Rego policy documentation pattern
key_files:
  created:
    - .claude/adssh-reference.md
  modified: []
decisions:
  - Reference document at .claude/adssh-reference.md (not inline in SKILL.md) for clean separation
  - All parameter names and return shapes copied verbatim from source (no invention)
  - Policy examples adapted from policy/examples/ with MCP-specific context
metrics:
  duration: "3m"
  completed: "2026-05-07"
  tasks_completed: 1
  files_created: 1
---

# Phase 3 Plan 01: Create adssh MCP Companion Reference — Summary

Complete companion reference document at `.claude/adssh-reference.md` covering all 6 MCP tools with verified parameter tables, PolicyContext fields, Rego examples, 3 workflow scenarios, and tool selection decision rule — all parameter names and return shapes verified against source code.

## What Was Built

`.claude/adssh-reference.md` — 627 lines, 7 top-level sections:

1. **MCP Setup** — 5-step fresh developer walkthrough: build binary, create policy file, configure `.mcp.json` (env-var form primary, CLI flags form as alternative), set env vars, verify. Full environment variables table (12 ADSSH_* vars from `config/env.go`).

2. **Policy System** — PolicyContext fields table (verified from `security/policy.go`), required Rego structure, dev quickstart allow-all snippet, two real Rego examples (deny-specific-tool adapted from `restrict_sudo.rego`, group-based from `ops_group_only.rego`), policy awareness guidance.

3. **Tool Selection** — 8-row decision table mapping situations to tools. Key insight documented: `cloud_query` is a shortcut for zero-argument `eval_starlark`.

4. **Tool Reference** — All 6 tools (`eval_starlark`, `run_shell`, `list_sessions`, `cloud_query`, `container_exec`, `audit_log`) with parameter tables, return format, and realistic usage examples. Return shapes copied verbatim from `tools_*.go` files.

5. **Workflows** — 3 end-to-end DevOps scenarios: investigate sessions + cloud state, shell diagnostics + container investigation, debug policy denial.

6. **Audit Trail** — Main audit log and container_audit.jsonl paths, filter pattern table.

7. **Common Pitfalls** — 5 pitfalls: cloud_query cannot pass arguments, starlark globals are shared, missing policy = allow-all fallback, container_exec requires Docker, run_shell is POSIX not bash.

## Verification Results

All acceptance criteria passed:
- File exists with all 7 required `##` sections
- All 6 tool `###` subsections present
- 58 tool name mentions (threshold: 30)
- All key content: `package adssh.authz`, `default allow = true`, `input.user`, `input.command`, `.mcp.json`, `ADSSH_MCP_API_KEY`, `ADSSH_POLICY`, `filter="denied"`, `~/.adssh/policy.rego`

## Commits

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create .claude/adssh-reference.md | 0e8763b | .claude/adssh-reference.md (created) |

## Deviations from Plan

None — plan executed exactly as written. All source files read as specified; all content derived from verified source.

## Known Stubs

None. The reference document is complete — no placeholder content.

## Threat Flags

None. The reference document contains no secrets (only env var names as placeholders, not values), and introduces no new network endpoints or auth paths.

## Self-Check: PASSED

- `.claude/adssh-reference.md` exists: FOUND
- Commit `0e8763b` exists: FOUND
