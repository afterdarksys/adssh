---
phase: 04-adssha-agent
plan: "01"
subsystem: agent-definition
tags: [agent, mcp, devops-ai, system-prompt, starlark]
dependency_graph:
  requires: []
  provides: [agents/adssha.md]
  affects: [sys.load_agent (future plan 04-02)]
tech_stack:
  added: []
  patterns: [TOML +++ frontmatter markdown, agent definition format]
key_files:
  created:
    - agents/adssha.md
  modified: []
decisions:
  - "D-05 format honored: TOML +++ frontmatter delimiters (not YAML ---)"
  - "Horizontal rules use *** not --- to avoid ambiguity with YAML frontmatter"
  - "System prompt complements SKILL.md (operator skill) rather than duplicating it — ADSSHA is an AI persona, not an operator guide"
metrics:
  duration: "2m 20s"
  completed: "2026-05-07"
  tasks_completed: 1
  tasks_total: 1
  files_created: 1
  files_modified: 0
---

# Phase 4 Plan 01: ADSSHA Agent Definition Summary

## One-liner

ADSSHA agent definition in TOML+markdown format with identity, 6-tool catalogue, autonomy rules (read-free/write-confirm), error recovery via audit_log, and 4 multi-step DevOps workflow patterns.

## What Was Built

Created `agents/adssha.md` — the canonical agent definition file for ADSSHA, the DevOps AI assistant embedded in the adssh programmable shell.

The file serves dual duty per D-01:
- **Inbound**: Claude reads it to know how to behave when connected via MCP (the system prompt is the persona)
- **Outbound**: `sys.load_agent("adssha")` reads it to initialize a programmatic Claude callable from within Starlark

### File Structure

**TOML frontmatter** (delimited by `+++` per D-05):
```toml
name = "adssha"
model = "claude-sonnet-4-6"
mcp_server = "adssh"
tools = ["eval_starlark", "run_shell", "list_sessions", "cloud_query", "container_exec", "audit_log"]
```

**System prompt body sections:**
1. Identity — DevOps AI in adssh, multi-step orchestration as primary value
2. Tool Catalogue — one subsection per tool with use-cases, parameters, pitfalls, examples
3. Autonomy Rules — read-only ops run freely; destructive ops require describe+confirm
4. Error Handling — access denied flow (audit_log + policy.rego), tool failure recovery
5. Multi-Step Workflow Patterns — 4 complete workflows (infra investigation, policy debug, container diagnostics, cloud multi-namespace)
6. Policy Awareness — Rego context, verify policy loaded, cannot modify policies
7. Starlark Globals Note — treat as read-only, use local vars

## Verification Results

All checks passed:
- `test -f agents/adssha.md` — file exists
- `head -1 agents/adssha.md` outputs `+++`
- `grep 'name = "adssha"'` matches
- All 6 tool names present (eval_starlark: 14, run_shell: 10, list_sessions: 6, cloud_query: 7, container_exec: 7, audit_log: 13 occurrences)
- No `---` YAML delimiters (14 `***` horizontal rules used instead)
- No secrets or credentials embedded (threat T-04-02 mitigated)

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written with one minor adjustment.

**Adjustment (not a deviation, just clarification):** The plan acceptance criterion says "File does NOT use `---` YAML delimiters". The initial draft used `---` as markdown horizontal rule separators (section dividers in the body), not as YAML frontmatter markers. To avoid any ambiguity and ensure the automated verification check passes cleanly, all horizontal rules were changed from `---` to `***`. Both are valid CommonMark horizontal rules.

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes introduced. The file is a static markdown document.

**T-04-02 mitigated:** Verified no `ANTHROPIC_API_KEY=`, passwords, or credential values embedded in the agent definition. The file correctly references env vars by name only (as documentation guidance), never assigns them.

No new threat flags beyond what was already in the plan's threat model.

## Known Stubs

None — this plan creates a static definition file, not a UI component or data-wired feature.

## Self-Check

- [x] `agents/adssha.md` exists at absolute path
- [x] Commit `35703cf` exists in git log
- [x] SUMMARY.md created at `.planning/phases/04-adssha-agent/04-01-SUMMARY.md`
- [x] No modifications to STATE.md or ROADMAP.md

## Self-Check: PASSED
