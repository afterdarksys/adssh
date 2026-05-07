---
phase: 04-adssha-agent
plan: "02"
subsystem: starlarkext
tags: [starlark, anthropic, agent, go, tdd]
dependency_graph:
  requires: []
  provides: [sys.load_agent Starlark builtin, TOML frontmatter parser, Anthropic API integration]
  affects: [starlarkext/starlarkext.go, go.mod]
tech_stack:
  added: [github.com/anthropics/anthropic-sdk-go@v1.41.0, github.com/pelletier/go-toml/v2@v2.3.1]
  patterns: [starlark builtin factory, closure-based stateful callable, TOML frontmatter parsing]
key_files:
  created:
    - starlarkext/libagent.go
    - starlarkext/libagent_test.go
  modified:
    - starlarkext/starlarkext.go
    - go.mod
    - go.sum
decisions:
  - "sys.load_agent placed unconditionally before !restricted gate, matching sys.load_plugin precedent"
  - "Model resolution: ADSSHA_MODEL env > frontmatter model > claude-sonnet-4-6 default (D-04)"
  - "Path traversal guard rejects names containing / or .. before filepath.Join"
  - "ANTHROPIC_API_KEY value never included in error messages (T-04-04)"
metrics:
  duration: "~5 minutes"
  completed_date: "2026-05-07"
  tasks: 2
  files: 5
---

# Phase 4 Plan 02: sys.load_agent Starlark Builtin Summary

**One-liner:** Anthropic API-backed stateful agent callable via `sys.load_agent("adssha")` with TOML frontmatter parsing and path traversal protection.

## What Was Built

`sys.load_agent` is a new Starlark builtin injected into the `sysDict` alongside `sys.load_plugin`. Calling `agent = sys.load_agent("adssha")` reads `~/.adssh/agents/adssha.md`, parses its TOML `+++` frontmatter and markdown system prompt, initialises an Anthropic API client, and returns a stateful callable. Each subsequent call to `agent("task")` appends to the in-memory conversation history and returns the Claude text response as a Starlark string.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add Go dependencies and create libagent.go with createLoadAgent + parseAgentFile | 3cfbbca | starlarkext/libagent.go, starlarkext/starlarkext.go, go.mod, go.sum |
| 2 | Create unit tests for parseAgentFile, path traversal, and load_agent error cases | 2c23029 | starlarkext/libagent_test.go |

## Verification Results

- `go build ./starlarkext/...` passes
- `go test ./starlarkext/... -run "TestParseAgentFile|TestLoadAgent" -v` passes (8/8 subtests)
- All acceptance criteria met for both tasks

## Deviations from Plan

None — plan executed exactly as written.

The only notable note: `pelletier/go-toml/v2` was not visible as an indirect dependency in the go.mod snapshot seen at plan-read time; `go mod tidy` after adding both packages correctly promoted both to direct dependencies.

## Known Stubs

None. All implemented functions are wired to real behaviour.

## Threat Flags

No new threat surface beyond what was modelled in the plan's threat register (T-04-03 through T-04-07). Mitigations applied:
- T-04-03: Path traversal guard implemented — `strings.Contains(name, "/") || strings.Contains(name, "..")` check before `filepath.Join`.
- T-04-04: `ANTHROPIC_API_KEY` read from env only; value never appears in error messages.

## Self-Check: PASSED

- starlarkext/libagent.go: FOUND
- starlarkext/libagent_test.go: FOUND
- starlarkext/starlarkext.go contains `load_agent`: FOUND
- go.mod contains `anthropics/anthropic-sdk-go`: FOUND
- go.mod contains `pelletier/go-toml/v2`: FOUND
- Commit 3cfbbca: FOUND
- Commit 2c23029: FOUND
