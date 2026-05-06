---
phase: 01-policy-engine
plan: 03
subsystem: starlarkext, policy/examples
tags: [starlark, rego, opa, policy, migration]
dependency_graph:
  requires: [01-01, 01-02]
  provides: [sec.check_policy builtin, example Rego policies, YAML migration guide]
  affects: [starlarkext/sec.go, policy/examples/]
tech_stack:
  added: []
  patterns: [starlark builtin registration, OPA Rego examples]
key_files:
  created:
    - policy/examples/restrict_sudo.rego
    - policy/examples/ops_group_only.rego
    - policy/examples/migrate-from-yaml.rego
  modified:
    - starlarkext/sec.go
decisions:
  - check_policy passes nil args and empty sessionID — scripts probe by command name only
  - example files are documentation only — not auto-loaded from examples directory
metrics:
  duration: 10m
  completed: 2026-05-06
  tasks_completed: 2
  files_changed: 4
---

# Phase 01 Plan 03: sec.check_policy Builtin and Example Rego Policies Summary

**One-liner:** Starlark sec.check_policy builtin calling OPA EvaluatePolicy, plus three example Rego policies covering sudo restriction, group access, and YAML-to-Rego migration.

## What Was Built

**Task 1: sec.check_policy Starlark builtin** (commit `06b0b17`)

Added `builtinSecCheckPolicy` to `starlarkext/sec.go`:
- Incremented `starlark.NewDict(3)` to `NewDict(4)` in `SetupSecurityAPI`
- Registered `check_policy` key in the sec dict
- Calls `security.BuildPolicyContext(command, nil, "")` then `security.EvaluatePolicy`
- Returns Starlark dict `{"allowed": bool, "reason": string}`

**Task 2: Example and migration Rego policies** (commit `347895e`)

Created three files in `policy/examples/`:
- `restrict_sudo.rego` — denies the `sudo` command for all users
- `ops_group_only.rego` — only members of the `ops` group may execute
- `migrate-from-yaml.rego` — maps YAML entitlement patterns (per-user/group allow/deny lists) to equivalent Rego rules with inline commentary

## Deviations from Plan

None — plan executed exactly as written.

Note: `go build ./...` fails on `example_plugin` (pre-existing issue — function main undeclared). This is not caused by plan changes. All other packages build and vet cleanly.

## Threat Surface Scan

No new trust boundaries introduced beyond those documented in the plan's threat model. `check_policy` is read-only evaluation only — cannot execute commands or modify policy state (T-01-09 mitigated).

## Self-Check: PASSED

- starlarkext/sec.go: present, builds, check_policy registered
- policy/examples/restrict_sudo.rego: present, package adssh.authz
- policy/examples/ops_group_only.rego: present, package adssh.authz
- policy/examples/migrate-from-yaml.rego: present, package adssh.authz
- Commits 06b0b17 and 347895e: verified in git log
