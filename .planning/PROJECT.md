# adssh

## What This Is

A security-first, programmable shell written in Go that fuses Starlark (Google's deterministic Python dialect) as the config/scripting language with mvdan.cc/sh for POSIX shell execution, plus a built-in SSH server. Designed for DevOps and infrastructure engineers who need a programmable, auditable, and AI-integrable shell.

## Core Value

Every shell command is auditable, policy-controlled, and scriptable from a single tool — with AI as a first-class operator.

## Requirements

### Validated

- ✓ Hybrid REPL (Starlark + POSIX shell auto-detection) — v0.x
- ✓ Built-in SSH server with public-key auth and session mirroring — v0.x
- ✓ Cloud Starlark namespaces: aws, oci, gcp, git, github, containers — v0.x
- ✓ RBAC via YAML entitlements + audit log — v0.x
- ✓ Container audit trail (ephemeral Docker, JSONL records, replay) — v0.x
- ✓ Go plugin system (.so via sys.load_plugin) — v0.x
- ✓ Virtual builtins: jq, yq, http — v0.x

### Active

- ✓ Rego/OPA policy engine replacing YAML entitlements — Validated in Phase 01: policy-engine
- ✓ MCP server (cmd/adssh-mcp/) exposing Starlark env to Claude — Validated in Phase 02: mcp-server
- [ ] Claude Code skill for operating adssh sessions
- [ ] ADSSHA agent — DevOps AI assistant living inside the shell

### Out of Scope

- Web UI — CLI/SSH-first always
- Multi-line interactive REPL — known limitation, deferred
- Plugin registry/versioning — file-path system sufficient for now
- Windows support — Linux/macOS target

## Context

- Go module: github.com/afterdarksys/adssh
- Architecture: main.go → repl → parser → security/interceptor → starlarkext
- Entitlements: security/entitlements.go (YAML RBAC, per-user/group command ACL)
- The MCP server is the integration surface for ADSSHA and the Claude Code skill
- Rego must ship before MCP — everything depends on authorization being solid
- Plugin system is fragile (exact Go toolchain match); future: Hashicorp go-plugin

## Constraints

- **Language**: Go only — no new runtime dependencies unless necessary
- **Security**: Rego/OPA policy evaluates every command with full context (user, groups, args, time, session)
- **Compatibility**: MCP server must work with Claude Code MCP client out of the box
- **Dependencies**: OPA via github.com/open-policy-agent/opa; MCP via mark3labs/mcp-go

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Starlark over Lua/Python | Deterministic, sandboxed, Bazel lineage | ✓ Good |
| mvdan.cc/sh for shell | Pure Go, no cgo, embeddable | ✓ Good |
| YAML entitlements first, Rego later | Ship fast, upgrade when policy complexity grows | — Pending |
| mark3labs/mcp-go for MCP | Most popular Go MCP server library | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-07 — Phase 04 complete (ADSSHA agent definition + sys.load_agent Starlark builtin)*
