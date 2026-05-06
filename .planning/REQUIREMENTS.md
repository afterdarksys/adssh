# Requirements: adssh

**Defined:** 2026-05-06
**Core Value:** Every shell command is auditable, policy-controlled, and scriptable — with AI as a first-class operator.

## v1.0 Requirements — AI-ready layer

### Policy Engine

- [ ] **POL-01**: Administrator can write Rego policies that evaluate every command before execution
- [ ] **POL-02**: Policy context includes: user, groups, command, args, time, session ID
- [ ] **POL-03**: Rego engine replaces YAML entitlements as the authorization backend
- [ ] **POL-04**: Existing YAML entitlements can be migrated to equivalent Rego policies
- [ ] **POL-05**: Policy evaluation result (allow/deny/reason) is recorded in the audit log
- [ ] **POL-06**: sec.* Starlark namespace exposes policy evaluation to scripts

### MCP Server

- [ ] **MCP-01**: `adssh-mcp` binary starts a standalone MCP server exposing adssh capabilities
- [ ] **MCP-02**: MCP tool `eval_starlark` executes Starlark expressions in a session context
- [ ] **MCP-03**: MCP tool `run_shell` executes POSIX shell commands with audit logging
- [ ] **MCP-04**: MCP tool `list_sessions` returns active SSH session list
- [ ] **MCP-05**: MCP tool `cloud_query` runs cloud namespace operations (aws/gcp/oci)
- [ ] **MCP-06**: MCP tool `container_exec` runs audited ephemeral container commands
- [ ] **MCP-07**: MCP tool `audit_log` queries recent audit log entries
- [ ] **MCP-08**: MCP server enforces Rego policy on every tool invocation

### Claude Code Skill

- [ ] **SKILL-01**: `.claude/skills/adssh.md` skill file gives Claude instructions for operating adssh
- [ ] **SKILL-02**: Skill covers: session management, Starlark scripting, cloud queries, container ops
- [ ] **SKILL-03**: Skill documents MCP server connection and tool reference

### ADSSHA Agent

- [ ] **AGENT-01**: ADSSHA agent definition (system prompt + MCP tool bindings) is written
- [ ] **AGENT-02**: Agent acts as a DevOps AI assistant with shell and cloud access
- [ ] **AGENT-03**: Agent definition is loadable via `sys.load_agent("adssha")` in Starlark

## v2.0 Requirements (deferred)

### Plugin Registry

- **PLUG-01**: Plugin registry with versioning (migrate from file-path sys.load_plugin)
- **PLUG-02**: Plugin distribution via adssh plugin marketplace

### Multi-line REPL

- **REPL-01**: Multi-line input in interactive REPL (def foo(): blocks)
- **REPL-02**: Tab completion on SSH sessions

## Out of Scope

| Feature | Reason |
|---------|--------|
| Web UI | CLI/SSH-first always — GUI adds complexity without value for target users |
| Windows support | Linux/macOS target; POSIX shell dependency |
| OAuth / SSO for MCP | API key auth sufficient for v1 MCP access |
| Plugin gRPC migration | Hashicorp go-plugin deferred to after MCP ships |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| POL-01 | Phase 1 | Pending |
| POL-02 | Phase 1 | Pending |
| POL-03 | Phase 1 | Pending |
| POL-04 | Phase 1 | Pending |
| POL-05 | Phase 1 | Pending |
| POL-06 | Phase 1 | Pending |
| MCP-01 | Phase 2 | Pending |
| MCP-02 | Phase 2 | Pending |
| MCP-03 | Phase 2 | Pending |
| MCP-04 | Phase 2 | Pending |
| MCP-05 | Phase 2 | Pending |
| MCP-06 | Phase 2 | Pending |
| MCP-07 | Phase 2 | Pending |
| MCP-08 | Phase 2 | Pending |
| SKILL-01 | Phase 3 | Pending |
| SKILL-02 | Phase 3 | Pending |
| SKILL-03 | Phase 3 | Pending |
| AGENT-01 | Phase 4 | Pending |
| AGENT-02 | Phase 4 | Pending |
| AGENT-03 | Phase 4 | Pending |

**Coverage:**
- v1 requirements: 20 total
- Mapped to phases: 20
- Unmapped: 0 ✓

---
*Requirements defined: 2026-05-06*
*Last updated: 2026-05-06 — traceability confirmed after roadmap creation*
