# Roadmap: adssh

## Overview

v1.0 delivers the AI-ready layer on top of adssh's existing programmable shell foundation. The four phases follow a strict dependency chain: policy engine first (authorization must be solid before anything exposes capabilities), then the MCP server (the integration surface), then the Claude Code skill (human-readable operating instructions), then the ADSSHA agent (the AI operator that uses everything).

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Policy Engine** - Replace YAML entitlements with Rego/OPA as the authorization backend
- [ ] **Phase 2: MCP Server** - Build the adssh-mcp binary exposing shell and cloud capabilities to AI clients
- [ ] **Phase 3: Claude Code Skill** - Write the skill file that teaches Claude how to operate adssh
- [ ] **Phase 4: ADSSHA Agent** - Define the DevOps AI agent that lives inside the shell

## Phase Details

### Phase 1: Policy Engine
**Goal**: Every command is evaluated by Rego policies before execution, with full context and audit trail
**Depends on**: Nothing (first phase)
**Requirements**: POL-01, POL-02, POL-03, POL-04, POL-05, POL-06
**Success Criteria** (what must be TRUE):
  1. Administrator can write a Rego policy file and it is evaluated for every command before execution
  2. Policy context includes user, groups, command, args, time, and session ID — all accessible in Rego rules
  3. YAML entitlements are no longer the auth backend; Rego is the sole authorization source
  4. An existing YAML entitlement can be expressed as an equivalent Rego policy with the same allow/deny outcome
  5. Policy evaluation result (allow/deny/reason) appears in the audit log, and `sec.*` Starlark namespace exposes policy evaluation to scripts
**Plans**: TBD

### Phase 2: MCP Server
**Goal**: Claude (or any MCP client) can connect to adssh-mcp and execute shell, Starlark, cloud, and container operations through a policy-enforced interface
**Depends on**: Phase 1
**Requirements**: MCP-01, MCP-02, MCP-03, MCP-04, MCP-05, MCP-06, MCP-07, MCP-08
**Success Criteria** (what must be TRUE):
  1. `adssh-mcp` binary starts as a standalone process and Claude Code can connect to it as an MCP server
  2. Claude can execute Starlark expressions and POSIX shell commands through the MCP tools, both with audit logging
  3. Claude can query active SSH sessions, cloud namespaces (aws/gcp/oci), ephemeral container commands, and recent audit log entries through dedicated MCP tools
  4. Every MCP tool invocation is evaluated by the Rego policy engine before execution — unauthorized calls are rejected
**Plans**: TBD

### Phase 3: Claude Code Skill
**Goal**: Claude has a complete, accurate skill file for operating adssh — session management, scripting, cloud queries, containers, and MCP connection
**Depends on**: Phase 2
**Requirements**: SKILL-01, SKILL-02, SKILL-03
**Success Criteria** (what must be TRUE):
  1. `.claude/skills/adssh.md` exists and gives Claude actionable instructions for operating an adssh session
  2. Skill covers all four operational domains: session management, Starlark scripting, cloud queries, and container ops
  3. Skill documents how to connect to the MCP server and includes a complete tool reference with usage examples
**Plans**: TBD

### Phase 4: ADSSHA Agent
**Goal**: A DevOps AI agent definition exists that binds the ADSSHA system prompt to MCP tools and is loadable from Starlark
**Depends on**: Phase 3
**Requirements**: AGENT-01, AGENT-02, AGENT-03
**Success Criteria** (what must be TRUE):
  1. ADSSHA agent definition (system prompt + MCP tool bindings) is written and reviewable
  2. Agent acts as a DevOps AI assistant with full shell and cloud access via MCP tools
  3. `sys.load_agent("adssha")` in a Starlark session loads and activates the agent definition
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Policy Engine | 0/TBD | Not started | - |
| 2. MCP Server | 0/TBD | Not started | - |
| 3. Claude Code Skill | 0/TBD | Not started | - |
| 4. ADSSHA Agent | 0/TBD | Not started | - |
