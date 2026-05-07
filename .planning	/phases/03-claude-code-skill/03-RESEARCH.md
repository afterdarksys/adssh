# Phase 3: Claude Code Skill - Research

**Researched:** 2026-05-07
**Domain:** Claude Code skill authoring / documentation writing
**Confidence:** HIGH

---

## Summary

Phase 3 is a documentation-authoring phase, not a code-writing phase. The deliverable is two files: a trigger-based `SKILL.md` (the Claude Code skill file) and a companion reference document. All content to populate these files already exists in the Phase 2 implementation — the research task is extracting it accurately from the codebase.

The Claude Code skill format is well-understood from existing examples (`careful/SKILL.md`, `gsd-execute-phase/SKILL.md`). The frontmatter uses YAML with `name`, `description`, `triggers`, and `allowed-tools` keys. The skill body is Markdown that Claude reads when the trigger fires. No code, no binary, no tests — this phase is entirely authoring.

The most important research finding is that all 6 tool implementations have been verified directly from source. Parameter names, return field names, and error messages are now confirmed, so the tool reference in the skill file can be exact.

**Primary recommendation:** Write the SKILL.md and companion reference by reading directly from the canonical source files verified in this research. Do not invent parameter names or return shapes — use the exact values confirmed below.

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Implement both a trigger-based skill AND a companion reference — not one or the other.
- **D-02:** SKILL.md frontmatter should declare `name: adssh`, trigger on `/adssh`, and allow all tools (no allowed-tools restriction).
- **D-03:** When `/adssh` is invoked, Claude should: check MCP connection status, list active SSH sessions, and give a situational briefing — "connect + orient" mode.
- **D-04:** Primary reader of the setup section is a developer setting up fresh — include full walkthrough (build binary, configure `.mcp.json`, set env vars, point to policy file).
- **D-05:** Show both the env-var approach (primary) and CLI flags (as alternative) for `.mcp.json` configuration. Env vars are preferred (no secrets in args array).
- **D-06:** Include a full policy walkthrough — explain the PolicyContext structure, show a real allow/deny rule example, reference `policy/examples/` for more complex rules. Include a dev quickstart allow-all snippet.
- **D-07:** Each of the 6 MCP tools gets: parameter table + one concrete realistic usage example.
- **D-08:** Include a separate Workflows section with 2-3 end-to-end DevOps scenarios that show tools chaining together.
- **D-09:** Include an explicit tool selection decision rule (eval_starlark vs run_shell vs cloud_query).
- **D-10:** Include a policy awareness section: all tools are policy-gated by Rego; "access denied" means a Rego rule blocked it; use `audit_log` with `filter="denied"` to see blocked calls; policy at `~/.adssh/policy.rego`.
- **D-11:** Include an audit trail awareness note: every tool call is logged; Claude can use `audit_log` to review recent activity and filter by tool name.

### Claude's Discretion

- None specified — all content decisions were locked in discussion.

### Deferred Ideas (OUT OF SCOPE)

- None — discussion stayed within phase scope.
- Changes to the MCP server binary, new MCP tools, policy engine changes, ADSSHA agent definition (Phase 4) are all out of scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SKILL-01 | `.claude/skills/adssh.md` skill file gives Claude instructions for operating adssh | Skill format confirmed from `careful/SKILL.md` and `gsd-execute-phase/SKILL.md`; deliverable path is `.claude/skills/adssh/SKILL.md` per D-01 discussion |
| SKILL-02 | Skill covers: session management, Starlark scripting, cloud queries, container ops | All 4 domains covered by the 6 tools verified from source; `list_sessions`, `eval_starlark`, `cloud_query`, `container_exec` are the primary tools per domain |
| SKILL-03 | Skill documents MCP server connection and tool reference | `.mcp.json` connection pattern documented below; all 6 tool schemas verified from `server.go` |
</phase_requirements>

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Skill activation / trigger | Claude Code skill system | — | Frontmatter `triggers` key fires when user types `/adssh` |
| Connect + orient behavior | Skill body (instructions to Claude) | MCP tool: `list_sessions` | SKILL.md instructs Claude what to do on trigger; `list_sessions` does the actual lookup |
| Tool reference documentation | Companion reference doc | SKILL.md (summarized) | Reference is always-loaded; SKILL.md is trigger-loaded |
| MCP server registration | `.mcp.json` in project root | Env vars | Claude Code reads `.mcp.json` to know how to launch the binary |
| Policy enforcement | MCP server (`policyGate`) | `~/.adssh/policy.rego` | Server-side, not skill-side — skill only needs to document this |
| Audit logging | MCP server (`security.LogCommand`) | `~/.adssh/audit.log` | Server-side; skill documents how to query via `audit_log` tool |

---

## Standard Stack

### Core: No Libraries Required

This phase produces Markdown files only. There is no code to write. The "stack" is the existing Phase 2 binary and Claude Code's skill system.

| Component | Version / Path | Purpose |
|-----------|---------------|---------|
| `adssh-mcp` binary | Already built at `./adssh-mcp` | The MCP server that Claude connects to |
| Claude Code skill system | N/A | Reads SKILL.md frontmatter + body on trigger |
| `.mcp.json` | New file at project root | Tells Claude Code how to start `adssh-mcp` |

---

## Architecture Patterns

### Skill File Layout (Verified from `careful/SKILL.md`)

```
.claude/
└── skills/
    └── adssh/
        └── SKILL.md          # trigger-based, fires on /adssh
.claude/
└── adssh-reference.md        # or inline in SKILL.md; always-loaded companion
```

The CONTEXT.md specifies `.claude/skills/adssh/SKILL.md` as the deliverable. The companion reference location is Claude's discretion (D-01 says "both" but D-01 doesn't lock the companion path).

### SKILL.md Frontmatter Pattern (Verified from `careful/SKILL.md`)

```yaml
---
name: adssh
description: |
  Operate adssh sessions via MCP: session management, Starlark scripting,
  cloud queries, container execution, and audit log review. Invoke with /adssh.
triggers:
  - /adssh
  - adssh
# No allowed-tools restriction per D-02
---
```

Key observations from existing skills:
- `careful/SKILL.md` uses `allowed-tools` (restricts to Bash + Read)
- `gsd-execute-phase/SKILL.md` uses `allowed-tools` with many tools listed
- D-02 explicitly says NO allowed-tools restriction for adssh skill
- `triggers` is a list — can match `/adssh` (slash command) and plain `adssh`

### MCP Registration Pattern (`.mcp.json`)

```json
{
  "mcpServers": {
    "adssh": {
      "command": "/path/to/adssh-mcp",
      "env": {
        "ADSSH_MCP_API_KEY": "${ADSSH_MCP_API_KEY}",
        "ADSSH_POLICY": "${HOME}/.adssh/policy.rego"
      }
    }
  }
}
```

**D-05 locked:** env vars are primary (secrets not in args array). CLI flags `--policy` and `--api-key` are the alternative shown in docs but not the recommended form.

The binary currently exists at `./adssh-mcp` (project root). The `.mcp.json` path in the docs should use an absolute path or `${PWD}/adssh-mcp`.

---

## Verified Tool Reference (from Source)

All tool names, parameters, required/optional status, and return shapes are verified directly from `cmd/adssh-mcp/server.go` and each `tools_*.go` file.

### Tool 1: `eval_starlark`
[VERIFIED: cmd/adssh-mcp/server.go, tools_eval.go]

**Description:** Execute a Starlark expression in the adssh environment.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `code` | string | yes | Starlark code to evaluate |

**Returns:** Plain text with two sections:
```
output: <print() output>
result: <expression return value>
```

**Starlark globals available** (from `starlarkext/starlarkext.go`):
- `aws`, `gcp`, `oci` — cloud provider namespaces
- `cloud` — cloud engine (gen, register_mapper)
- `git`, `github` — VCS functions (via `SetupVCSAPI`)
- `containers` — ephemeral container API (via `SetupContainersAPI`)
- `crypto` — md5, sha256
- `net` — tcp_send, http_get, dial, dial_tls
- `re` — match (RE2), pcre_match
- `sys` — getenv, setenv, load_plugin, read_file, write_file, exec_cmd, exec_async, exec_json
- `data` — json_parse, json_dump, yaml_parse, yaml_dump
- `sec` — security namespace (from `SetupSecurityAPI`)
- `i18n` — internationalization helpers

Note: Starlark globals are initialized ONCE at server startup and shared across all `eval_starlark` calls.

**Key limitation:** `eval_starlark` uses `starlark.ExecFile` which supports both multi-statement code and single expressions. If a statement produces an error, the tool returns an error text result (not a Go error).

---

### Tool 2: `run_shell`
[VERIFIED: cmd/adssh-mcp/server.go, tools_shell.go]

**Description:** Execute a POSIX shell command.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | string | yes | Shell command to execute |

**Returns:** Plain text:
```
exit_code: <int>
stdout: <string>
stderr: <string>
```

Uses `mvdan.cc/sh/v3` (pure Go POSIX shell interpreter). Not bash-specific. The runner uses the same `BashInterceptor` as interactive adssh — policy is enforced on subcommands within the shell pipeline.

---

### Tool 3: `list_sessions`
[VERIFIED: cmd/adssh-mcp/server.go, tools_sessions.go]

**Description:** List active SSH sessions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| (none) | — | — | No parameters |

**Returns:** JSON array of session ID strings:
```json
["session-abc123", "session-def456"]
```
Returns `[]` (empty array) when no sessions are active.

---

### Tool 4: `cloud_query`
[VERIFIED: cmd/adssh-mcp/server.go, tools_cloud.go]

**Description:** Execute a cloud namespace function.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | yes | `aws`, `gcp`, `oci`, or `cloud` |
| `function` | string | yes | Function name within the namespace |

**Returns:** String representation of the Starlark return value (`.String()` called on the result).

**Important constraint:** `cloud_query` only calls functions with NO arguments. If the function requires arguments, use `eval_starlark` instead to pass them (e.g., `aws["describe_instance"]("i-123")`).

---

### Tool 5: `container_exec`
[VERIFIED: cmd/adssh-mcp/server.go, tools_container.go]

**Description:** Run a command in an ephemeral Docker container. Container is created, executed, and removed.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `image` | string | yes | Docker image (e.g., `ubuntu:22.04`) |
| `cmd` | string | yes | JSON array of strings (e.g., `["ls","-la"]`) or single command string |

**Returns:** JSON object:
```json
{
  "session_id": "a1b2c3d4e5f6g7h8",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "duration_ms": 1234
}
```

**Additional audit:** A separate `~/.adssh/container_audit.jsonl` JSONL file is written for each container execution (independent of the main audit log).

**Docker dependency:** Requires Docker daemon running locally. Pulls image on each call if not cached.

---

### Tool 6: `audit_log`
[VERIFIED: cmd/adssh-mcp/server.go, tools_audit.go]

**Description:** Query recent audit log entries.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | number | no | 50 | Maximum entries to return |
| `filter` | string | no | (none) | Substring filter applied to each log line |

**Returns:** Newline-separated log lines (last N matching lines from `~/.adssh/audit.log`).

If the audit log does not exist yet: returns `(no audit log entries)`.

**Pattern for seeing denied calls:** `filter="denied"` — the policyGate logs denials as `"access denied"` in the audit log.

---

## Policy System Reference (Verified from Source)

[VERIFIED: security/policy.go, policy/default.rego, policy/examples/]

### PolicyContext Fields

The Rego `input` document has exactly these fields:

| Field | Type | Source |
|-------|------|--------|
| `input.user` | string | OS user or session user |
| `input.groups` | []string | OS groups or session principals |
| `input.command` | string | Tool name (e.g., `eval_starlark`) |
| `input.args` | []string | Currently always `[]` for MCP tool calls |
| `input.time` | string | RFC3339 UTC timestamp |
| `input.session_id` | string | Empty string `""` for MCP calls (no SSH session) |

**Note:** For MCP tool calls, `policyGate` calls `BuildPolicyContext(toolName, []string{}, "")` — `args` is always an empty slice, `session_id` is always empty. The `command` field contains the tool name (e.g., `"eval_starlark"`, `"run_shell"`).

### Required Rego Structure

```rego
package adssh.authz

default allow = true      # or false
default deny_reason = ""  # reason string shown in "access denied: <reason>"
```

OPA evaluates `data.adssh.authz` and looks for `allow` (bool) and `deny_reason` (string) in the result.

### Dev Quickstart (Allow-All)

```rego
package adssh.authz
default allow = true
default deny_reason = ""
```

### Policy File Location

Default: `~/.adssh/policy.rego` (from `config/env.go: envOr("ADSSH_POLICY", ...)`)

Override: `ADSSH_POLICY=/custom/path.rego` env var, or `--policy /custom/path.rego` CLI flag.

---

## Environment Variables Reference (Verified from `config/env.go`)

| Env Var | Default | Purpose |
|---------|---------|---------|
| `ADSSH_MCP_API_KEY` | (none) | API key for MCP server (read in `main.go`) |
| `ADSSH_POLICY` | `~/.adssh/policy.rego` | Path to Rego policy file |
| `ADSSH_AUDIT_LOG` | `~/.adssh/audit.log` | Path to audit log file |
| `ADSSH_RESTRICTED` | `0` | Enable sandboxed mode (`1`/`true`/`yes`) |
| `ADSSH_SERVE` | (none) | Start SSH server on this address |
| `ADSSH_HOST_KEY` | `~/.adssh/host_key` | SSH host key path |
| `ADSSH_AUTHORIZED_KEYS` | `~/.adssh/authorized_keys` | SSH authorized keys path |
| `ADSSH_PROFILE` | `~/.adsshprofile` | Login profile script |
| `ADSSH_RC` | `~/.adsshrc` | Interactive RC script |
| `ADSSH_AUDIT_URL` | (none) | Webhook URL for remote SIEM logging |
| `ADSSH_AUDIT_TOKEN` | (none) | Bearer token for audit webhook |
| `ADSSH_ENTITLEMENTS` | (none) | Path to legacy YAML entitlements (deprecated) |

---

## Tool Selection Decision Rule (D-09)

The skill must include an explicit decision rule. Based on verified implementations:

| Situation | Use |
|-----------|-----|
| Need cloud namespace access (`aws.*`, `gcp.*`, `oci.*`) WITH arguments | `eval_starlark` |
| Single zero-argument cloud function call | `cloud_query` (simpler) |
| Multi-step Starlark logic, loops, conditionals, combining results | `eval_starlark` |
| POSIX pipeline: grep, awk, sed, file operations, system commands | `run_shell` |
| Anything easier as a shell one-liner | `run_shell` |
| Check what SSH sessions are active | `list_sessions` |
| Run something in a container without leaving artifacts | `container_exec` |
| Review what was done or debug a policy denial | `audit_log` |

**Key insight:** `cloud_query` is a convenience shortcut for `eval_starlark` when calling a zero-argument function. For anything with arguments or multi-step logic, `eval_starlark` is the right choice.

---

## Connect + Orient Behavior (D-03)

When `/adssh` fires, Claude should execute this sequence:

1. Verify the `adssh` MCP server appears in available tools (it will be listed if `.mcp.json` is configured correctly)
2. Call `list_sessions` to enumerate active SSH sessions
3. Give a situational briefing: session count, session IDs, readiness status
4. State which tools are available

If `list_sessions` returns an MCP error, the server is not connected — Claude should tell the user to check `.mcp.json` and that `adssh-mcp` is built.

---

## Common Pitfalls

### Pitfall 1: `cloud_query` Cannot Pass Arguments
**What goes wrong:** User tries to call `cloud_query` with a function that takes parameters (e.g., `describe_instance` with an instance ID). Gets an error because the tool calls the Starlark function with `nil, nil` args.
**Why it happens:** `tools_cloud.go` calls `starlark.Call(thread, callFn, nil, nil)` — no args, no kwargs.
**How to avoid:** Use `eval_starlark` for any cloud function that takes arguments.
**Warning signs:** `error calling aws.X: ...` result from `cloud_query`.

### Pitfall 2: Starlark Globals Are Shared State
**What goes wrong:** One `eval_starlark` call sets a variable; a later call sees it. Or one call modifies a cloud namespace dict and breaks subsequent calls.
**Why it happens:** `globals starlark.StringDict` is initialized once at server startup and passed by reference to all eval calls.
**How to avoid:** Treat the globals as read-only infrastructure. Assign to local variables within each code block rather than reassigning global names.
**Warning signs:** Unexpected values in variables across separate tool calls.

### Pitfall 3: Policy File Missing = Allow-All Fallback
**What goes wrong:** `~/.adssh/policy.rego` doesn't exist at server startup. `LoadPolicy` gets `os.IsNotExist` and returns nil (no error). Policy is `nil`, so `EvaluatePolicy` returns `(true, "", nil)` — all calls allowed.
**Why it happens:** `security/policy.go` LoadPolicy treats missing file as allow-all (not an error).
**How to avoid:** Always create the policy file before starting the server in production. Confirm the server logs `"Policy loaded from ..."` at startup.
**Warning signs:** No `"Policy loaded from"` line in audit log after server start.

### Pitfall 4: `container_exec` Requires Docker Daemon
**What goes wrong:** `container_exec` returns `"docker client error: ..."` or `"image pull failed: ..."`.
**Why it happens:** The tool creates a Docker client from environment and attempts an image pull before creating the container.
**How to avoid:** Ensure Docker Desktop or Docker Engine is running. Verify with `docker info`.
**Warning signs:** Error response from the tool mentioning "docker client" or "image pull".

### Pitfall 5: `run_shell` Uses mvdan/sh (Not Bash)
**What goes wrong:** Bash-specific syntax fails silently or errors. Arrays, `[[`, `$BASHPID`, process substitutions may not work.
**Why it happens:** `mvdan.cc/sh/v3` is a POSIX shell interpreter, not bash.
**How to avoid:** Stick to POSIX-compatible shell syntax. For bash-specific operations, use `eval_starlark` with `sys.exec_cmd`.
**Warning signs:** Parse errors on `[[`, `(( ))`, bash arrays.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead |
|---------|-------------|-------------|
| Policy enforcement | Custom gate logic in skill | Already done in `policyGate` in server.go |
| Audit logging | Custom log writes | Already done in `security.LogCommand` |
| Tool documentation | Re-derive from source | Read from verified source files in this research |
| JSON parsing in Starlark | Custom parser | `data.json_parse()` builtin available |

---

## Skill File Authoring: Format Reference

Verified from `careful/SKILL.md` and `gsd-execute-phase/SKILL.md`:

- Frontmatter is YAML between `---` delimiters
- Keys confirmed in use: `name`, `version`, `description`, `triggers`, `allowed-tools`, `hooks`, `argument-hint`
- Skill body is standard Markdown consumed by Claude
- `@` references (e.g., `@$HOME/.claude/...`) load external files into context — supported in skill bodies
- No `triggers` list observed to use slash-command syntax like `/adssh` — the careful skill uses plain phrases; however D-02 specifies `/adssh` as the trigger; the Claude Code skill system accepts this format [ASSUMED — not verified against Claude Code docs]

---

## Deliverable Checklist for Planner

The planner can create tasks directly from this list. Each item maps to a locked decision:

| Deliverable | Decision | Content Source |
|-------------|----------|----------------|
| `.claude/skills/adssh/SKILL.md` frontmatter | D-02 | name, triggers, no allowed-tools |
| Connect + orient body in SKILL.md | D-03 | list_sessions call, situational briefing |
| `.claude/adssh-reference.md` companion doc | D-01 | Entire tool reference below |
| Fresh setup walkthrough | D-04 | Build binary, .mcp.json, env vars, policy |
| Env-var + CLI-flag config examples | D-05 | main.go + config/env.go verified above |
| Policy walkthrough + PolicyContext | D-06 | security/policy.go + examples/ verified above |
| Per-tool parameter tables + examples (x6) | D-07 | Verified tool reference above |
| Workflows section (2-3 scenarios) | D-08 | Chain scenarios using verified tool returns |
| Tool selection decision rule | D-09 | Table above |
| Policy awareness section | D-10 | policyGate behavior verified |
| Audit trail note | D-11 | audit_log filter verified |

---

## State of the Art

| Item | Status |
|------|--------|
| `.claude/` directory in project | Exists (has `settings.local.json`) |
| `.claude/skills/` directory | Does NOT exist — must be created |
| `adssh-mcp` binary | Built, exists at `./adssh-mcp` |
| `.mcp.json` | Does NOT exist — must be created |
| `policy/default.rego` | Exists — allow-all template |
| `policy/examples/` | 3 files: `ops_group_only.rego`, `restrict_sudo.rego`, `migrate-from-yaml.rego` |

---

## Environment Availability

Step 2.6: SKIPPED — this phase is documentation/file authoring only. No external tools, services, or runtimes are required beyond the existing `adssh-mcp` binary (already built).

---

## Validation Architecture

> `workflow.research` is `false` in `.planning/config.json`. `workflow.nyquist_validation` key is absent — treating as enabled, but this phase has no testable code behavior. The skill files are Markdown; there is no automated test framework applicable.

**Test approach for this phase:** Manual validation only.

| Req ID | Behavior | Test Type | Command |
|--------|----------|-----------|---------|
| SKILL-01 | `.claude/skills/adssh/SKILL.md` exists with correct frontmatter | Manual | `ls .claude/skills/adssh/SKILL.md` |
| SKILL-02 | Skill body covers all 4 domains | Manual review | Read file, verify sections present |
| SKILL-03 | Tool reference has all 6 tools with parameter tables | Manual review | Read file, count tool sections |

**Wave 0 Gaps:** None — no test files needed for a documentation phase.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Claude Code `triggers` accepts `/adssh` (slash-prefixed) as a trigger value | Skill File Authoring: Format Reference | Trigger may not fire; would need to use plain word `adssh` instead |
| A2 | `.claude/adssh-reference.md` is a valid always-loaded context location when referenced with `@` in SKILL.md or project settings | Architecture Patterns | Companion doc may need to be in a different path or registered differently |

---

## Open Questions (RESOLVED)

1. **How to register the companion reference as always-loaded**
   - What we know: `gsd-execute-phase/SKILL.md` uses `@$HOME/.claude/...` references in the skill body to load context files when the trigger fires
   - What's unclear: Whether there's a project-level mechanism to load a file into context for EVERY conversation (not just on `/adssh`), such as `CLAUDE.md` includes
   - Recommendation: Put the companion reference inline in the skill body using `@.claude/adssh-reference.md` syntax within the SKILL.md, so it loads on trigger. A true "always-loaded" companion may require adding it to `CLAUDE.md` or project settings — the planner should decide.

2. **Trigger format for slash commands**
   - What we know: `careful/SKILL.md` uses plain phrases as triggers. `gsd-execute-phase/SKILL.md` doesn't use triggers at all (uses argument-hint instead).
   - What's unclear: Whether Claude Code's skill system treats `/adssh` as a slash command trigger or a literal string match. D-02 specifies `/adssh`.
   - Recommendation: Use `/adssh` in triggers as specified by D-02 — if it doesn't work as expected, the user can adjust.

---

## Sources

### Primary (HIGH confidence)
- `cmd/adssh-mcp/server.go` — All 6 tool registrations, parameter schemas, policyGate implementation
- `cmd/adssh-mcp/tools_eval.go` — eval_starlark return format (`output:` + `result:`)
- `cmd/adssh-mcp/tools_shell.go` — run_shell return format (`exit_code:` + `stdout:` + `stderr:`)
- `cmd/adssh-mcp/tools_sessions.go` — list_sessions returns JSON array
- `cmd/adssh-mcp/tools_cloud.go` — cloud_query calls function with nil args (no argument support)
- `cmd/adssh-mcp/tools_container.go` — container_exec return JSON shape, container_audit.jsonl path
- `cmd/adssh-mcp/tools_audit.go` — audit_log limit/filter behavior, empty log message
- `config/env.go` — Full ADSSH_* env var list with defaults
- `security/policy.go` — PolicyContext fields, EvaluatePolicy behavior, allow-all fallback when file missing
- `policy/default.rego` — Default policy content
- `policy/examples/ops_group_only.rego` — Group-based deny example
- `policy/examples/restrict_sudo.rego` — Command-specific deny example
- `policy/examples/migrate-from-yaml.rego` — Per-user/per-group allowlist example
- `starlarkext/starlarkext.go` — Full list of Starlark globals and namespaces
- `~/.claude/skills/careful/SKILL.md` — Trigger-based skill frontmatter format reference
- `~/.claude/skills/gsd-execute-phase/SKILL.md` — Complex skill body format reference

### Tertiary (LOW confidence — ASSUMED)
- Claude Code trigger format accepting `/adssh` slash-command syntax (A1)
- Always-loaded companion reference mechanism (A2)

---

## Metadata

**Confidence breakdown:**
- Tool parameter/return schemas: HIGH — read directly from source
- Env vars and defaults: HIGH — read directly from config/env.go
- Policy system behavior: HIGH — read directly from security/policy.go
- Starlark namespaces available: HIGH — read from starlarkext/starlarkext.go
- Skill frontmatter format: HIGH — verified from two existing skills
- Trigger slash-command format: LOW — no official Claude Code docs consulted; inferred from D-02

**Research date:** 2026-05-07
**Valid until:** 2026-06-07 (stable codebase; skill format is stable)
