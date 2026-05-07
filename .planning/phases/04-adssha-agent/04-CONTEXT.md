# Phase 4: ADSSHA Agent - Context

**Gathered:** 2026-05-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver ADSSHA in two parts:

1. **Agent definition file** — `agents/adssha.md` (committed to repo, users copy to `~/.adssh/agents/adssha.md`): a markdown file with TOML frontmatter that captures the agent's name, model, MCP server binding, and allowed tools, with a full DevOps AI system prompt in the body.

2. **`sys.load_agent` Go builtin** — added to `starlarkext/starlarkext.go` alongside `sys.load_plugin`: reads `~/.adssh/agents/{name}.md`, parses frontmatter + system prompt, and returns a stateful Starlark callable. Calling `agent("task description")` sends the prompt to Claude API (ANTHROPIC_API_KEY from env) with the agent's system prompt and conversation history, returning a string response.

**Out of scope:** Changes to MCP server tools, new Rego policies, Claude Code skill changes, UI, plugin registry, multi-line REPL.

</domain>

<decisions>
## Implementation Decisions

### Agent Direction
- **D-01:** ADSSHA is **both** inbound and outbound:
  - **Inbound** (Claude reads it): `agents/adssha.md` is a definition that tells Claude how to behave when connecting to adssh via MCP. It is the authoritative system prompt for the Claude Code skill use case.
  - **Outbound** (adssh calls Claude): `sys.load_agent("adssha")` returns a callable that hits the Claude API directly from within the Starlark runtime. The shell can call the agent programmatically.
- **D-02:** The agent callable maintains **stateful conversation history** across calls within the same Starlark session. Multi-turn interactions work naturally: `agent("list containers")` → `agent("stop the first one")`.
- **D-03:** Returns a **plain Starlark string** — the Claude text response. Simple: `result = agent("deploy staging"); print(result)`.

### API Configuration
- **D-04:** **Env vars only** — no secrets in definition files.
  - `ANTHROPIC_API_KEY` — required for outbound calls
  - `ADSSHA_MODEL` — optional model override (default: `claude-sonnet-4-6`)

### Agent Definition Format
- **D-05:** **Markdown with TOML frontmatter** (`.md` file, `+++` delimiters). Frontmatter holds structured metadata; body is the system prompt in plain markdown. Mirrors the SKILL.md convention established in Phase 3.

  ```toml
  +++
  name = "adssha"
  model = "claude-sonnet-4-6"
  mcp_server = "adssh"
  tools = ["eval_starlark", "run_shell", "list_sessions", "cloud_query", "container_exec", "audit_log"]
  +++
  ```

- **D-06:** Agent definition files live in **`~/.adssh/agents/`** at runtime (mirrors `~/.adssh/policy.rego`). The canonical distributed copy is committed at **`agents/adssha.md`** in the repo root. Users install it with: `cp agents/adssha.md ~/.adssh/agents/adssha.md`.

### sys.load_agent Runtime Behavior
- **D-07:** `sys.load_agent("adssha")` looks up `~/.adssh/agents/adssha.md`, parses TOML frontmatter and markdown body, initializes conversation history with the system prompt, and returns a Starlark callable. Pattern follows `sys.load_plugin` in `starlarkext/libmod.go`.
- **D-08:** Each call to the returned callable appends the user message + Claude response to the in-memory history. History is scoped to the Starlark session — not persisted to disk (no conversation log files in this phase).

### Agent Persona & Scope
- **D-09:** **Autonomy level — ask before destructive, run safe ops freely:**
  - Read-only / observability ops (`list_sessions`, `audit_log`, read-only `eval_starlark`, read-only `cloud_query`): runs autonomously without confirmation.
  - Destructive / state-changing ops (`container_exec`, `run_shell` with writes, `eval_starlark` with side effects): describes the plan, states what command will run, and asks for confirmation before executing.
- **D-10:** **Primary job: multi-step DevOps workflow orchestration.** ADSSHA chains tools together to do the tedious orchestration humans skip: list sessions → query cloud state → run diagnostic scripts → review audit log. This is what makes it genuinely useful vs. a single-command interface.
- **D-11:** **Error handling — explain + show recovery path:** When blocked (policy denial, API error, missing session), ADSSHA names the exact failure, shows what `audit_log` contains, and suggests a concrete next step (e.g., "check policy.rego line N" or "confirm with your admin"). No silent swallowing of errors.

### Claude's Discretion
- Call pattern for the returned Starlark callable: follow the `sys.load_plugin` pattern — `agent = sys.load_agent("adssha")` stores a callable; `agent("task")` invokes it. Planner/implementer decides the exact Go struct layout for conversation history.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Starlark Extension System (where sys.load_agent goes)
- `starlarkext/starlarkext.go` — `SetupExtensions()` builds the `sys` dict; `sys.load_agent` must be injected here alongside `sys.load_plugin`
- `starlarkext/libmod.go` — `createLoadPlugin()` implementation — the structural template for `createLoadAgent()`

### MCP Server (what the agent uses)
- `cmd/adssh-mcp/server.go` — All 6 tool names and parameter schemas (what `tools` array in frontmatter references)
- `cmd/adssh-mcp/main.go` — Binary startup flags and env var list

### Configuration
- `config/env.go` — Existing ADSSH_* env var patterns; ANTHROPIC_API_KEY and ADSSHA_MODEL follow same convention

### Phase Context
- `.planning/phases/03-claude-code-skill/03-CONTEXT.md` — Phase 3 decisions (SKILL.md format, tool reference, policy awareness patterns)
- `.planning/REQUIREMENTS.md` §AGENT-01, AGENT-02, AGENT-03 — Requirements this phase must satisfy

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `starlarkext/libmod.go:createLoadPlugin()` — Direct template for `createLoadAgent()`: same pattern of reading a path argument, opening a resource, and returning a `*starlark.Builtin`
- `starlarkext/starlarkext.go:59–72` — The `sysDict` block where the new builtin must be injected (line 62 adds `load_plugin`; `load_agent` goes on the same dict)

### Established Patterns
- **sys dict injection**: `sysDict.SetKey(starlark.String("load_agent"), createLoadAgent(env))` — follows exact pattern of `load_plugin` and `exec_cmd`
- **Agent path convention**: `~/.adssh/agents/{name}.md` mirrors `~/.adssh/policy.rego` (user-local config directory)
- **File format**: TOML `+++` frontmatter + markdown body mirrors the SKILL.md convention from Phase 3

### Integration Points
- `starlarkext/starlarkext.go` — `SetupExtensions()` is called from `main.go:82`; adding `sys.load_agent` here makes it available in all Starlark execution contexts (interactive REPL, scripts, SSH sessions)
- `go.mod` — Anthropic Go SDK (`github.com/anthropics/anthropic-sdk-go`) will need to be added as a dependency

</code_context>

<specifics>
## Specific Ideas

- The ADSSHA system prompt body (in `agents/adssha.md`) should describe: (1) identity as a DevOps AI in the adssh shell, (2) the 6 available MCP tools and when to use each, (3) the autonomy rules (read = free, write = confirm), (4) how to handle policy denials (explain + show audit log + suggest fix), (5) example multi-step workflow patterns.
- The frontmatter `tools` array defines what the agent is supposed to use — informational in Phase 4 (not enforced by Go code in this phase; Rego is the enforcement layer).
- Conversation history struct: a `[]anthropic.MessageParam` slice attached to the agent callable, appended on each call. Not persisted across sessions.
- `sys.load_agent` should return a helpful error if `~/.adssh/agents/{name}.md` doesn't exist: `"agent 'adssha' not found — copy agents/adssha.md to ~/.adssh/agents/adssha.md"`.

</specifics>

<deferred>
## Deferred Ideas

- Persisting conversation history to disk (audit log integration for agent sessions) — future phase
- Multiple concurrent agent instances (one per SSH session) — future phase
- Agent tool call interception / policy enforcement at the callable level (currently Rego enforces at the MCP layer) — future phase
- Proactive monitoring mode (ADSSHA watches for drift / alerts without being asked) — could be its own phase after v1.0

</deferred>

---

*Phase: 4-ADSSHA Agent*
*Context gathered: 2026-05-07*
