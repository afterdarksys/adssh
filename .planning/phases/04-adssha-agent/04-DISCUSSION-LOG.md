# Phase 4: ADSSHA Agent - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-07
**Phase:** 4-adssha-agent
**Areas discussed:** Agent direction, sys.load_agent behavior, Agent definition format, Agent persona & scope

---

## Agent Direction

| Option | Description | Selected |
|--------|-------------|----------|
| Inbound — Claude reads it | ADSSHA is a document that tells Claude how to behave when connecting to adssh via MCP. No Claude API calls from adssh. | |
| Outbound — adssh calls Claude | adssh spawns a Claude API session from within the shell via sys.load_agent(). | |
| Both — definition + runtime caller | The agent definition exists as a document AND sys.load_agent() triggers an active Claude API session from inside adssh. | ✓ |

**User's choice:** Both — inbound definition (for Claude Code skill use case) AND outbound caller (adssh → Claude API via Starlark).

| Option | Description | Selected |
|--------|-------------|----------|
| sys.load_agent() starts the session inline | Kicks off a Claude API session in the shell directly. | |
| Separate Starlark callable returned | sys.load_agent() returns a callable; agent("task") sends the prompt. | |
| You decide | Claude figures out the right call pattern. | ✓ |

**User's choice:** You decide — Claude to follow sys.load_plugin pattern.

| Option | Description | Selected |
|--------|-------------|----------|
| Env var only | ANTHROPIC_API_KEY + ADSSHA_MODEL env var override. | ✓ |
| Agent definition file | API key + model declared in the file alongside system prompt. | |
| Existing adssh config | Extend config/env.go with ADSSHA_API_KEY and ADSSHA_MODEL. | |

**User's choice:** Env vars only — no secrets in definition files.

---

## sys.load_agent Behavior

| Option | Description | Selected |
|--------|-------------|----------|
| ~/.adssh/agents/ | Convention mirrors ~/.adssh/policy.rego. sys.load_agent("adssha") reads ~/.adssh/agents/adssha.md. | ✓ |
| Relative path as arg | sys.load_agent("./agents/adssha.md") — caller provides explicit path. | |
| Embedded in binary | Agent baked into the adssh binary as a Go embed. | |

**User's choice:** ~/.adssh/agents/ — consistent with existing adssh config conventions.

| Option | Description | Selected |
|--------|-------------|----------|
| String response | Returns Claude text response as a Starlark string. | ✓ |
| Dict with metadata | Returns {response, model, tokens}. | |
| Streams to stdout | Streams response directly to REPL output, nothing returned. | |

**User's choice:** String response — simple and composable.

| Option | Description | Selected |
|--------|-------------|----------|
| Stateful — remembers context | Callable maintains message history across calls in the session. | ✓ |
| Stateless — single-turn only | Each call independent; system prompt prepended but no history. | |

**User's choice:** Stateful — enables natural multi-turn: agent("list containers") → agent("stop the first one").

---

## Agent Definition Format

| Option | Description | Selected |
|--------|-------------|----------|
| Markdown with TOML frontmatter | TOML +++ delimiters for metadata; markdown body for system prompt. | ✓ |
| Pure YAML config | Structured YAML with system_prompt field. | |
| Plain markdown only | No frontmatter; metadata from env vars; maximally simple. | |

**User's choice:** Markdown with TOML frontmatter — human-readable, mirrors SKILL.md convention.

| Option | Description | Selected |
|--------|-------------|----------|
| agents/adssha.md (top-level) | Top-level agents/ directory; users copy to ~/.adssh/agents/. | ✓ |
| cmd/adssh-mcp/agents/adssha.md | Alongside MCP server code. | |
| .claude/agents/adssha.md | Alongside Claude Code skill. | |

**User's choice:** agents/adssha.md — clear top-level distribution directory.

---

## Agent Persona & Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Ask before destructive, run safe ops | Read ops autonomous; destructive ops require confirmation. | ✓ |
| Always ask before any tool call | Describes every action and waits for approval. | |
| Fully autonomous | Runs anything policy permits without asking. | |

**User's choice:** Ask before destructive, run safe ops — Rego is the safety net; ADSSHA adds a UX layer of confirmation for destructive actions.

| Option | Description | Selected |
|--------|-------------|----------|
| Multi-step DevOps workflow orchestration | Chaining: list sessions → cloud state → diagnostics → audit log review. | ✓ |
| Proactive monitoring + alerts | Watches for drift, cost anomalies, security events. | |
| On-demand scripting assistant | Writes and runs Starlark scripts on request. | |

**User's choice:** Multi-step DevOps workflow orchestration — the tedious chaining humans skip.

| Option | Description | Selected |
|--------|-------------|----------|
| Explain + show recovery path | Names exact failure, shows audit_log, suggests fix. | ✓ |
| Fail silently and try another approach | Swallows error and attempts alternative. | |
| Report raw error and stop | Shows raw error message and halts. | |

**User's choice:** Explain + show recovery path — especially important for Rego policy denials where the fix path is non-obvious.

---

## Claude's Discretion

- Call pattern for the Starlark callable returned by `sys.load_agent()` — follow `sys.load_plugin` structural pattern. Claude decides the exact Go struct layout for conversation history.

## Deferred Ideas

- Persisting conversation history to disk (audit log integration for agent sessions)
- Multiple concurrent agent instances (one per SSH session)
- Agent tool call interception / policy enforcement at the callable level
- Proactive monitoring mode (ADSSHA watches for drift / alerts without being asked)
