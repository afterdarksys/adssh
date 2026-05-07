# Phase 3: Claude Code Skill - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-07
**Phase:** 3-Claude Code Skill
**Areas discussed:** Skill format, MCP setup docs, Example depth, Tool selection guidance

---

## Skill Format

| Option | Description | Selected |
|--------|-------------|----------|
| Trigger-based skill | SKILL.md with /adssh slash command, frontmatter, triggers | |
| Reference document | Plain .md always loaded via CLAUDE.md @-include | |
| Both | SKILL.md for /adssh + companion reference always in context | ✓ |

**User's choice:** Both — trigger-based skill AND companion reference doc

| Option | Description | Selected |
|--------|-------------|----------|
| Connect + orient | Check MCP connection, list sessions, situational briefing | ✓ |
| Just load context | Load reference into context, prime Claude's behavior | |
| Interactive menu | Menu: connect, list sessions, run snippet, check audit log | |

**User's choice:** Connect + orient — /adssh checks connection, lists sessions, gives briefing

| Option | Description | Selected |
|--------|-------------|----------|
| MCP tools only | Only the 6 adssh MCP tools in allowed-tools | |
| MCP + Bash | 6 MCP tools + Bash for local shell commands | |
| All tools | No restriction, Claude uses whatever fits | ✓ |

**User's choice:** All tools — no allowed-tools restriction

---

## MCP Setup Docs

| Option | Description | Selected |
|--------|-------------|----------|
| Developer setting up fresh | Full walkthrough: build binary, .mcp.json, env vars, policy | ✓ |
| Claude using a live server | Assumes connected, focuses on verification and recovery | |
| Both sections | Setup section for devs + connection check section for Claude | |

**User's choice:** Developer setting up fresh

| Option | Description | Selected |
|--------|-------------|----------|
| Env var approach | Show .mcp.json with env block, ADSSH_MCP_API_KEY | |
| CLI flags approach | Show args array with --api-key, --policy flags | |
| Both variants | Env var as primary, CLI flags as alternative | ✓ |

**User's choice:** Both variants

| Option | Description | Selected |
|--------|-------------|----------|
| Reference only | Point to policy/default.rego, don't embed content | |
| Include dev quickstart policy | Embed minimal allow-all Rego for local dev | |
| Full policy walkthrough | PolicyContext structure, real examples, link to policy/examples/ | ✓ |

**User's choice:** Full policy walkthrough with dev quickstart allow-all snippet

---

## Example Depth

| Option | Description | Selected |
|--------|-------------|----------|
| Quick ref + one realistic example | Parameter table + one concrete usage per tool | ✓ |
| Pure quick reference | Parameter tables only, no examples | |
| Full cookbook | 3-5 worked examples per tool | |

**User's choice:** Quick ref + one realistic example per tool

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, 2-3 workflow scenarios | End-to-end DevOps scenarios showing tool chaining | ✓ |
| No, per-tool examples are enough | Keep it focused, no workflow section | |
| Yes, but just one example | One 'Putting it all together' scenario | |

**User's choice:** Yes — 2-3 end-to-end DevOps workflow scenarios

---

## Tool Selection Guidance

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, a decision rule | Explicit rule: eval_starlark for cloud/Starlark, run_shell for POSIX | ✓ |
| Yes, but just a hint | One-liner note on preference | |
| No, leave it to Claude | Trust Claude to read tool schemas | |

**User's choice:** Yes — explicit decision rule (eval_starlark vs run_shell vs cloud_query)

| Option | Description | Selected |
|--------|-------------|----------|
| Include policy awareness section | Explain gate, 'access denied' meaning, recovery via audit_log | ✓ |
| Just mention it briefly | One-line note | |
| Skip it | Don't document policy gate | |

**User's choice:** Full policy awareness section with recovery guidance

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — audit trail awareness | Note that every call is logged, use audit_log to review history | ✓ |
| No — covered by audit_log tool reference | Tool docs cover it | |

**User's choice:** Yes — include audit trail awareness note

---

## Claude's Discretion

- Exact companion reference document path (.claude/adssh-reference.md or similar)
- Specific wording of workflow scenario titles
- Whether companion reference is inline in SKILL.md or a separate file

## Deferred Ideas

- None — discussion stayed within phase scope
