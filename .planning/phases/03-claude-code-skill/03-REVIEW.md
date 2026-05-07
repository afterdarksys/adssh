---
phase: 03-claude-code-skill
reviewed: 2026-05-07T00:00:00Z
depth: standard
files_reviewed: 3
files_reviewed_list:
  - .claude/adssh-reference.md
  - .claude/skills/adssh/SKILL.md
  - .mcp.json
findings:
  critical: 2
  warning: 3
  info: 1
  total: 6
status: issues_found
---

# Phase 03: Code Review Report

**Reviewed:** 2026-05-07
**Depth:** standard
**Files Reviewed:** 3
**Status:** issues_found

## Summary

Three files were reviewed: the operational reference document, the Claude Code skill definition,
and the project-local MCP configuration. The reference document is thorough and accurate.
Two critical issues were found: a hardcoded local filesystem path committed to the repo
(`.mcp.json`), and a security gap where the policy engine receives no information about
command arguments — meaning shell commands like `run_shell` cannot be policy-gated at the
command level, only at the tool level. Three warnings cover the broken `@`-include path in
the skill, an incomplete troubleshooting checklist, and a silent allow-all fallback on missing
policy file.

---

## Critical Issues

### CR-01: Hardcoded Absolute Path in `.mcp.json`

**File:** `.mcp.json:4`
**Issue:** The `command` field contains a hardcoded developer-local absolute path
(`/Users/ryan/development/adssh/adssh-mcp`). This file is committed to the repository.
Any developer who clones the repo and attempts to use `.mcp.json` as-is will get a broken
MCP server entry pointing to a non-existent path. The reference document (line 56) explicitly
warns users to replace the placeholder path — which is evidence this path was never meant
to be committed verbatim.

**Fix:** Either (a) add `.mcp.json` to `.gitignore` so each developer maintains their own
untracked copy, or (b) replace the hardcoded path with documentation-only placeholder text
and add a comment, or (c) use an env-var-based path (Claude Code supports `${VAR}` expansion):

```json
{
  "mcpServers": {
    "adssh": {
      "command": "${ADSSH_MCP_BINARY}",
      "env": {
        "ADSSH_MCP_API_KEY": "${ADSSH_MCP_API_KEY}",
        "ADSSH_POLICY": "${HOME}/.adssh/policy.rego"
      }
    }
  }
}
```

The simplest fix is to add `.mcp.json` to `.gitignore` and add a `.mcp.json.example`
template with the placeholder path from the reference docs.

---

### CR-02: Policy Engine Cannot Inspect Shell Command Arguments — Shell Injection Risk

**File:** `.claude/adssh-reference.md:119-125`
**Issue:** The PolicyContext documentation explicitly states `input.args` is `Always []` for
MCP tool calls. This means a Rego policy cannot distinguish between
`run_shell(command="df -h")` and `run_shell(command="rm -rf /")` — both present identically
to the policy engine. A policy can only allow or deny the `run_shell` tool entirely;
it cannot inspect the actual shell command being executed. The reference doc describes the
`BashInterceptor` (line 270) as enforcing policy "on subcommands within the pipeline" but the
PolicyContext table contradicts this — `input.args` is always empty. If `BashInterceptor`
does pass command content, the documentation is wrong; if it does not, the system has no
per-command policy enforcement for `run_shell` or `eval_starlark`.

This gap means production deployments that rely on Rego to block dangerous commands (e.g.,
`sudo`, `rm -rf`, credential exfiltration) cannot actually do so through the documented
policy interface — they can only block the tool wholesale.

**Fix:** Either (a) populate `input.args` with the actual command content for MCP tool calls
so Rego rules can inspect it, or (b) update the documentation to explicitly state that
per-command filtering is not available through `input.args` and document the correct mechanism
(`BashInterceptor`), so operators are not misled into writing Rego rules that will never fire.

Example of a Rego rule that a user might write expecting it to work, but which will never
trigger because `input.args` is always `[]`:

```rego
# This rule WILL NOT WORK — input.args is always [] for MCP calls
allow = false {
    input.command == "run_shell"
    some arg in input.args
    contains(arg, "sudo")
}
```

---

## Warnings

### WR-01: `@` Include Path in SKILL.md Will Not Resolve from Skill File Location

**File:** `.claude/skills/adssh/SKILL.md:41`
**Issue:** The last line is `@.claude/adssh-reference.md`. The `@` file inclusion in Claude
Code resolves paths relative to the working directory at invocation time, not relative to
the skill file itself. The skill file lives at `.claude/skills/adssh/SKILL.md`; the reference
file lives at `.claude/adssh-reference.md`. If Claude Code were to resolve `@` includes
relative to the skill file's directory (`.claude/skills/adssh/`), the path
`.claude/adssh-reference.md` would resolve to
`.claude/skills/adssh/.claude/adssh-reference.md`, which does not exist. If it resolves
relative to the project root (which is the actual behavior), this works — but it is fragile:
the include will silently produce nothing if the user invokes the skill from any subdirectory.

**Fix:** The path should be made robust. If Claude Code supports absolute-from-root includes,
use that form. As a defensive measure, the SKILL.md should note that it must be invoked
from the project root, or the reference content should be inlined rather than included by
reference:

```
# Current (fragile):
@.claude/adssh-reference.md

# Preferred (explicit root-relative, if supported):
@/.claude/adssh-reference.md
```

---

### WR-02: Troubleshooting Checklist in SKILL.md Omits API Key Verification

**File:** `.claude/skills/adssh/SKILL.md:25-27`
**Issue:** The error-handling path (when `list_sessions` returns an MCP error) instructs the
operator to verify three things: `.mcp.json` presence, binary build, and `ADSSH_POLICY` env
var. However `ADSSH_MCP_API_KEY` is documented in the reference as a required env var
(`.claude/adssh-reference.md:90`). If the key is absent and the server requires it, the
server will fail to start or reject calls — but the troubleshooting checklist will not lead
the operator to check it. This creates a confusing dead-end diagnosis path.

**Fix:** Add `ADSSH_MCP_API_KEY` to the verification checklist:

```markdown
- Required env vars are set:
  - `ADSSH_POLICY` pointing to a .rego file
  - `ADSSH_MCP_API_KEY` if the server requires authentication
```

---

### WR-03: Silent Allow-All Fallback on Missing Policy File Is Not Adequately Surfaced

**File:** `.claude/adssh-reference.md:588-596`
**Issue:** The "Missing Policy File = Allow-All Fallback" section documents that when
`~/.adssh/policy.rego` is absent, the policy engine returns `(true, "", nil)` for every call,
allowing everything. This is a serious security default but the only warning sign given is
"No `Policy loaded from` line in the audit log" — which requires the operator to proactively
check the audit log after every startup. There is no mention that the server itself emits no
warning, no startup error, and no indication to the calling client that policy is absent.

The reference document correctly identifies this as a pitfall, but only in a buried section.
The SKILL.md connect+orient sequence (steps 1-3) does not include checking for the
`"Policy loaded from"` audit log entry as part of the orientation ritual — so an operator
using the skill will never be prompted to verify policy is loaded.

**Fix:** Add a step 4 to the SKILL.md connect+orient sequence:

```markdown
4. Call `audit_log(limit=5, filter="Policy loaded")` and confirm policy was loaded.
   If no "Policy loaded from" entry appears, the server is running with allow-all fallback —
   create `~/.adssh/policy.rego` and restart the server.
```

---

## Info

### IN-01: Shared Starlark Globals Warning Only in Pitfalls Section, Not Tool Reference

**File:** `.claude/adssh-reference.md:231-235`
**Issue:** The `eval_starlark` tool reference mentions shared globals as a fact but does not
include a warning. The security/correctness implications (globals mutated by one call affect
all subsequent calls, including potential namespace clobbering) are only documented in the
"Common Pitfalls" section at line 568. An operator reading only the tool reference to write
a quick script may miss this critical constraint entirely.

**Fix:** Add a warning callout directly in the `eval_starlark` parameters/description section:

```markdown
> **Warning:** Starlark globals (`aws`, `gcp`, `oci`, etc.) are shared across all
> `eval_starlark` calls. Do not reassign or mutate them — use local variables only.
> See [Starlark Globals Are Shared State](#starlark-globals-are-shared-state) in pitfalls.
```

---

_Reviewed: 2026-05-07_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
