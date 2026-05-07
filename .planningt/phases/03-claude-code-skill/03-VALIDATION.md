---
phase: 3
slug: claude-code-skill
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-07
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | file existence checks (no test runner — documentation-only phase) |
| **Config file** | none |
| **Quick run command** | `ls .claude/skills/adssh/SKILL.md` |
| **Full suite command** | `ls .claude/skills/adssh/SKILL.md && ls .mcp.json` |
| **Estimated runtime** | ~1 second |

---

## Sampling Rate

- **After every task commit:** Run `ls .claude/skills/adssh/SKILL.md`
- **After every plan wave:** Run `ls .claude/skills/adssh/SKILL.md && ls .mcp.json`
- **Before `/gsd-verify-work`:** Both files must exist and be non-empty
- **Max feedback latency:** 1 second

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 3-01-01 | 01 | 1 | SKILL-01 | — | N/A | file check | `test -f .claude/skills/adssh/SKILL.md` | ❌ W0 | ⬜ pending |
| 3-01-02 | 01 | 1 | SKILL-02 | — | N/A | content check | `grep -q "eval_starlark" .claude/skills/adssh/SKILL.md` | ❌ W0 | ⬜ pending |
| 3-01-03 | 01 | 1 | SKILL-03 | — | N/A | content check | `grep -q "list_sessions" .claude/skills/adssh/SKILL.md` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `.claude/skills/adssh/` — directory must be created

*Existing infrastructure covers all phase requirements once the directory exists.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `/adssh` slash command invokes skill | SKILL-01 | Requires live Claude Code session | Run `/adssh` in Claude Code, verify it lists active SSH sessions |
| Policy walkthrough is accurate | SKILL-02 | Requires reading comprehension | Read policy section, verify Rego example matches `policy/default.rego` |
| MCP setup walkthrough works end-to-end | SKILL-03 | Requires live MCP server | Follow setup steps in skill, verify `adssh-mcp` connects and tools respond |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 1s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
