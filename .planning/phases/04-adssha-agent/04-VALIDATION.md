---
phase: 4
slug: adssha-agent
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-07
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test |
| **Config file** | none — standard `go test ./...` |
| **Quick run command** | `go build ./...` |
| **Full suite command** | `go test ./starlarkext/... -v -run TestLoadAgent` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `go build ./...`
- **After every plan wave:** Run `go test ./starlarkext/... -v`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 4-01-01 | 01 | 1 | AGENT-01 | — | N/A | build | `go build ./...` | ✅ | ⬜ pending |
| 4-01-02 | 01 | 1 | AGENT-01 | — | N/A | unit | `go test ./starlarkext/... -run TestLoadAgent` | ❌ W0 | ⬜ pending |
| 4-02-01 | 02 | 1 | AGENT-02 | — | N/A | manual | manual smoke test | ✅ | ⬜ pending |
| 4-03-01 | 03 | 2 | AGENT-03 | — | N/A | manual | `adssh eval 'agent = sys.load_agent("adssha"); print(agent("hello"))'` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `starlarkext/starlarkext_test.go` — stubs for AGENT-01 (sys.load_agent exists in sys dict)
- [ ] `starlarkext/libagent_test.go` — stubs for AGENT-01 (createLoadAgent returns callable)

*If none: "Existing infrastructure covers all phase requirements."*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `agent("hello")` calls Claude API and returns string | AGENT-02 | Requires live ANTHROPIC_API_KEY and network | Set ANTHROPIC_API_KEY, run `adssh eval 'agent = sys.load_agent("adssha"); print(agent("hello"))'` |
| Multi-turn history works across calls | AGENT-02 | Requires live API | Call agent twice in sequence; verify second call references first response context |
| `sys.load_agent("nonexistent")` returns helpful error | AGENT-01 | Runtime behavior | Run without agent file installed; verify error message includes copy path |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
