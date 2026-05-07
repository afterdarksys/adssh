---
phase: 04-adssha-agent
fixed_at: 2026-05-07T00:00:00Z
review_path: .planning/phases/04-adssha-agent/04-REVIEW.md
iteration: 1
findings_in_scope: 7
fixed: 7
skipped: 0
status: all_fixed
---

# Phase 04: Code Review Fix Report

**Fixed at:** 2026-05-07T00:00:00Z
**Source review:** .planning/phases/04-adssha-agent/04-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 7
- Fixed: 7
- Skipped: 0

## Fixed Issues

### CR-01: `resp.Content[0].Text` silently returns empty string for non-text content blocks

**Files modified:** `starlarkext/libagent.go`
**Commit:** cd085f7
**Applied fix:** Replaced direct `resp.Content[0].Text` access with a loop over all content blocks that finds the first block with `Type == "text"`. If no text block is found (e.g. thinking or tool_use is first), returns a descriptive error including stop_reason and first block type instead of silently appending an empty string to conversation history.

---

### CR-02: `builtinTCPSend` hardcodes `InsecureSkipVerify: true` — TLS verification unconditionally disabled

**Files modified:** `starlarkext/net.go`
**Commit:** 0b1931a
**Applied fix:** Added `skip_verify?` optional parameter (default `false`) to `builtinTCPSend`, matching the existing pattern in `builtinDialTLS`. The TLS dial now uses `InsecureSkipVerify: skipVerify` (caller-controlled) instead of the hardcoded `true`. TLS connections now verify certificates by default.

---

### CR-03: `builtinPcreMatch` silently swallows regex match error

**Files modified:** `starlarkext/starlarkext.go`
**Commit:** 5cdcc75
**Applied fix:** Changed `matched, _ := re.MatchString(text)` to `matched, err := re.MatchString(text)` and added an `if err != nil` check that returns the error to the Starlark caller. Timeout and internal regexp2 failures now surface as errors rather than silently returning `false`.

---

### WR-01: `os.UserHomeDir()` error silently ignored — path resolution fails silently

**Files modified:** `starlarkext/libagent.go`
**Commit:** cc5e040
**Applied fix:** Changed `home, _ := os.UserHomeDir()` to capture and check the error. Returns `fmt.Errorf("cannot determine home directory: %v", err)` immediately if `UserHomeDir` fails, rather than proceeding with an empty string that produces a misleading root-relative path.

---

### WR-02: Agent `env` parameter in `createLoadAgent` is accepted but never used

**Files modified:** `starlarkext/libagent.go`
**Commit:** cb0b03f
**Applied fix:** Added `_ = env` with a comment: "env is reserved for future injection of Starlark globals into agent tool calls." This makes the intent explicit and prevents the parameter from being overlooked in future changes.

---

### WR-03: `TestLoadAgentNoAPIKey` writes a real file to the user's home directory

**Files modified:** `starlarkext/libagent_test.go`
**Commit:** 76763ee
**Applied fix:** Replaced the `~/.adssh/agents/` write with `t.TempDir()` as the synthetic home directory, set via `t.Setenv("HOME", tmpHome)`. The agent file is created inside the temp dir and cleaned up automatically by the test framework. The manual `defer os.Remove(agentFile)` and manual API key save/restore were removed in favour of `t.Setenv("ANTHROPIC_API_KEY", "")`.

---

### WR-04: `go.mod` specifies `go 1.26.2` — not a released Go version

**Files modified:** `go.mod`
**Commit:** 6438993
**Applied fix:** Changed `go 1.26.2` to `go 1.24.2` and ran `go mod tidy`, which resolved the directive to `go 1.25.5` (the actual installed toolchain). The bogus unreleased version that could trigger unpredictable toolchain auto-download behaviour is gone.

---

_Fixed: 2026-05-07T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
