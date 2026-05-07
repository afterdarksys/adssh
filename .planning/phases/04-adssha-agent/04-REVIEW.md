---
phase: 04-adssha-agent
reviewed: 2026-05-07T00:00:00Z
depth: standard
files_reviewed: 6
files_reviewed_list:
  - agents/adssha.md
  - starlarkext/libagent.go
  - starlarkext/libagent_test.go
  - starlarkext/starlarkext.go
  - go.mod
  - go.sum
findings:
  critical: 3
  warning: 4
  info: 2
  total: 9
status: issues_found
---

# Phase 04: Code Review Report

**Reviewed:** 2026-05-07T00:00:00Z
**Depth:** standard
**Files Reviewed:** 6
**Status:** issues_found

## Summary

This phase introduces the ADSSHA agent definition (`agents/adssha.md`) and the `sys.load_agent` Starlark builtin (`starlarkext/libagent.go`), plus incidental changes to `starlarkext/starlarkext.go` and module files. The agent definition file itself is well-structured. The core implementation in `libagent.go` has one critical correctness bug (incorrect response content extraction), one security issue inherited from `net.go` (hardcoded `InsecureSkipVerify: true` in `tcp_send`), and one silent error discard that will produce a confusing failure path.

`starlarkext.go` carries a pre-existing but reviewed-here security defect in `builtinPcreMatch` (ignored regex match error). The `go.mod` file specifies `go 1.26.2`, which is not a released Go version as of the review date — likely a typo.

---

## Critical Issues

### CR-01: `resp.Content[0].Text` silently returns empty string for non-text content blocks

**File:** `starlarkext/libagent.go:107`
**Issue:** `resp.Content[0].Text` accesses the `Text` field of a `ContentBlockUnion` union struct. In the Anthropic Go SDK v1.41.0, `ContentBlockUnion` is a flattened struct where `.Text` is always present but is an empty string when the first block is not a `TextBlock` (e.g., when it is a `tool_use`, `thinking`, or `redacted_thinking` block). The code checks `len(resp.Content) == 0` above, but does not check `resp.Content[0].Type == "text"`. When the model returns a non-text first block the Starlark caller receives a silent empty string with no error, and that empty string is appended to history — corrupting subsequent turns.

This is not a hypothetical: the agent definition in `agents/adssha.md` calls itself an autonomous DevOps orchestrator; if the model ever emits a `thinking` block first (extended thinking mode) or if a future caller passes `tools` to the API, the response will silently mangle history.

**Fix:**
```go
if len(resp.Content) == 0 {
    return nil, fmt.Errorf("agent returned empty response (stop_reason: %s)", resp.StopReason)
}
// Guard: extract text from the first TextBlock only.
var text string
for _, block := range resp.Content {
    if block.Type == "text" {
        text = block.Text
        break
    }
}
if text == "" {
    return nil, fmt.Errorf("agent response contained no text block (stop_reason: %s, first block type: %s)", resp.StopReason, resp.Content[0].Type)
}
history = append(history, resp.ToParam())
return starlark.String(text), nil
```

---

### CR-02: `builtinTCPSend` hardcodes `InsecureSkipVerify: true` — TLS verification unconditionally disabled

**File:** `starlarkext/net.go:48`
**Issue:** When `use_tls=True` is passed to `tcp_send`, the TLS dial is made with `InsecureSkipVerify: true` — hardcoded, not controlled by the caller. This makes TLS offer no security: any MitM attacker can intercept the connection. The `builtinDialTLS` function (line 88) exposes `skip_verify?` as an optional parameter (defaulting `false`) and is correct; `builtinTCPSend`'s TLS path is inconsistent and always insecure.

Although `net.go` is not a file newly introduced in this phase, it is in scope because it is listed for review and the pattern was introduced in the codebase being reviewed.

**Fix:**
```go
// Add skip_verify? parameter, default false, matching dial_tls:
var addr, data string
var useTLS, skipVerify bool
if err := starlark.UnpackArgs(b.Name(), args, kwargs,
    "addr", &addr, "data", &data, "use_tls?", &useTLS, "skip_verify?", &skipVerify); err != nil {
    return nil, err
}
// ...
if useTLS {
    conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: skipVerify})
}
```

---

### CR-03: `builtinPcreMatch` silently swallows regex match error

**File:** `starlarkext/starlarkext.go:146`
**Issue:** The second return value from `re.MatchString(text)` is discarded with `_`. The `regexp2` library returns an error when the match times out (via `regexp2`'s timeout mechanism) or encounters an internal failure. Silently discarding this error means callers receive `false` (no match) when the pattern actually failed to execute — a correctness bug that is also a potential security issue: a policy-checking Starlark script using `re.pcre_match` for access-control logic would silently "pass" when the regex engine errors.

```go
matched, _ := re.MatchString(text)
```

**Fix:**
```go
matched, err := re.MatchString(text)
if err != nil {
    return nil, fmt.Errorf("pcre_match error: %v", err)
}
return starlark.Bool(matched), nil
```

---

## Warnings

### WR-01: `os.UserHomeDir()` error silently ignored — path resolution fails silently

**File:** `starlarkext/libagent.go:55`
**Issue:** `home, _ := os.UserHomeDir()` discards the error. When `UserHomeDir` fails (e.g., `$HOME` not set, running in a minimal container), `home` is an empty string and the path resolves to `/.adssh/agents/<name>.md`. The subsequent `os.ReadFile` will fail, but the error message will show a misleading absolute path from root rather than a home-relative one, making diagnosis harder.

**Fix:**
```go
home, err := os.UserHomeDir()
if err != nil {
    return starlark.None, fmt.Errorf("cannot determine home directory: %v", err)
}
```

---

### WR-02: Agent `env` parameter in `createLoadAgent` is accepted but never used

**File:** `starlarkext/libagent.go:43`
**Issue:** `createLoadAgent(env starlark.StringDict)` accepts `env` as a parameter (consistent with the pattern for `createLoadPlugin`, `createExecCmd`, etc.), but the inner callable never references it. Accepting it without using it creates a false expectation that the agent callable can access the Starlark environment. If a future change to the outer function needs `env` (e.g., to inject Starlark globals into the agent's tool context), the silently-captured-but-unused variable will be overlooked.

This is a warning rather than a blocker because it does not cause incorrect behavior today, but it is a misleading API surface.

**Fix:** Either document explicitly why `env` is reserved for future use:
```go
// env is reserved for future injection of Starlark globals into agent tool calls.
_ = env
```
Or remove the parameter and add it back when actually needed.

---

### WR-03: `TestLoadAgentNoAPIKey` writes a real file to the user's home directory

**File:** `starlarkext/libagent_test.go:125-133`
**Issue:** The test creates `~/.adssh/agents/testnokey.md` on the developer's real machine (not a temp directory). While it defers `os.Remove`, if the test panics or is killed between write and defer, the file persists. More importantly, running tests in CI environments that share a home directory will pollute real state. The `os.MkdirAll(agentDir, 0755)` call also creates the live configuration directory if it does not exist, which is a side effect of running tests.

**Fix:** Use `t.TempDir()` and set `HOME` to point at it:
```go
tmpHome := t.TempDir()
t.Setenv("HOME", tmpHome)
agentDir := filepath.Join(tmpHome, ".adssh", "agents")
```

---

### WR-04: `go.mod` specifies `go 1.26.2` — not a released Go version

**File:** `go.mod:3`
**Issue:** As of the review date (2026-05-07), Go 1.26 has not been released (latest stable is Go 1.24.x). A `go` directive set to a non-released version can cause `go mod tidy` and `go build` to behave unpredictably with toolchain auto-download logic introduced in Go 1.21. If this is a typo for `go 1.24.2` or `go 1.23.2`, it should be corrected before the module is built in CI.

**Fix:** Correct to the actual minimum required Go version, e.g.:
```
go 1.24.2
```

---

## Info

### IN-01: `..hidden` path traversal test case description is misleading

**File:** `starlarkext/libagent_test.go:80`
**Issue:** The test case `{"..hidden", true}` is named as if it is a path traversal test case. The comment at line 81 explains it is expected to fail, but the test name `..hidden` and the table comment both suggest the test is about hidden files rather than path traversal. The real concern is `..` appearing anywhere in the name. The test is correct (the guard at `libagent.go:51` does catch `..hidden`), but the test description does not explain why this name is dangerous — it looks like a hidden-file check to the reader.

**Fix:** Rename the test case to clarify the intent:
```go
{"..hidden", true},  // starts with .. — caught by Contains(..) check
```

---

### IN-02: `MaxTokens` hardcoded to 4096 with no caller override

**File:** `starlarkext/libagent.go:96`
**Issue:** `MaxTokens: 4096` is hardcoded in the API call. This is fine for most uses, but the `agents/adssha.md` system prompt describes multi-step orchestration that may require longer responses. There is no mechanism for callers to pass a higher limit, and no documentation that 4096 is the cap. This is informational: it may become a practical problem when ADSSHA generates long structured outputs.

**Fix:** Consider reading a `max_tokens` field from the agent frontmatter:
```go
type agentFrontmatter struct {
    // ...
    MaxTokens int64 `toml:"max_tokens"`
}
// then: if fm.MaxTokens > 0 { maxTokens = fm.MaxTokens }
```

---

_Reviewed: 2026-05-07T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
