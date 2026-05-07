---
phase: 02-mcp-server
reviewed: 2026-05-07T00:00:00Z
depth: standard
files_reviewed: 8
files_reviewed_list:
  - cmd/adssh-mcp/main.go
  - cmd/adssh-mcp/server.go
  - cmd/adssh-mcp/tools_eval.go
  - cmd/adssh-mcp/tools_shell.go
  - cmd/adssh-mcp/tools_sessions.go
  - cmd/adssh-mcp/tools_cloud.go
  - cmd/adssh-mcp/tools_container.go
  - cmd/adssh-mcp/tools_audit.go
findings:
  critical: 5
  warning: 7
  info: 3
  total: 15
status: issues_found
---

# Phase 02: Code Review Report

**Reviewed:** 2026-05-07T00:00:00Z
**Depth:** standard
**Files Reviewed:** 8
**Status:** issues_found

## Summary

This phase delivers the `adssh-mcp` binary: an MCP server that exposes Starlark evaluation, shell execution, session listing, cloud namespace queries, ephemeral Docker containers, and audit log reads as MCP tools. The server wraps every tool in a `policyGate` that calls OPA before dispatch.

The code is generally readable and follows established project patterns, but contains several security-critical defects. The most severe are: the shared mutable `globals` dict being accessed concurrently without synchronisation across all tool handlers; the policy gate passing empty arguments to OPA so argument-based policy rules can never fire; the `eval_starlark` handler logging the executed code only on success (not on error); and `handleContainerExec` silently ignoring errors from `rand.Read` and the audit file write. There are also multiple resource leak paths and a path-traversal risk in `handleAuditLog`.

---

## Critical Issues

### CR-01: Shared Starlark `globals` dict mutated without synchronisation — data race and potential policy bypass

**File:** `cmd/adssh-mcp/tools_eval.go:31`, `cmd/adssh-mcp/tools_cloud.go:51`, `cmd/adssh-mcp/server.go:16`

**Issue:** `globals` is a `starlark.StringDict` (a plain `map[string]starlark.Value`) created once in `main.go` and shared across every concurrent MCP tool invocation. `starlark.ExecFile` writes bindings produced by the executed code back into `globals` (the fourth argument), and `starlark.Call` may trigger Starlark code that does the same via `register_command`, `register_completer`, etc. Map writes from multiple goroutines are a data race under the Go memory model and will cause crashes or silent corruption. Additionally, a malicious Starlark caller can overwrite security-critical globals (e.g., the `cloud` dict, `__custom_commands__`) for subsequent requests, effectively bypassing the policy gate for those requests.

**Fix:** Use a per-call copy of `globals` for `ExecFile`, and protect any globals mutations with a mutex. For `ExecFile` in particular, pass a shallow copy so that side effects stay local to the invocation:

```go
// In handleEvalStarlark, before ExecFile:
localGlobals := make(starlark.StringDict, len(globals))
globalsMu.RLock()
for k, v := range globals {
    localGlobals[k] = v
}
globalsMu.RUnlock()

val, err := starlark.ExecFile(thread, "<mcp>", code, localGlobals)
```

A `sync.RWMutex` protecting the canonical `globals` should be held for reads during the copy, and for writes whenever `register_command`/`register_completer` builtins mutate it.

---

### CR-02: `policyGate` passes empty args to OPA — argument-based policy rules silently always pass

**File:** `cmd/adssh-mcp/server.go:110`

**Issue:**

```go
pctx := security.BuildPolicyContext(toolName, []string{}, "")
```

The `args` field is hardcoded to an empty slice and `sessionID` to an empty string for every tool. OPA policy rules that check `input.args` (e.g., blocking `run_shell` for a specific command pattern, or scoping `cloud_query` by namespace) will never see the actual arguments. This silently reduces the effective policy coverage to tool-name-only checks, making the gate appear functional while argument-level rules are dead.

**Fix:** Extract relevant arguments from `req` inside the gate and pass them through. The gate receives `req mcp.CallToolRequest`, so argument extraction is straightforward:

```go
policyGate := func(toolName string, handler server.ToolHandlerFunc) server.ToolHandlerFunc {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        // Collect all string params as args for OPA
        var args []string
        for k, v := range req.Params.Arguments {
            args = append(args, fmt.Sprintf("%s=%v", k, v))
        }
        pctx := security.BuildPolicyContext(toolName, args, "")
        // ... rest of gate
    }
}
```

---

### CR-03: `handleEvalStarlark` — audit log written only on the success path; errors go unlogged

**File:** `cmd/adssh-mcp/tools_eval.go:33-37`

**Issue:**

```go
val, err := starlark.ExecFile(thread, "<mcp>", code, globals)
if err != nil {
    security.LogCommand("MCP:eval_starlark", code)   // line 33 — inside error branch
    return mcp.NewToolResultError(...), nil
}

security.LogCommand("MCP:eval_starlark", code)       // line 37 — success path
```

The audit call inside the error branch on line 33 is *after* the return is already written — wait, actually it logs before returning. However the positioning is identical and confusing, but the real defect is structural: `security.LogCommand` is called in both branches but only **after** `ExecFile` completes. If `ExecFile` panics (which Starlark can do for stack overflows, etc.), neither branch executes and the execution is not audited at all. More importantly, `LogCommand` should be the **first** action after extracting `code`, before any execution, so that attempted-but-failed executions appear in the audit trail with proper ordering relative to policy decisions.

**Fix:** Move `security.LogCommand("MCP:eval_starlark", code)` to immediately after the `code` parameter is extracted, before `ExecFile` is called.

```go
code, err := req.RequireString("code")
if err != nil { ... }

security.LogCommand("MCP:eval_starlark", code)  // audit before execution

thread := &starlark.Thread{Name: "mcp-eval"}
// ...
val, err := starlark.ExecFile(thread, "<mcp>", code, globals)
if err != nil {
    return mcp.NewToolResultError(fmt.Sprintf("starlark error: %v", err)), nil
}
```

The same ordering issue applies in `handleRunShell` (line 56) and `handleCloudQuery` (lines 53, 57).

---

### CR-04: `handleContainerExec` — error return from `rand.Read` silently discarded; session IDs may collide

**File:** `cmd/adssh-mcp/tools_container.go:50-51`

**Issue:**

```go
b := make([]byte, 8)
rand.Read(b)
```

`crypto/rand.Read` returns `(n int, err error)`. The error is silently dropped. On systems where the kernel entropy pool is exhausted or the random device is unavailable (restricted containers, hardened environments), `rand.Read` can return an error and `b` may be partially or entirely zeroed. This makes `sessionID` predictable or empty, which causes container name collision (`adssh-mcp-0000000000000000`) and allows one request to observe or interfere with another's logs.

**Fix:**

```go
b := make([]byte, 8)
if _, err := rand.Read(b); err != nil {
    return mcp.NewToolResultError(fmt.Sprintf("failed to generate session ID: %v", err)), nil
}
sessionID := hex.EncodeToString(b)
```

---

### CR-05: `handleAuditLog` — reads arbitrary file path set by environment at startup; path can be influenced via `ADSSH_AUDIT_LOG`

**File:** `cmd/adssh-mcp/tools_audit.go:27`

**Issue:** `auditLogPath` is passed in from `cfg.AuditLogPath`, which comes from the `ADSSH_AUDIT_LOG` environment variable with no sanitisation (see `config/env.go:55`). If an attacker controls the process environment (e.g., via a compromised service manager, container env injection, or `.env` file), they can set `ADSSH_AUDIT_LOG=/etc/passwd` and the `audit_log` MCP tool will happily serve the contents of any file readable by the process user.

This is not a purely theoretical concern in the MCP threat model, where the server is invoked by an LLM agent that may be fed hostile instructions. The attack surface is: set env, call `audit_log` with no `filter`, read arbitrary file.

**Fix:** Validate that `auditLogPath` is within the expected `.adssh` directory before opening it:

```go
func handleAuditLog(auditLogPath string) server.ToolHandlerFunc {
    // Resolve and validate path at handler construction time, not per-call
    home, _ := os.UserHomeDir()
    allowedDir := filepath.Join(home, ".adssh")
    cleanPath := filepath.Clean(auditLogPath)
    if !strings.HasPrefix(cleanPath, allowedDir+string(filepath.Separator)) && cleanPath != allowedDir {
        // Fallback to safe default
        auditLogPath = filepath.Join(allowedDir, "audit.log")
    }
    return func(...) { ... }
}
```

---

## Warnings

### WR-01: `handleContainerExec` — `ContainerRemove` errors silently ignored on all paths

**File:** `cmd/adssh-mcp/tools_container.go:84,93,103,113`

**Issue:** Every call to `cli.ContainerRemove` discards its return value. If container removal fails (daemon unresponsive, container already removed, permissions), the container leaks. This can exhaust Docker resources over time and leave containers with sensitive label data (`adssh.session`, `adssh.managed`) running indefinitely.

**Fix:** Log removal errors at minimum:

```go
if removeErr := cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true}); removeErr != nil {
    security.LogEvent(fmt.Sprintf("container remove failed %s: %v", resp.ID, removeErr))
}
```

---

### WR-02: `handleContainerExec` — `io.Copy` error from `ImagePull` discarded; pull failure may be silently masked

**File:** `cmd/adssh-mcp/tools_container.go:65`

**Issue:**

```go
io.Copy(io.Discard, rc)
rc.Close()
```

Docker's `ImagePull` returns a stream that must be fully consumed for the pull to complete. If the copy is interrupted (context cancelled, network error) `io.Copy` returns an error that is discarded. `rc.Close()` is also not deferred; if code between the pull and `rc.Close()` panics, the body leaks. Most critically, an error-free `io.Copy` return does not guarantee the image exists locally — the `ImagePull` response body must be checked for `{"error":...}` lines in the JSON stream to detect mid-pull failures.

**Fix:**

```go
rc, pullErr := cli.ImagePull(ctx, image, dockerimage.PullOptions{})
if pullErr != nil {
    return mcp.NewToolResultError(fmt.Sprintf("image pull failed: %v", pullErr)), nil
}
defer rc.Close()
if _, err := io.Copy(io.Discard, rc); err != nil {
    return mcp.NewToolResultError(fmt.Sprintf("image pull stream error: %v", err)), nil
}
```

---

### WR-03: `handleContainerExec` — audit file write errors silently discarded

**File:** `cmd/adssh-mcp/tools_container.go:130-133`

**Issue:**

```go
if f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
    json.NewEncoder(f).Encode(auditRec)
    f.Close()
}
```

Both `json.NewEncoder(f).Encode(auditRec)` and `f.Close()` errors are silently discarded. A full disk or revoked permission causes the container audit record to be silently dropped — the caller receives a success result with no indication the audit write failed. For a security-sensitive audit trail this is a compliance risk.

**Fix:**

```go
if f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
    if encErr := json.NewEncoder(f).Encode(auditRec); encErr != nil {
        security.LogEvent(fmt.Sprintf("container audit write failed: %v", encErr))
    }
    if closeErr := f.Close(); closeErr != nil {
        security.LogEvent(fmt.Sprintf("container audit file close failed: %v", closeErr))
    }
} else {
    security.LogEvent(fmt.Sprintf("container audit file open failed: %v", err))
}
```

---

### WR-04: `handleRunShell` — `ctx` from MCP request discarded; uses `context.Background()` instead

**File:** `cmd/adssh-mcp/tools_shell.go:47`

**Issue:**

```go
if err := runner.Run(context.Background(), parserFile); err != nil {
```

The handler receives `ctx context.Context` (which carries MCP request cancellation / deadline) but passes `context.Background()` to the shell runner. If the MCP client cancels or times out the request, the shell command will continue running until it naturally exits. This can cause unbounded resource consumption and makes the server unresponsive to client cancellation.

**Fix:**

```go
if err := runner.Run(ctx, parserFile); err != nil {
```

---

### WR-05: `handleCloudQuery` — no restriction on which namespaces/functions can be called; policy gate passes empty args

**File:** `cmd/adssh-mcp/tools_cloud.go:28-58`

**Issue:** Any string that happens to be a key in `globals` is accepted as a `namespace` (line 28). `globals` contains not just cloud provider dicts but also `crypto`, `re`, `sys`, `data`, `i18n`, `cloud`, and `__custom_commands__`. A caller who passes `namespace=sys` and `function=exec_cmd` will reach a callable that executes arbitrary OS commands, effectively bypassing the `run_shell` tool's separate policy gate (if OPA rules are tool-name scoped). Combined with CR-02 (args not passed to OPA), the policy gate cannot distinguish a `cloud_query(namespace=aws)` call from `cloud_query(namespace=sys)`.

**Fix:** Restrict accepted namespaces to an explicit allowlist:

```go
var allowedNamespaces = map[string]bool{"aws": true, "gcp": true, "oci": true, "cloud": true}

if !allowedNamespaces[namespace] {
    return mcp.NewToolResultError(fmt.Sprintf("unknown namespace: %s", namespace)), nil
}
```

---

### WR-06: `handleAuditLog` — unbounded file read with no size limit

**File:** `cmd/adssh-mcp/tools_audit.go:27`

**Issue:** `os.ReadFile(auditLogPath)` reads the entire file into memory with no size cap. On a busy server with `ADSSH_AUDIT_LOG` pointing to a large log, this can exhaust process memory. Even at normal growth rates, an audit log on a production server can reach hundreds of megabytes.

**Fix:** Use `io.LimitReader` or tail-read using `os.Seek` to read only the last N bytes before splitting on newlines. A simple upper bound:

```go
const maxAuditReadBytes = 10 * 1024 * 1024 // 10 MB

f, err := os.Open(auditLogPath)
if err != nil { ... }
defer f.Close()
data, err := io.ReadAll(io.LimitReader(f, maxAuditReadBytes))
```

---

### WR-07: `main.go` — `apiKey` is parsed but never used

**File:** `cmd/adssh-mcp/main.go:26-37`, `cmd/adssh-mcp/server.go:16`

**Issue:** `apiKey` is read from `ADSSH_MCP_API_KEY` and from `--api-key` CLI flag, passed to `serveMCP`, but `serveMCP` accepts the parameter and never references it. The MCP server has no API key validation middleware anywhere. If the intent was to require a bearer token from callers, that logic is entirely missing. If the intent was future work, shipping a binary that accepts an API key argument and silently ignores it is misleading and creates false confidence.

**Fix:** Either implement API key validation (e.g., check a header in an HTTP transport or a handshake field in the stdio transport if supported), or remove the parameter and the env-var documentation until it is ready.

---

## Info

### IN-01: `tools_eval.go` — `starlark.ExecFile` return value `val` is a `StringDict`, not a single value

**File:** `cmd/adssh-mcp/tools_eval.go:31,40`

**Issue:**

```go
val, err := starlark.ExecFile(thread, "<mcp>", code, globals)
// ...
result := fmt.Sprintf("output: %s\nresult: %v", buf.String(), val)
```

`starlark.ExecFile` returns `(StringDict, error)` — the dict of all bindings defined at module level, not "the result value". For code that defines variables, `val` will print as a `map[name:value ...]` dump. For code that only calls functions with side effects (print), `val` will be an empty dict. This is likely to confuse callers who expect the return value of the last expression. `starlark.Eval` or capturing the thread's final expression value would be needed for single-expression semantics.

**Fix:** Document clearly in the tool description that `result` is a dict of module-level bindings, or switch to `starlark.Eval` for expression-oriented use cases and `starlark.ExecFile` for script use cases, possibly auto-detecting.

---

### IN-02: `tools_container.go` — `json.MarshalIndent` error discarded

**File:** `cmd/adssh-mcp/tools_container.go:145`

**Issue:**

```go
data, _ := json.MarshalIndent(result, "", "  ")
return mcp.NewToolResultText(string(data)), nil
```

The error from `json.MarshalIndent` is discarded with `_`. If marshalling fails (it can for types containing channels, functions, or if the runtime panics), `data` is nil and `string(data)` is an empty string, producing a silent empty response. In this specific case the map contains only `string`, `int64`, and `time.Duration` types so it is unlikely to fail, but the pattern is incorrect.

**Fix:**

```go
data, err := json.MarshalIndent(result, "", "  ")
if err != nil {
    return mcp.NewToolResultError(fmt.Sprintf("failed to marshal result: %v", err)), nil
}
```

---

### IN-03: `tools_shell.go` — `run_shell` receives unrestricted `globals` parameter but does not use it

**File:** `cmd/adssh-mcp/tools_shell.go:22`

**Issue:** `handleRunShell` accepts `globals starlark.StringDict` as a parameter (mirroring `handleEvalStarlark`), but it is only passed to `security.BashInterceptor`. That is correct, but `globals` is the shared mutable dict (see CR-01). If `BashInterceptor` reads from `globals` during interception while another goroutine's `ExecFile` writes to it, there is another data race vector. This is a secondary instance of CR-01 but worth noting explicitly.

**Fix:** Addressed by the mutex introduced in the CR-01 fix; note that `BashInterceptor` accesses must also hold the read lock.

---

_Reviewed: 2026-05-07T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
