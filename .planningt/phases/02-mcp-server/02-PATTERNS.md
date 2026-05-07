# Phase 2: MCP Server - Pattern Map

**Mapped:** 2026-05-06
**Files analyzed:** 7 new/modified files
**Analogs found:** 7 / 7

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `cmd/adssh-mcp/main.go` | entrypoint | request-response | `main.go` | exact |
| `cmd/adssh-mcp/server.go` | service | request-response | `starlarkext/exec.go` | role-match |
| `cmd/adssh-mcp/tools_eval.go` | handler | request-response | `starlarkext/exec.go` | exact |
| `cmd/adssh-mcp/tools_shell.go` | handler | request-response | `starlarkext/exec.go` + `security/interceptor.go` | exact |
| `cmd/adssh-mcp/tools_sessions.go` | handler | request-response | `sys/session.go` | exact |
| `cmd/adssh-mcp/tools_audit.go` | handler | request-response | `security/audit.go` | role-match |
| `cmd/adssh-mcp/tools_cloud.go` | handler | request-response | `starlarkext/starlarkext.go` | role-match |

## Pattern Assignments

### `cmd/adssh-mcp/main.go` (entrypoint, request-response)

**Analog:** `main.go`

**Imports pattern** (lines 1-17):
```go
package main

import (
	"fmt"
	"os"

	"go.starlark.net/resolve"
	"go.starlark.net/starlark"

	"adssh/config"
	"adssh/security"
	"adssh/starlarkext"
)
```

**Startup initialization pattern** (lines 27-88) — copy this exact sequence:
```go
// 1. Load configuration from ADSSH_* environment variables
cfg := config.LoadFromEnv()

// 2. Parse CLI flags (--policy, --api-key, etc.)
for i := 1; i < len(os.Args); i++ {
    arg := os.Args[i]
    switch {
    case (arg == "--policy") && i+1 < len(os.Args):
        cfg.PolicyPath = os.Args[i+1]
        i++
    // add --api-key, --listen here
    }
}

// 3. Initialize audit logging
security.InitAuditLog(cfg.AuditLogPath, cfg.AuditURL, cfg.AuditToken)

// 4. Load Rego policy engine
if err := security.LoadPolicy(cfg.PolicyPath); err != nil {
    fmt.Fprintf(os.Stderr, "Warning: failed to load policy from %s: %v\n", cfg.PolicyPath, err)
} else {
    security.LogEvent(fmt.Sprintf("Policy loaded from %s", cfg.PolicyPath))
}

// 5. Build Starlark environment (globals shared across all tool calls)
globals := starlark.StringDict{}
starlarkext.SetupExtensions(globals, false)
```

**Starlark resolve init pattern** (lines 19-24):
```go
func init() {
    resolve.AllowSet = true
    resolve.AllowGlobalReassign = true
    resolve.AllowRecursion = true
}
```

**Error exit pattern** (lines 114-119):
```go
if err := startMCPServer(cfg, globals); err != nil {
    fmt.Fprintf(os.Stderr, "Failed to start MCP server: %v\n", err)
    os.Exit(1)
}
```

---

### `cmd/adssh-mcp/server.go` (service, request-response)

**Analog:** `starlarkext/exec.go` (wiring pattern), `config/env.go` (config extension pattern)

**Config extension pattern** — add MCP-specific fields to a local MCPConfig struct that embeds AppConfig:
```go
// From config/env.go lines 27-42 — copy AppConfig fields, extend with MCP fields:
type MCPConfig struct {
    config.AppConfig
    ListenAddr string // ADSSH_MCP_LISTEN, default :7779
    APIKey     string // ADSSH_MCP_API_KEY
}

func loadMCPConfig() MCPConfig {
    base := config.LoadFromEnv()
    return MCPConfig{
        AppConfig:  base,
        ListenAddr: envOr("ADSSH_MCP_LISTEN", ":7779"),
        APIKey:     os.Getenv("ADSSH_MCP_API_KEY"),
    }
}
```

**API key auth middleware pattern** — minimal HTTP middleware wrapping the MCP handler:
```go
func withAPIKeyAuth(apiKey string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if apiKey != "" {
            got := r.Header.Get("Authorization")
            if got != "Bearer "+apiKey {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
        }
        next.ServeHTTP(w, r)
    })
}
```

---

### `cmd/adssh-mcp/tools_eval.go` (handler, request-response)

**Analog:** `starlarkext/exec.go` lines 17-43

**Core tool handler pattern** — copy the per-call thread + globals approach from `createExecCmd`:
```go
// From starlarkext/exec.go lines 17-43
// Key: create a NEW thread per call; globals is the SHARED dict initialized at startup.
func handleEvalStarlark(globals starlark.StringDict) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        code := req.Params.Arguments["code"].(string)

        // Policy check before execution (copy from interceptor.go lines 23-35)
        pctx := security.BuildPolicyContext("eval_starlark", []string{}, "")
        allowed, reason, policyErr := security.EvaluatePolicy(pctx)
        if policyErr != nil {
            return nil, fmt.Errorf("policy evaluation error: %v", policyErr)
        }
        if !allowed {
            security.LogPolicyDecision(pctx.User, "eval_starlark", false, reason)
            return mcp.NewToolResultError(fmt.Sprintf("access denied: %s", reason)), nil
        }
        security.LogPolicyDecision(pctx.User, "eval_starlark", true, "")

        // New thread per evaluation (from interceptor.go line 45)
        thread := &starlark.Thread{Name: "mcp-eval"}
        var buf bytes.Buffer
        thread.Print = func(_ *starlark.Thread, msg string) { buf.WriteString(msg + "\n") }

        val, err := starlark.ExecFile(thread, "<mcp>", code, globals)
        if err != nil {
            security.LogCommand("MCP:eval_starlark", code)
            return mcp.NewToolResultError(err.Error()), nil
        }
        security.LogCommand("MCP:eval_starlark", code)

        return mcp.NewToolResultText(fmt.Sprintf("output: %s\nresult: %v", buf.String(), val)), nil
    }
}
```

---

### `cmd/adssh-mcp/tools_shell.go` (handler, request-response)

**Analog:** `starlarkext/exec.go` lines 17-43 AND `security/interceptor.go` lines 13-114

**Shell execution pattern** — copy from `createExecCmd` exactly, separate stdout/stderr buffers:
```go
// From starlarkext/exec.go lines 29-41
var stdout, stderr bytes.Buffer
runner, _ := interp.New(
    interp.StdIO(nil, &stdout, &stderr),
    interp.ExecHandlers(security.BashInterceptor(false, globals)),
    interp.OpenHandler(security.VirtualOpenHandler()),
)

parserFile, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
if err != nil {
    return mcp.NewToolResultError(fmt.Sprintf("parse error: %v", err)), nil
}

exitCode := 0
if err := runner.Run(context.Background(), parserFile); err != nil {
    if status, ok := interp.IsExitStatus(err); ok {
        exitCode = int(status)
    } else {
        return mcp.NewToolResultError(err.Error()), nil
    }
}
```

**Policy check pattern** (from `security/interceptor.go` lines 23-35) — apply before runner.Run:
```go
pctx := security.BuildPolicyContext(args[0], args[1:], "")
allowed, reason, policyErr := security.EvaluatePolicy(pctx)
if policyErr != nil {
    return nil, fmt.Errorf("adssh: policy evaluation error: %v", policyErr)
}
if !allowed {
    security.LogPolicyDecision(pctx.User, cmd, false, reason)
    if reason != "" {
        return mcp.NewToolResultError(fmt.Sprintf("access denied: %s", reason)), nil
    }
    return mcp.NewToolResultError(fmt.Sprintf("access denied for '%s' by policy", args[0])), nil
}
security.LogPolicyDecision(pctx.User, cmd, true, "")
```

---

### `cmd/adssh-mcp/tools_sessions.go` (handler, request-response)

**Analog:** `sys/session.go` lines 107-115

**ListSessions pattern** (lines 107-115):
```go
// From sys/session.go
func ListSessions() []string {
    sessionsMu.RLock()
    defer sessionsMu.RUnlock()
    var ids []string
    for id := range globalSessions {
        ids = append(ids, id)
    }
    return ids
}

// GetSession for per-session detail (lines 101-105):
func GetSession(id string) *Session {
    sessionsMu.RLock()
    defer sessionsMu.RUnlock()
    return globalSessions[id]
}
```

**Tool handler pattern** — serialize Session fields to JSON result:
```go
func handleListSessions() func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        pctx := security.BuildPolicyContext("list_sessions", []string{}, "")
        allowed, reason, _ := security.EvaluatePolicy(pctx)
        if !allowed {
            security.LogPolicyDecision(pctx.User, "list_sessions", false, reason)
            return mcp.NewToolResultError("access denied"), nil
        }
        ids := sys.ListSessions()
        // marshal ids to JSON for result text
        data, _ := json.Marshal(ids)
        return mcp.NewToolResultText(string(data)), nil
    }
}
```

---

### `cmd/adssh-mcp/tools_audit.go` (handler, request-response)

**Analog:** `security/audit.go` — `InitAuditLog` shows the log file path convention

**Audit log read pattern** — tail the file at `cfg.AuditLogPath`:
```go
// Modeled on security/audit.go lines 21-35 (file open pattern):
func handleAuditLog(auditLogPath string) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        pctx := security.BuildPolicyContext("audit_log", []string{}, "")
        allowed, reason, _ := security.EvaluatePolicy(pctx)
        if !allowed {
            security.LogPolicyDecision(pctx.User, "audit_log", false, reason)
            return mcp.NewToolResultError("access denied"), nil
        }

        limit := 50
        if v, ok := req.Params.Arguments["limit"]; ok {
            limit = int(v.(float64))
        }
        filter, _ := req.Params.Arguments["filter"].(string)

        data, err := os.ReadFile(auditLogPath)
        if err != nil {
            return mcp.NewToolResultError(fmt.Sprintf("cannot read audit log: %v", err)), nil
        }
        // tail last `limit` lines, filter by `filter` string
        lines := strings.Split(string(data), "\n")
        // ... filter + limit logic ...
        return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
    }
}
```

---

### `cmd/adssh-mcp/tools_cloud.go` (handler, request-response)

**Analog:** `starlarkext/starlarkext.go` lines 22-103 (namespace dict access pattern)

**Cloud namespace query pattern** — access `cloud`, `aws`, `gcp`, `oci` dicts from shared globals:
```go
// Modeled on starlarkext/starlarkext.go lines 99-104
// globals["cloud"] is a *starlark.Dict set up by SetupExtensions
func handleCloudQuery(globals starlark.StringDict) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        namespace := req.Params.Arguments["namespace"].(string) // e.g. "aws", "gcp"
        fn := req.Params.Arguments["function"].(string)

        nsVal, ok := globals[namespace]
        if !ok {
            return mcp.NewToolResultError(fmt.Sprintf("unknown namespace: %s", namespace)), nil
        }
        nsDict, ok := nsVal.(*starlark.Dict)
        if !ok {
            return mcp.NewToolResultError("namespace is not a dict"), nil
        }
        callable, found, _ := nsDict.Get(starlark.String(fn))
        if !found {
            return mcp.NewToolResultError(fmt.Sprintf("unknown function: %s.%s", namespace, fn)), nil
        }

        thread := &starlark.Thread{Name: "mcp-cloud"}
        result, err := starlark.Call(thread, callable.(starlark.Callable), nil, nil)
        if err != nil {
            return mcp.NewToolResultError(err.Error()), nil
        }
        return mcp.NewToolResultText(result.String()), nil
    }
}
```

---

## Shared Patterns

### Policy Check Sequence
**Source:** `security/interceptor.go` lines 23-35 AND `security/policy.go` lines 57-104
**Apply to:** Every MCP tool handler, before any execution

```go
// Standard policy gate — copy verbatim into each tool handler
pctx := security.BuildPolicyContext(toolName, args, sessionID)
allowed, reason, policyErr := security.EvaluatePolicy(pctx)
if policyErr != nil {
    return nil, fmt.Errorf("policy evaluation error: %v", policyErr)
}
if !allowed {
    security.LogPolicyDecision(pctx.User, toolName, false, reason)
    if reason != "" {
        return mcp.NewToolResultError(fmt.Sprintf("access denied: %s", reason)), nil
    }
    return mcp.NewToolResultError(fmt.Sprintf("access denied for '%s' by policy", toolName)), nil
}
security.LogPolicyDecision(pctx.User, toolName, true, "")
security.LogCommand("MCP:"+toolName, strings.Join(args, " "))
```

### Audit Logging
**Source:** `security/audit.go` lines 61-91
**Apply to:** All tool handlers after successful execution

```go
// After execution succeeds:
security.LogCommand("MCP:"+toolName, inputSummary)
// After policy decisions:
security.LogPolicyDecision(pctx.User, toolName, allowed, reason)
```

### Starlark Thread Per Call
**Source:** `security/interceptor.go` line 45; `starlarkext/exec.go` lines 30-41
**Apply to:** `tools_eval.go`, `tools_cloud.go` (any tool that calls into Starlark)

```go
// NEVER reuse a thread across requests — create per invocation:
thread := &starlark.Thread{Name: "mcp-<toolname>"}
```

### Shell Runner Construction
**Source:** `starlarkext/exec.go` lines 29-37
**Apply to:** `tools_shell.go`

```go
runner, _ := interp.New(
    interp.StdIO(nil, &stdout, &stderr),
    interp.ExecHandlers(security.BashInterceptor(false, globals)),
    interp.OpenHandler(security.VirtualOpenHandler()),
)
```

### Startup Init Sequence
**Source:** `main.go` lines 27-88
**Apply to:** `cmd/adssh-mcp/main.go`

Order must be preserved:
1. `config.LoadFromEnv()` + CLI flag overrides
2. `security.InitAuditLog(...)`
3. `security.LoadPolicy(...)`
4. `starlarkext.SetupExtensions(globals, false)` — once, shared across all calls
5. Start MCP server

### Package Import Aliases
**Source:** `main.go` lines 3-17; `security/policy.go` lines 3-13
**Apply to:** All new files under `cmd/adssh-mcp/`

```go
// Module path prefix is "adssh" (from go.mod line 1)
import (
    "adssh/config"
    "adssh/security"
    "adssh/starlarkext"
    "adssh/sys"
)
```

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `cmd/adssh-mcp/auth.go` (if separated) | middleware | request-response | No HTTP middleware exists yet — use pattern from `withAPIKeyAuth` stub in server.go section above |

**Note on `mark3labs/mcp-go`:** This library is not yet in `go.mod`. The planner must add `go get github.com/mark3labs/mcp-go` as the first step of any plan that creates MCP server files. All `mcp.CallToolRequest`, `mcp.NewToolResultText`, `mcp.NewToolResultError` references depend on it.

## Metadata

**Analog search scope:** `main.go`, `config/`, `security/`, `starlarkext/`, `sys/`
**Files scanned:** 8
**Pattern extraction date:** 2026-05-06
