# Phase 1: Policy Engine - Pattern Map

**Mapped:** 2026-05-06
**Files analyzed:** 7 (5 modified, 2 new Go files, 2 new Rego files)
**Analogs found:** 5 / 7 (2 Rego files have no codebase analog)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `security/policy.go` (new) | service | request-response | `security/entitlements.go` | role-match |
| `policy/default.rego` (new) | config | — | none | no analog |
| `policy/examples/*.rego` (new) | config | — | none | no analog |
| `security/entitlements.go` (modify) | service | request-response | self (existing) | exact |
| `security/interceptor.go` (modify) | middleware | request-response | self (existing) | exact |
| `security/audit.go` (modify) | utility | event-driven | self (existing) | exact |
| `starlarkext/sec.go` (modify) | utility | request-response | self (existing) | exact |
| `config/env.go` (modify) | config | — | self (existing) | exact |

---

## Pattern Assignments

### `security/policy.go` (new — service, request-response)

**Analog:** `security/entitlements.go`

**Imports pattern** (`security/entitlements.go` lines 1–9):
```go
package security

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"os/user"
	"sync"
)
```
New file will swap yaml/user for OPA SDK and context:
```go
package security

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"sync"

	"github.com/open-policy-agent/opa/rego"
)
```

**Initialization pattern** (`security/entitlements.go` lines 16–42):
```go
var (
	entitlements   EntitlementsConfig
	entitlementsMu sync.RWMutex
)

func LoadEntitlements(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	entitlementsMu.Lock()
	defer entitlementsMu.Unlock()

	err = yaml.Unmarshal(data, &entitlements)
	if err != nil {
		return fmt.Errorf("failed to parse entitlements: %v", err)
	}
	return nil
}
```
`policy.go` mirrors this shape: a package-level `sync.RWMutex`-protected variable, a `LoadPolicy(path string) error` that reads the file, falls back gracefully on `os.IsNotExist`, and builds/stores the `rego.PreparedEvalQuery`.

**Authorization pattern** (`security/entitlements.go` lines 47–89):
```go
func IsAuthorized(command string) bool {
	entitlementsMu.RLock()
	defer entitlementsMu.RUnlock()

	// If no config loaded, allow all
	if len(entitlements.Groups) == 0 && len(entitlements.Users) == 0 {
		return true
	}
	// ... lookup logic ...
	return false
}
```
`policy.go` replaces this with `EvaluatePolicy(ctx PolicyContext) (allowed bool, denyReason string, err error)`. The allow-all default when no policy is loaded is preserved — mirroring lines 52–54.

**Concrete shape for `policy.go`:**
```go
// PolicyContext is the input document passed to OPA.
type PolicyContext struct {
	User      string   `json:"user"`
	Groups    []string `json:"groups"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Time      string   `json:"time"`
	SessionID string   `json:"session_id"`
}

var (
	preparedQuery *rego.PreparedEvalQuery
	policyMu      sync.RWMutex
)

func LoadPolicy(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // allow-all when no policy file
		}
		return fmt.Errorf("failed to read policy: %w", err)
	}
	policyMu.Lock()
	defer policyMu.Unlock()
	// build rego.PreparedEvalQuery from data, store in preparedQuery
	...
}

func EvaluatePolicy(pctx PolicyContext) (bool, string, error) {
	policyMu.RLock()
	defer policyMu.RUnlock()
	if preparedQuery == nil {
		return true, "", nil // no policy loaded — allow all
	}
	// eval against "data.adssh.authz.allow" / "data.adssh.authz.deny_reason"
	...
}
```

---

### `security/entitlements.go` (modify — service, request-response)

**Analog:** self

The file needs no structural change. The only modification is documenting that Rego evaluation takes precedence when a policy is loaded. `IsAuthorized` becomes the fallback path.

No new pattern required — existing file is the pattern.

---

### `security/interceptor.go` (modify — middleware, request-response)

**Analog:** self (`security/interceptor.go`)

**Current authorization call pattern** (lines 26–28 and 51–53):
```go
if !IsAuthorized(args[0]) {
    return fmt.Errorf("adssh: access denied for custom command '%s' by RBAC policy", args[0])
}
```

**Replace with two-stage evaluation:** call `EvaluatePolicy` first; fall back to `IsAuthorized` if no Rego policy is loaded. Preserve the existing `fmt.Errorf` error shape but include `denyReason` when available:
```go
allowed, reason, err := EvaluatePolicy(PolicyContext{...})
if err != nil {
    return fmt.Errorf("adssh: policy evaluation error: %v", err)
}
if !allowed {
    if reason != "" {
        return fmt.Errorf("adssh: access denied: %s", reason)
    }
    return fmt.Errorf("adssh: access denied for '%s' by policy", args[0])
}
```

**Context building pattern** — derive user/groups the same way `entitlements.go` does (lines 56–82):
```go
currentUser, err := user.Current()
// ...
groupIDs, err := currentUser.GroupIds()
for _, gid := range groupIDs {
    g, err := user.LookupGroupId(gid)
    // ...
}
```

**Imports to add** (mirror existing import block at lines 1–9, add):
```go
"os/user"
"time"
```

---

### `security/audit.go` (modify — utility, event-driven)

**Analog:** self (`security/audit.go`)

**Existing log pattern** (lines 28–38):
```go
func LogCommand(source string, cmd string) {
	if auditLogger != nil {
		auditLogger.Printf("[%s] %s\n", source, cmd)
	}
}

func LogEvent(event string) {
	if auditLogger != nil {
		auditLogger.Println(event)
	}
}
```

**Add a new function** following the same nil-guard + `auditLogger.Printf` pattern:
```go
// LogPolicyDecision records an OPA evaluation result in the audit log.
func LogPolicyDecision(user, command string, allowed bool, denyReason string) {
	if auditLogger != nil {
		auditLogger.Printf("[POLICY] user=%s command=%s allowed=%v reason=%q\n",
			user, command, allowed, denyReason)
	}
}
```

No structural change to the file — append the new function at the bottom.

---

### `starlarkext/sec.go` (modify — utility, request-response)

**Analog:** self (`starlarkext/sec.go`)

**Existing dict registration pattern** (lines 15–22):
```go
func SetupSecurityAPI(env starlark.StringDict, restricted bool) {
	isRestricted = restricted
	secDict := starlark.NewDict(3)
	secDict.SetKey(starlark.String("audit"), starlark.NewBuiltin("audit", builtinSecAudit))
	secDict.SetKey(starlark.String("is_restricted"), starlark.NewBuiltin("is_restricted", builtinSecIsRestricted))
	secDict.SetKey(starlark.String("file_hash"), starlark.NewBuiltin("file_hash", builtinSecFileHash))
	env["sec"] = secDict
}
```
Increment dict size to 4 and add:
```go
secDict.SetKey(starlark.String("check_policy"), starlark.NewBuiltin("check_policy", builtinSecCheckPolicy))
```

**Builtin function pattern** (lines 24–31 — `builtinSecAudit`):
```go
func builtinSecAudit(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var msg string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "msg", &msg); err != nil {
		return nil, err
	}
	security.LogEvent("STARLARK_AUDIT: " + msg)
	return starlark.None, nil
}
```

**New builtin shape for `sec.check_policy`:**
```go
func builtinSecCheckPolicy(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var command string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "command", &command); err != nil {
		return nil, err
	}
	// Build PolicyContext (user + groups from OS), evaluate
	allowed, reason, err := security.EvaluatePolicy(security.PolicyContext{Command: command, ...})
	if err != nil {
		return nil, fmt.Errorf("check_policy error: %v", err)
	}
	result := starlark.NewDict(2)
	result.SetKey(starlark.String("allowed"), starlark.Bool(allowed))
	result.SetKey(starlark.String("reason"), starlark.String(reason))
	return result, nil
}
```
Error wrapping mirrors the `fmt.Errorf("file_hash error: %v", err)` pattern from lines 44/49.

---

### `config/env.go` (modify — config)

**Analog:** self (`config/env.go`)

**Existing env field pattern** (lines 24–36, 41–56):
```go
type AppConfig struct {
	// ...
	EntitlementsPath   string
	// ...
}

func LoadFromEnv() AppConfig {
	// ...
	cfg := AppConfig{
		// ...
		EntitlementsPath: os.Getenv("ADSSH_ENTITLEMENTS"),
		// ...
	}
	return cfg
}
```

**Add `PolicyPath` field** using `envOr` with a default of `~/.adssh/policy.rego`, following the same pattern as `AuditLogPath`:
```go
// In AppConfig struct — add after EntitlementsPath:
PolicyPath string

// In the doc comment — add:
//	ADSSH_POLICY=/path         Path to Rego policy file     (default: ~/.adssh/policy.rego)

// In LoadFromEnv — add to cfg literal:
PolicyPath: envOr("ADSSH_POLICY", filepath.Join(adsshDir, "policy.rego")),
```

**`envOr` pattern** (lines 58–63) — reuse as-is, no change needed.

---

### `policy/default.rego` (new — config)

**No codebase analog.** Use OPA Rego conventions. Default allow-all policy following the `data.adssh.authz` package declared in CONTEXT.md:

```rego
package adssh.authz

default allow = true
default deny_reason = ""
```

---

### `policy/examples/*.rego` (new — config)

**No codebase analog.** Example policies that override the default. Two examples per CONTEXT.md specifics:

`policy/examples/restrict_sudo.rego`:
```rego
package adssh.authz

default allow = false
default deny_reason = "command not permitted"

allow {
    input.command != "sudo"
}

deny_reason = "sudo is not allowed by policy" {
    input.command == "sudo"
}
```

`policy/examples/ops_group_only.rego`:
```rego
package adssh.authz

default allow = false
default deny_reason = "only members of the ops group may run this command"

allow {
    "ops" in input.groups
}
```

---

## Shared Patterns

### Package-level mutex-guarded state initialization
**Source:** `security/entitlements.go` lines 16–42
**Apply to:** `security/policy.go`
```go
var (
	<state>   <Type>
	<state>Mu sync.RWMutex
)

func Load<Thing>(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	<state>Mu.Lock()
	defer <state>Mu.Unlock()
	// parse / build
	return nil
}
```

### Nil-guard audit logging
**Source:** `security/audit.go` lines 28–38
**Apply to:** `security/audit.go` (new `LogPolicyDecision` function)
```go
func LogX(...) {
	if auditLogger != nil {
		auditLogger.Printf(...)
	}
}
```

### Starlark builtin registration in a namespace dict
**Source:** `starlarkext/sec.go` lines 15–22; `starlarkext/starlarkext.go` lines 16–94
**Apply to:** `starlarkext/sec.go` (adding `check_policy` builtin)
```go
secDict.SetKey(starlark.String("<name>"), starlark.NewBuiltin("<name>", builtin<Name>))
```

### Starlark builtin UnpackArgs + fmt.Errorf wrapping
**Source:** `starlarkext/sec.go` lines 24–31, 37–53
**Apply to:** `starlarkext/sec.go` (`builtinSecCheckPolicy`)
```go
func builtinFoo(...) (starlark.Value, error) {
	var param string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "param", &param); err != nil {
		return nil, err
	}
	result, err := someCall(param)
	if err != nil {
		return nil, fmt.Errorf("foo error: %v", err)
	}
	return starlark.String(result), nil
}
```

### AppConfig env field + envOr default
**Source:** `config/env.go` lines 24–56
**Apply to:** `config/env.go` (adding `PolicyPath`)
```go
// struct field
SomePath string

// in LoadFromEnv cfg literal
SomePath: envOr("ADSSH_SOME", filepath.Join(adsshDir, "some.default")),
```

### Error message format in interceptor
**Source:** `security/interceptor.go` lines 27, 52
**Apply to:** `security/interceptor.go` (replacing `IsAuthorized` calls)
```go
return fmt.Errorf("adssh: access denied for <thing> '%s' by <reason>", args[0])
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `policy/default.rego` | config | — | No Rego files exist in the codebase |
| `policy/examples/*.rego` | config | — | No Rego files exist in the codebase |

---

## Metadata

**Analog search scope:** `security/`, `starlarkext/`, `config/`, `main.go`
**Files scanned:** 10
**Pattern extraction date:** 2026-05-06
