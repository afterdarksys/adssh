# adssh Virtual Binary (VBIN) Specification

**Version:** 1.0  
**Status:** Normative

---

## Overview

A **virtual binary** (VBIN) is a command that appears in the adssh shell exactly like a real executable but is implemented in Go and runs in-process. VBINs have full access to the shell's I/O streams, security context, and session state without spawning a child process or requiring anything to be installed on the host system.

VBINs are the canonical extension point for tools that adssh ships as built-ins — `jq`, `yq`, `http`, security scanners, system management tools, and the discovery command `vbins` itself.

---

## Design Principles

1. **Zero external dependencies.** A VBIN works on any machine adssh is installed on. It must not exec a subprocess that may be absent.
2. **Transparent to the shell.** A VBIN is invoked identically to any shell command: `jq '.' < file.json`. Pipelines, redirections, and argument quoting all work unchanged.
3. **Audit-first.** Every VBIN invocation passes through `BashInterceptor` before dispatch. Policy evaluation, access control, and command logging happen automatically — VBIN authors do not implement these.
4. **Self-describing.** Every VBIN exposes its name, one-line description, and usage string. `vbins --help` and tab completion are driven by this metadata.
5. **Register-by-init.** VBINs self-register in a Go `init()` function. No central registry file requires editing to add a new VBIN.

---

## Interface

Every VBIN implements the `VirtualBinary` interface defined in `security/virtualbin_registry.go`:

```go
type VirtualBinary interface {
    Name()        string
    Description() string
    Usage()       string
    Run(ctx context.Context, args []string) error
}
```

### Method contracts

| Method | Contract |
|--------|----------|
| `Name()` | Returns the command name as it appears on the shell prompt. Must be a single token with no whitespace. Must be unique across all registered VBINs. |
| `Description()` | One-line human-readable description used by `vbins` and tab completion. No trailing period. 80 characters or fewer. |
| `Usage()` | Minimal usage synopsis, e.g. `jq <filter>`. Shown by `--help`. |
| `Run(ctx, args)` | Executes the command. `args[0]` is the command name (matching `Name()`). Returns a non-nil error to signal failure; the shell prints the error and sets `$?` to a non-zero exit code. |

---

## Registration

A VBIN registers itself by calling `security.Register` inside a package-level `init()` function. This guarantees the VBIN is available as soon as the package is imported.

```go
func init() {
    security.Register(myBinary{})
}
```

The registry stores VBINs in a `map[string]VirtualBinary` keyed by `Name()`. Duplicate names panic at init time.

---

## Dispatch Flow

When a shell command is executed, `BashInterceptor` processes it in this order:

```
Shell command
    │
    ▼
[0] Rego/OPA policy evaluation
    │  denied → "access denied" error, logged
    │  allowed ↓
[1] Custom Starlark commands (register_command)
    │  match → call Starlark callable
    │  no match ↓
[2] VBIN registry lookup (Lookup(args[0]))
    │  match → DispatchVBin(ctx, vb, args)
    │  no match ↓
[3] Restricted-mode checks
    │
    ▼
[4] Real shell (mvdan.cc/sh)
```

VBINs occupy layer 2. They run after policy has approved the command, and before the real shell tries to exec anything. A VBIN for a name that also exists as a real binary always wins.

### DispatchVBin

`DispatchVBin` handles the `--help` / `help` argument automatically:

```go
func DispatchVBin(ctx context.Context, vb VirtualBinary, args []string) error {
    if len(args) > 1 && (args[1] == "--help" || args[1] == "help") {
        fmt.Fprintf(hc.Stdout, "%s — %s\nUsage: %s\n", vb.Name(), vb.Description(), vb.Usage())
        return nil
    }
    return vb.Run(ctx, args)
}
```

VBIN authors do not need to implement `--help` handling.

---

## I/O

Inside `Run`, I/O is accessed through `interp.HandlerCtx`:

```go
func (b myBinary) Run(ctx context.Context, args []string) error {
    hc := interp.HandlerCtx(ctx)

    // Read from stdin (e.g. for pipe input)
    data, err := io.ReadAll(hc.Stdin)

    // Write to stdout
    fmt.Fprintf(hc.Stdout, "result: %s\n", result)

    // Write to stderr
    fmt.Fprintf(hc.Stderr, "warning: %v\n", warn)

    return nil
}
```

`hc.Stdin`, `hc.Stdout`, and `hc.Stderr` are wired by `mvdan.cc/sh` and reflect whatever redirections the user specified (`< file`, `| next-cmd`, `2>/dev/null`, etc.). Never read `os.Stdin` or write to `os.Stdout`/`os.Stderr` directly.

---

## Session Context

When adssh has an active SSH session, the session ID is threaded into the context by `BashInterceptor`:

```go
sessionID := security.SessionIDFromContext(ctx)
```

VBINs that need to record per-session state (e.g. `mirror`, `containers.audit`) retrieve the session ID this way.

---

## Security Model

### Policy (Rego/OPA)

Every VBIN invocation is policy-evaluated before dispatch. The VBIN author does not call `EvaluatePolicy` — it happens automatically in `BashInterceptor`. If an OPA policy denies the command, `Run` is never called.

### RBAC / Entitlements

`security.IsAuthorized(user, principals, command)` checks whether a user (or their SSH certificate principals) is permitted to run a command. This is used by `BashInterceptor` in SSH sessions. VBINs that perform privileged sub-operations may call `IsAuthorized` themselves for fine-grained control.

### Restricted mode

When adssh is launched with `-r` / `--restricted`, the interceptor blocks commands that contain `/` in the name and forbids `cd` / `export`. This check happens at layer 3, after VBIN dispatch, so restricted mode does not block VBINs by default. VBINs that should be unavailable in restricted sessions should inspect `restricted` from their enclosing scope or check an explicit policy rule.

### Audit logging

Command execution is logged by `BashInterceptor` before dispatch via `LogCommand("BASH", cmd)`. VBINs do not need to log their own invocation. VBINs that perform significant sub-actions (e.g. submitting a file for scanning, modifying system state) should log those actions explicitly:

```go
security.LogEvent(fmt.Sprintf("darkscan: submitted %s", args[1]))
```

---

## Built-in VBINs

| Name | File | Description |
|------|------|-------------|
| `jq` | `security/virtualbin.go` | JSON processor using `gojq` — reads stdin, applies a jq filter, writes JSON to stdout |
| `yq` | `security/virtualbin.go` | YAML processor — same as `jq` but reads YAML input and writes YAML output |
| `http` | `security/virtualbin.go` | Simple HTTP GET client — fetches a URL and writes the response body to stdout |
| `darkscan` | `security/virtualbin.go` | Malware scanner stub — submits a file path to the DarkAPI scanner |
| `memforensics` | `security/virtualbin.go` | Memory forensics stub — scans a PID for secrets and injections |
| `vbins` | `security/vbin_vbins.go` | Discovery — lists all registered VBINs with their descriptions |
| `proc` | `sysmgmt/proc.go` | Linux `/proc` filesystem accessor — `proc get|set <path> [value]` |
| `package` | `sysmgmt/package.go` | Cross-distro package manager wrapper — `package install|remove|update|list <pkg>` |

---

## Adding a New VBIN

1. **Choose a file.** Place the implementation in `security/` for security-oriented tools or create a new package (e.g. `sysmgmt/`) for domain-specific tools.

2. **Implement the interface.**

```go
package security

import (
    "context"
    "fmt"

    "mvdan.cc/sh/v3/interp"
)

type myToolBinary struct{}

func (myToolBinary) Name()        string { return "mytool" }
func (myToolBinary) Description() string { return "Does something useful" }
func (myToolBinary) Usage()       string { return "mytool <arg>" }

func (myToolBinary) Run(ctx context.Context, args []string) error {
    hc := interp.HandlerCtx(ctx)
    if len(args) < 2 {
        return fmt.Errorf("mytool: missing argument")
    }
    fmt.Fprintf(hc.Stdout, "result: %s\n", args[1])
    return nil
}

func init() { Register(myToolBinary{}) }
```

3. **Import the package in `main.go`** (if it is a new package) using a blank import so `init()` runs:

```go
import _ "adssh/sysmgmt"
```

4. **Update tab completion** in `repl/completer.go`. Add the binary name to the `virtualBinaries` slice so it appears in first-word completions.

5. **Build and verify.**

```bash
go build ./...
echo '{}' | adssh -c 'mytool arg'
mytool --help
vbins
```

---

## Tab Completion

The completer (`repl/completer.go`) includes a static slice of known VBIN names for first-word tab completion. When adding a VBIN, update this slice to include the new name:

```go
var virtualBinaries = []string{"jq", "yq", "http", "mirror", "cmdgen", "mytool"}
```

Dynamic completion based on `ListVBins()` is a planned improvement.

---

## Naming Conventions

- Use lowercase names that match common Unix tool conventions where applicable (`jq`, `yq`, `http`).
- For adssh-specific tools, use descriptive names that are unlikely to shadow real system binaries (`darkscan`, `memforensics`, `vbins`).
- Avoid names that shadow critical POSIX builtins (`cd`, `export`, `exec`, `exit`, `read`, `set`, `test`, `[`, `[[`).

---

## Error Handling

Return a descriptive error prefixed with the binary name:

```go
return fmt.Errorf("mytool: expected <arg>, got nothing")
```

The shell prints this to stderr and sets a non-zero exit status. Do not call `os.Exit` from a VBIN — it terminates the entire shell process.

---

## Future Extensions

| Feature | Notes |
|---------|-------|
| Dynamic tab completion | Drive `virtualBinaries` from `ListVBins()` at completer init time |
| Per-VBIN entitlement blocks | Allow entitlements YAML to list VBINs by name, not just arbitrary commands |
| Starlark-defined VBINs | `sys.register_command` already covers this use case for simple cases |
| VBIN argument completion | Extend the `VirtualBinary` interface with an optional `Complete(args []string) []string` method |
