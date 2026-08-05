# adssh Virtual Binary (VBIN) Specification

**Version:** 1.1  
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
6. **Replacement-shell quality.** VBINs that shadow common Unix tools must preserve familiar stdin/stdout behavior, exit semantics, and composability unless their help text explicitly documents the difference.

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
| `Name()` | Returns the command name as it appears on the shell prompt. Must be a single token with no whitespace or `/`. Must be unique across all registered VBINs. |
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

The registry stores VBINs in a `map[string]VirtualBinary` keyed by `Name()`. `Register` panics at init time when a VBIN has an empty name, a name containing whitespace or `/`, or a name that duplicates an existing VBIN.

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

### Shadowing real commands

Shadowing is intentional for tools that adssh wants to provide everywhere, such as `jq`, `yq`, and `http`. Shadowing is also a compatibility risk. A VBIN that shadows a common host command must meet one of these criteria:

- It is a close behavioral subset of the common command and documents unsupported flags in `Usage()` or command-specific help.
- It is adssh-specific and has a name that is unlikely to collide with POSIX or common admin tooling.
- It is explicitly security-gated by policy or entitlements because it changes system state.

Do not shadow shell control flow, POSIX special builtins, or commands whose semantics scripts commonly depend on: `cd`, `export`, `exec`, `exit`, `read`, `set`, `test`, `[`, `[[`, `trap`, `return`, `shift`, `eval`.

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

### Pipeline contract

A VBIN must be composable in shell pipelines:

- Read data from `hc.Stdin` when input is not supplied by explicit arguments.
- Write machine-readable primary output to `hc.Stdout`.
- Write warnings, prompts, diagnostics, progress, and human-only messages to `hc.Stderr`.
- Do not emit banners or progress output to `stdout` when the command is likely to be piped.
- Return after `ctx.Done()` is closed for long-running operations.
- Do not close `hc.Stdin`, `hc.Stdout`, or `hc.Stderr`; the shell owns them.

Commands that may produce structured output should prefer stable JSON by default or provide a documented flag for JSON output.

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

## Portability Tiers

Every VBIN should be clear about where it works.

| Tier | Meaning | Requirements |
|------|---------|--------------|
| Portable | Works on supported adssh platforms without host-specific files or tools | No subprocess dependency; no Linux-only filesystem assumptions |
| Host-adapter | Wraps or inspects host capabilities | Detect missing capability and return a clear error |
| Platform-specific | Intentionally tied to an OS or subsystem | Document the platform in `Description()` or `Usage()` and fail cleanly elsewhere |
| Privileged | Requires elevated rights or mutates protected state | Must be policy/entitlement friendly and audit meaningful sub-actions |

The default expectation is Portable. Use a lower tier only when the command's purpose requires it.

---

## Built-in VBINs

| Name | File | Description |
|------|------|-------------|
| `jq` | `security/virtualbin.go` | JSON processor using `gojq` — reads stdin, applies a jq filter, writes JSON to stdout |
| `yq` | `security/virtualbin.go` | YAML processor — same as `jq` but reads YAML input and writes YAML output |
| `http` | `security/virtualbin.go` | Simple HTTP GET client — fetches a URL and writes the response body to stdout |
| `darkscan` | `security/virtualbin.go` | Simulated malware-scanner demo — does not upload or scan files and returns no verdict |
| `memforensics` | `security/virtualbin.go` | Simulated memory-forensics demo — does not attach to or inspect processes |
| `vbins` | `security/vbin_vbins.go` | Discovery — lists all registered VBINs with their descriptions |
| `help` | `security/vbin_help.go` | Shell help system |
| `history` | `security/vbin_history.go` | Interactive command history |
| `fc` | `security/vbin_history.go` | History listing/editing command |
| `audit` | `security/vbin_audit.go` | Audit-chain inspection and export |
| `mirror` | `security/mirror.go` | Session metadata, mirroring, console access, and audited termination |
| `admin` | `security/vbin_admin.go` | Governed local admin API for sessions, gateways, approvals, explanations, and evidence |
| `identity` | `security/vbin_identity.go` | OIDC claim import and short-lived SSH certificate issuance |
| `cmdgen` | `security/cmdgen.go` | Cloud and container command generator |
| `grant` | `security/grants.go` | Temporary role escalation |
| `elevate` | `security/vbin_elevate.go` | Time-boxed break-glass elevation with reason and audit trail |
| `gateway` | `security/vbin_gateway.go` | Policy-audited local TCP gateway for SSH and internal services |
| `4eyes` | `security/vbin_foureyes.go` | Four-eyes approval workflow |
| `cm` | `security/vbin_cm.go` | Change-management workflow |
| `pick` | `security/vbin_pick.go` | Charm-powered fuzzy selector for arguments, stdin lines, and JSON choices |
| `nav` | `security/vbin_nav.go` | Three-column file navigator with parent/current/preview panes |
| `from`, `where`, `select`, `to` | `security/vbin_structured.go` | JSONL structured pipeline with JSON/CSV adapters and Starlark predicates |
| `why` | `security/vbin_why.go` | Side-effect-free explanation of every governance stage |
| `??` | `security/vbin_denial.go` | Last-denial explanation for the current session |
| `runbook` | `security/vbin_runbook.go` | Typed Starlark procedures whose argv-only steps are independently governed |
| `par` | `security/vbin_par.go` | Bounded worker pool with deterministic output and per-child governance |
| `evidence` | `security/vbin_evidence.go` | Full-chain-verified, filtered audit evidence bundles |
| `lease` | `security/vbin_lease.go` | TTL-bounded command environment secrets with output redaction |
| `stty` | `security/vbin_stty.go` | Terminal mode controls |
| `proc` | `security/vbin_proc.go` | Linux `/proc` filesystem accessor — `proc get|set <path> [value]` |
| `package` | `security/vbin_package.go` | Cross-distro package manager wrapper — `package install|remove|update|list <pkg>` |

### Governed child execution

`runbook`, `par`, and `lease` use the shared runtime in `security/vbin_runtime.go`.
Each child argv is passed through the same Rego, entitlement, change-management,
four-eyes, restricted-mode, and audit gate used by an ordinary shell command.
The runtime does not construct `/bin/sh -c` strings. Output capture is bounded;
`par` renders buffers in input order even when work completes out of order.

### Structured pipeline contract

`from` normalizes JSON arrays/objects, JSONL, or header-based CSV into one JSON
value per line. `where` evaluates a Starlark expression with the current value
available as `row`; the expression must return a boolean. `select` projects
comma-separated dotted fields. `to` emits JSON, JSONL, CSV, or a terminal table.
Record size, input size, and record count are bounded. This preserves POSIX pipe
compatibility while providing a predictable structured-data layer.

### Runbook contract

Runbooks are permission-checked `.star` files containing `description`, `params`,
and a non-empty `steps` list. Parameters support `string`, `int`, `float`, and
`bool`. Every step uses a string argv list—shell program strings are deliberately
unsupported. Runbooks are loaded from `ADSSH_RUNBOOK_DIR`, or the XDG adssh
configuration directory's `runbooks/` child by default.

### Evidence and lease boundaries

`evidence` verifies the complete configured HMAC ledger before applying session,
change, or time filters. Returned entries retain their original chain hashes;
the bundle also contains its chain head and a SHA-256 digest. If a matching
session recording exists under `ADSSH_RECORD_DIR` (or `~/.adssh/recordings`),
the bundle includes a recording manifest with path, size, event count, and
SHA-256 digest. If a gateway connection log exists at `ADSSH_GATEWAY_LOG` (or
the default under the recording directory), the bundle includes its path, size,
event count, and SHA-256 digest. Output files are published atomically with mode
`0600`.

`lease` accepts `env:NAME`, a private regular `file:path`, or read-only
vault-backed sources: `vault:path?field=KEY`, `aws-sm:name?region=REGION`,
`azure-kv:vault/name?version=VERSION`, and
`gcp-sm:project/name?version=VERSION`. Provider authentication comes from the
provider's normal environment/configuration, not from command-line tokens. The
value is injected into one child environment with a maximum 24-hour TTL. For
`env:NAME`, the source variable is removed from the child environment so only
the requested destination name is present.

Before fetching the secret, `lease` authorizes the child command with structured
Rego input under `input.lease`: `id`, `source_type`, `source_name`,
`destination`, `ttl_seconds`, and `command`. This lets policy constrain which
sources may be leased, how long a lease may live, and which child command may
receive it without parsing the `lease` argv. The audit chain records
`LEASE_REQUEST`, `LEASE_GRANT`, and `LEASE_REVOKE` events with the lease ID and
non-secret metadata.

Captured stdout/stderr redact the exact leased secret and common
credential-shaped strings. Audit command/event/policy entries are redacted
before they are written to the flat audit log, remote audit sink, or HMAC chain.
`lease` is a command-scoping primitive, not a complete vault. The owned source
byte buffer is zeroed after the child exits, but Go and the operating system
necessarily create immutable environment copies that cannot be synchronously
erased by the parent process. This is an explicit runtime boundary rather than
an unfinished guarantee. A child can also deliberately exfiltrate a credential
through transformed output or external side effects, so policy must restrict
which commands may receive a lease.

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

4. **Build and verify.**

```bash
go build ./...
echo '{}' | adssh -c 'mytool arg'
mytool --help
vbins
```

---

## Tab Completion

The REPL completer reads first-word VBIN completions from `security.ListVBins()`. A registered VBIN appears in first-word completion automatically.

Argument completion is still command-specific. Add first-argument completions to `vbinSubcommands` in `repl/completer.go` when the command has a small stable subcommand set. Do not add file, URL, or free-form value domains there.

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

For replacement-shell reliability:

- Validate arguments before performing side effects.
- Prefer deterministic errors over partial output.
- For unsupported flags, return a clear message instead of silently ignoring them.
- For network operations, set bounded timeouts and honor context cancellation.
- For mutating commands, log meaningful sub-actions with `security.LogEvent`.

---

## Test Requirements

Every non-trivial VBIN should have focused tests. Minimum coverage:

- `--help` or `Usage()` output is coherent.
- Missing/invalid arguments return an error prefixed with the binary name.
- Stdin/stdout behavior works under `interp.HandlerCtx`.
- Structured output is parseable when the command promises structured output.
- Host-adapter and platform-specific commands handle missing capabilities cleanly.
- Mutating or privileged commands verify policy/entitlement/audit behavior where applicable.

Prefer tests around `Run(ctx, args)` with a handler context over end-to-end shell tests unless the command depends on parser or redirection behavior.

---

## Future Extensions

| Feature | Notes |
|---------|-------|
| Per-VBIN entitlement blocks | Allow entitlements YAML to list VBINs by name, not just arbitrary commands |
| Starlark-defined VBINs | `sys.register_command` already covers this use case for simple cases |
| VBIN argument completion | Extend the `VirtualBinary` interface with an optional `Complete(args []string) []string` method |
| Extended metadata | Add optional categories, portability tier, examples, and output format metadata |
