# Embedding adssh

adssh is a security-first, programmable DevOps shell that ships as a Go library
as well as a binary. A commercial host imports the public `engine` package
directly to run policy-gated shell/Starlark sessions inside its own process, with
per-tenant isolation and a tamper-evident audit trail.

This guide covers the stable embedding surface:

1. [Create an engine](#1-create-an-engine)
2. [Open a session and run commands over custom I/O](#2-open-a-session-over-custom-io)
3. [Evaluate policy-gated commands and classify denials](#3-policy-gated-commands-and-error-classification)
4. [Read and verify the audit chain](#4-read-and-verify-the-audit-chain)
5. [Run many isolated sessions concurrently](#5-concurrent-isolated-sessions)
6. [Mount the SSH server and MCP handlers](#6-mounting-ssh-and-mcp)

The import path is `github.com/afterdarksys/adssh/engine`. The `engine` package
is the intended boundary; `security/`, `sys/`, `starlarkext/` and `repl/` are
lower-level and may change between minor versions.

---

## 1. Create an engine

An `*engine.Engine` owns one isolated security context: its own Rego policy
evaluator, audit log, HMAC hash chain, four-eyes / change-management state, RBAC
entitlements and virtual-binary registry. Two engines in one process share
nothing mutable, so each can serve a different tenant.

Construction is **fail-closed**: a malformed policy, a `RequirePolicy` with no
policy configured, or an unreadable entitlements file returns an error and no
engine.

```go
package main

import (
	"log"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/security"
)

func main() {
	eng, err := engine.New(engine.Config{
		EngineConfig: security.EngineConfig{
			// Inline Rego takes precedence over PolicyPath; use it to build an
			// engine without touching the filesystem.
			PolicySource: []byte(`
package adssh.authz
default allow = false
default deny_reason = "not permitted by tenant policy"
allow { input.command == "echo" }
`),
			RequirePolicy: true, // fail closed if no policy compiles

			// Tamper-evident audit trail (optional, but recommended).
			AuditLogPath: "/var/lib/tenant-42/audit.log",
			ChainPath:    "/var/lib/tenant-42/audit.log.chain",
			ChainKeyPath: "/var/lib/tenant-42/audit.key",
			SessionID:    "tenant-42",

			// RBAC entitlements + restricted mode (optional).
			EntitlementsPath: "/etc/tenant-42/entitlements.yaml",
			Restricted:       false,
		},
	})
	if err != nil {
		log.Fatalf("engine: %v", err) // fail closed: bad policy => no engine
	}
	_ = eng
}
```

A zero-value `engine.Config` yields an allow-by-default engine with no audit log
or chain — useful for tests, never for production.

---

## 2. Open a session over custom I/O

A `*engine.Session` is the per-session unit of isolation: its own Starlark thread
and globals, its own shell interpreter (`interp.Runner`) with an explicit working
directory, its own `pushd`/`popd` stack, and **injectable I/O** — the session
never touches `os.Stdin`/`os.Stdout`/`os.Stderr` directly. Open it with
`eng.NewSession`, which binds the session's authorization to *this* engine.

```go
import (
	"bytes"
	"context"
	"strings"

	"mvdan.cc/sh/v3/syntax"
	"go.starlark.net/starlark"
)

func runFor(eng *engine.Engine, user, script string) (string, error) {
	var out, errOut bytes.Buffer
	sess, err := eng.NewSession(engine.SessionOptions{
		SessionID: "req-1001",
		User:      user,
		In:        strings.NewReader(""),
		Out:       &out,
		Err:       &errOut,
		Dir:       "/srv/work", // empty => process cwd
	})
	if err != nil {
		return "", err
	}

	// Shell: parse then run on the session's engine-authorized runner.
	f, err := syntax.NewParser().Parse(strings.NewReader(script), "")
	if err != nil {
		return "", err
	}
	if err := sess.Runner.Run(context.Background(), f); err != nil {
		return out.String(), err // may be a policy denial — see §3
	}

	// Starlark: evaluate against the session's own thread + globals.
	if v, err := starlark.Eval(sess.Thread, "<embed>", `1 + 2`, sess.Globals); err == nil {
		_ = v // starlark.Int(3)
	}

	return out.String(), nil
}
```

`SessionOptions` fields: `SessionID`, `User`, `Restricted`, `In`/`Out`/`Err`,
`HistoryFile`, `Dir`, and `ExecMiddleware` (extra exec middlewares appended after
the security interceptor — tests use it to install a sentinel in place of real OS
exec). If `Engine` is left nil here it defaults to the process-global engine;
`eng.NewSession` fills it with `eng` for you.

---

## 3. Policy-gated commands and error classification

Every shell command a session runs passes through the interceptor chain: Rego
policy → change-management ticket → four-eyes approval → custom commands →
builtins → virtual binaries → restricted checks → real exec. Policy failures
**fail closed** (an evaluation error denies).

The host needs to tell an authorization **deny** apart from an execution
**failure**. The facade exposes helpers for that:

```go
out, err := runFor(eng, "alice", "rm -rf /")
switch {
case err == nil:
	// executed
case engine.IsAccessDenied(err):
	// blocked by Rego policy — surface as 403, not 500
case engine.IsApprovalRequired(err):
	// blocked by four-eyes or a change-management ticket — prompt for approval
default:
	// genuine execution failure
}
_ = out
```

To evaluate policy **outside** a session (e.g. a pre-flight check in an API
handler) use the engine's security handle directly:

```go
sec := eng.Security()
pctx := security.BuildPolicyContext("deploy", []string{"--prod"}, "req-1001")
allowed, reason, err := sec.EvaluatePolicy(pctx)
if err != nil {
	// fail closed: treat evaluation errors as denials
}
if !allowed {
	log.Printf("denied: %s", reason)
}
```

`engine.ErrAccessDenied` and `engine.ErrApprovalRequired` are sentinels usable
with `errors.Is`; the `IsAccessDenied` / `IsApprovalRequired` helpers also match
the interceptor's current error strings, so they work today without any change to
interceptor behavior.

---

## 4. Read and verify the audit chain

When `ChainPath` is configured, the engine appends an HMAC-linked entry per
command / policy decision / event. Verify the ledger end-to-end (any tampered
entry or broken link fails verification):

```go
sec := eng.Security()

ok, badSeq, err := sec.VerifyChain("/var/lib/tenant-42/audit.log.chain")
if err != nil {
	log.Fatalf("verify: %v", err)
}
if !ok {
	log.Fatalf("audit chain broken at seq %d", badSeq)
}

// Export a filtered slice of the ledger (format: "jsonl" or "csv").
data, err := sec.ExportChain(
	"/var/lib/tenant-42/audit.log.chain",
	"jsonl",
	"2026-01-01T00:00:00Z", // since (RFC3339, empty = beginning)
	"",                     // until (empty = now)
)
if err != nil {
	log.Fatal(err)
}
_ = data
```

To append your own event or command record through the engine, use
`sec.LogEvent(...)`, `sec.LogCommand(source, cmd)` or `sec.AppendChain(security.ChainEntry{...})`.

---

## 5. Concurrent isolated sessions

Sessions are single-threaded internally, but many run in parallel per engine.
Shared engine state (audit chain writes, four-eyes approvals) is mutex-guarded,
so N goroutines each driving their own session are race-free:

```go
var wg sync.WaitGroup
for i := 0; i < 50; i++ {
	wg.Add(1)
	go func(n int) {
		defer wg.Done()
		sess, err := eng.NewSession(engine.SessionOptions{
			SessionID: fmt.Sprintf("sess-%d", n),
			User:      "worker",
			Out:       io.Discard,
			Err:       io.Discard,
		})
		if err != nil {
			return
		}
		f, _ := syntax.NewParser().Parse(strings.NewReader("echo hi"), "")
		_ = sess.Runner.Run(context.Background(), f)
	}(i)
}
wg.Wait()

// The chain still verifies after concurrent appends.
ok, _, _ := eng.Security().VerifyChain("/var/lib/tenant-42/audit.log.chain")
_ = ok
```

For strict per-tenant isolation, build one `engine.New` per tenant rather than
sharing one engine across tenants.

---

## 6. Mounting SSH and MCP

The binary mounts the same building blocks a host can mount.

### SSH server

`sys.EnableSSH` starts the built-in pubkey-only SSH server. The starter callback
runs once per accepted connection; build a fresh session (or REPL) per connection
inside it.

```go
import "github.com/afterdarksys/adssh/sys"

// The SSH server and the Starlark exec builtins still resolve the process-global
// default engine. Point the default at your engine once at startup so those
// paths authorize through the same policy/audit/chain as your sessions.
security.SetDefaultEngine(eng.Security())

starter := func(sessionID, user string, principals []string,
	in io.ReadCloser, out, errOut io.Writer) {

	menu := eng.Security().GetMenuForUser(user, principals)
	if menu != "" {
		repl.StartMenu(menu, /* globals */ nil, false, in, out, errOut)
		return
	}
	repl.Start(/* globals */ nil, false, "", in, out, errOut)
}

if err := sys.EnableSSH(":2222", "/etc/adssh/host_key", "/etc/adssh/authorized_keys", starter); err != nil {
	log.Fatal(err)
}
```

> Note: `repl.Start`/`repl.StartMenu` and the Starlark exec builtins currently
> resolve the process default engine rather than taking an `*engine.Engine`
> directly (tracked as `TODO(engine-facade)`). `security.SetDefaultEngine` keeps
> them consistent with your engine for single-tenant hosts. Multi-tenant hosts
> that need per-connection engines should not share the process default; wire the
> connection's own `engine.Session` instead.

### MCP server

`cmd/adssh-mcp` is the reference host for the Model Context Protocol. It builds an
`engine.Engine` from env config, points the default engine at it, and gates every
tool through `eng.Security().EvaluatePolicy` before dispatch — the same Rego a
human at the terminal is subject to. Use it as a template for exposing adssh to AI
agents; the policy gate is a thin wrapper you can reproduce over your own
transport:

```go
sec := eng.Security()
pctx := security.BuildPolicyContext(toolName, nil, "")
allowed, reason, err := sec.EvaluatePolicy(pctx)
if err != nil || !allowed {
	sec.LogPolicyDecision(pctx.User, toolName, false, reason)
	return deny(reason)
}
sec.LogPolicyDecision(pctx.User, toolName, true, "")
return dispatch()
```

---

## API stability

The `engine` package is the versioned boundary. Until `v1.0.0` its exported
surface changes only by deliberate decision. Lower-level packages (`security/`,
`sys/`, `starlarkext/`, `repl/`) are consumed by `engine` and the binaries and may
change; prefer the `engine`/`Session` methods, and reach through `eng.Security()`
only for the security-core operations (`EvaluatePolicy`, `VerifyChain`,
`ExportChain`, `LogEvent`) that the facade does not yet re-expose.
