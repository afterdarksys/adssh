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
7. [Core and enterprise builds](#7-core-and-enterprise-builds)

The import path is `github.com/afterdarksys/adssh/engine`. The `engine` package
is the intended boundary. `security/` is also public and may be reached through
`eng.Security()` for operations the `engine` facade does not yet re-expose.
Everything else (`sys/`, `starlarkext/`, `repl/`, `sysmgmt/`, `devops/`, `i18n/`,
`config/`) lives under `internal/` as of the v0.9.0 API freeze and is not part of
the embedding surface at all — it cannot be imported from outside this module.

---

## 1. Create an engine

An `*engine.Engine` owns one isolated security context: its own Rego policy
evaluator, audit log, HMAC hash chain, change-management patterns (and, in the
enterprise build, tickets), RBAC entitlements and virtual-binary registry. Two engines in one process share
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
	defer sess.Close() // releases the session's identity binding

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

`SessionOptions` fields: `SessionID`, `User`, `Groups`, `Restricted`,
`In`/`Out`/`Err`, `HistoryFile`, `Dir`, and `ExecMiddleware` (extra exec
middlewares appended after the security interceptor — tests use it to install a
sentinel in place of real OS exec). If `Engine` is left nil here it defaults to
the process-global engine; `eng.NewSession` fills it with `eng` for you.

### Session identity

`NewSession` binds `SessionID` to `User` and `Groups` on the session's engine
(`security.Engine.BindSessionIdentity`). Policy sees that principal as
`input.user` and `input.groups` for every shell command, `GateProgram`
declaration, and Starlark `sys.exec_cmd` the session runs. The host must
authenticate `User` first; adssh does not.

- An empty `SessionID` is generated.
- An empty `User` binds the current OS user and its groups when the session is
  created. If that lookup fails, `NewSession` returns an error.
- Opening a second session with a live `SessionID` and a different principal on
  the same engine returns an error. The same ID on two engines does not share
  an identity.
- Call `sess.Close()` when the session ends. After `Close`, a gate call for that
  session ID is denied with `adssh: access denied: session identity unknown`.
- A non-empty session ID that is neither bound on the engine nor registered by
  the adssh binary's SSH or local session table is always denied. It never falls
  back to the process user. Pass an empty session ID to
  `Security().AuthorizeCommand` to authorize as the process user.

---

## 3. Policy-gated commands and error classification

Every shell command a session runs passes through the interceptor chain: Rego
policy → entitlements → approval gate (change-management ticket, then four-eyes
approval; see [§7](#7-core-and-enterprise-builds)) → custom commands →
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
	// blocked by four-eyes or a change-management ticket. In the core build
	// this is a refusal: nothing in the core build can approve it (§7).
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

Several engines and processes on one host can share one ledger if they use the
same key file. `adssh` and `adssh-mcp` do this by default. Each append takes an
exclusive `flock` on the ledger, reads the tail from disk, and writes and syncs
before it releases the lock, so the chain stays one sequence. If another process
holds the lock for more than 5 seconds, the append returns an error. It also
returns an error if the tail entry fails its HMAC check or is a partial line.
Do not share a ledger across hosts. `flock` on NFS and other network filesystems
is not reliable.

---

## 5. Concurrent isolated sessions

Sessions are single-threaded internally, but many run in parallel per engine.
Shared engine state (audit chain writes, and four-eyes approvals in the
enterprise build) is mutex-guarded,
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

The `adssh` binary mounts its own SSH server internally; the MCP server is the
one building block of this kind that a host can mount directly today.

### SSH server

The built-in pubkey-only SSH server (previously `sys.EnableSSH`) and the REPL
starters (`repl.Start`/`repl.StartMenu`) live under `internal/` as of the
v0.9.0 API freeze and are not part of the public embedding surface — a host
in another module cannot import them. Mounting an SSH-accessible shell is
currently only supported by running the `adssh` binary itself (with
`ADSSH_SERVE`/`-s`, see `internal/config/env.go` and `main.go`); there is no public
`engine`-level API for it yet. If your host needs to embed SSH mounting
directly, treat that as a feature request against the `engine` facade rather
than reaching into `internal/sys`.

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

## 7. Core and enterprise builds

v0.10.0 splits adssh into two builds from one module. This is a breaking
change for embedders.

- `go build` (no tag) is the core, Apache 2.0. It compiles no `*_ee.go` file
  and no package under `ee/`.
- `go build -tags ee` is the enterprise build, BSL 1.1. It adds the `*_ee.go`
  files next to the core files they extend, `ee/cmd/adsshadm` and
  `ee/policy/bundles`.

An embedder that imports `engine` or `security` gets the core unless its own
build passes `-tags ee`. Build tags apply to the whole build, so a host that
builds with `-tags ee` gets the enterprise layer and is bound by its license.

### What moved to the enterprise build

| Area | Files | Moved in |
|---|---|---|
| Admin API, attach, adsshadm | `admin_*_ee.go`, `vbin_admin_ee.go`, `ee/cmd/adsshadm` | wave 1 |
| Four-eyes approval | `foureyes_ee.go`, `foureyes_hook_ee.go`, `foureyes_pending_ee.go`, `vbin_foureyes_ee.go`, `approval_notice_ee.go` | wave 2 |
| Change management | `cm_ee.go`, `cm_hook_ee.go`, `vbin_cm_ee.go` | wave 2 |
| Evidence export | `vbin_evidence_ee.go`, `gateway_evidence_ee.go` | wave 2 (gateway evidence in wave 3, with the gateway) |
| Elevation and grants | `vbin_elevate_ee.go`, `grants_ee.go` | wave 2 |
| Secret leases | `vbin_lease_ee.go`, `vbin_lease_sources_ee.go` | wave 2 |
| Identity: OIDC import, device login, SSH CA | `vbin_identity_ee.go`, `device_login_ee.go`; MCP `identity_device_login` | wave 3 |
| Governed gateways and SSH `direct-tcpip` | `vbin_gateway_ee.go`, `gateway_policy_ee.go`, `main_gateway_ee.go` | wave 3 |
| Mirror sharing and supervising other users' sessions | `mirror_share_ee.go` | wave 3 |
| Grid, sah/1 | `internal/grid/*_ee.go`, `internal/sah/*_ee.go`, `main_sah_ee.go` | wave 3 |
| Policy bundles | `ee/policy/bundles/` | wave 3 |

These exported `security` identifiers exist only with `-tags ee`: the
four-eyes request and decision API (`CheckFourEyes*`, `RequestApproval*`,
`ApproveRequest*`, `DenyRequest*`, `DecideRequest`, `ListPending`,
`AddFourEyesRule`, `RemoveFourEyesRule`, `SaveFourEyesRules`,
`FourEyesPending`, `FourEyesStatus*`, `FourEyesSurface*`), change-management
tickets (`CMTicket`, `FetchCMTicket`, `IsTicketValid`, `CMSessionCheck*`,
`CMCurrentTicketID`, `Set`/`Get`/`ClearActiveCMTicket*`), evidence
(`EvidenceBundle`, `EvidenceFilter`, `BuildEvidence`), identity
(`DeviceLogin`, `DeviceLoginRequest`, `DeviceLoginResult`,
`ParseFlexibleDuration`), gateways (`GatewayPolicyRequest`,
`AuthorizeGateway`, `GatewayConnectionRecord`, `GatewayLogRef`,
`NewGatewayClaim`), and the admin API (`NewAdminHTTPHandler*`, `AdminKey`,
`LoadAdminKeysFile`, `AdminHTTPPaths`, the `List*` admin methods,
`ApprovalPublic`, `RecordingRef`, `RecordingListItem`, `ElevationListItem`).
`StartAdminAPI` exists in both builds and returns an error in the core.

These stay in core: `FourEyesRule`, `FourEyesDir`, `LoadFourEyesRules`,
`MatchesFourEyes`, `ForbidFourEyesDecisions`, `CMPatternsForSession`,
`AddCMPatternForSession`, `CMRequiredForSession`, `CMRequiredForCommand`,
`CMStrictMode`, `EngineConfig.FourEyesDir`, `LeaseEvidence`, and the policy
input claims (`ElevationClaim`, `LeaseClaim`, `GatewayClaim`, `SnoopClaim`).

### Hook points

| Hook | Who fills it | Without it (core) |
|---|---|---|
| `security.SetApprovalGate(security.ApprovalGate)` | The enterprise build, from `init()`. A core embedder may install its own gate. It can be set once per process. | The core gate: a command that matches a four-eyes rule, or that strict change management covers, is refused with a `foureyes:` or `cm:` error (`engine.IsApprovalRequired` is true). An unreadable rules file refuses every command. |
| `mirrorPeerAccess` (unexported, `mirror_attach.go`) | `mirror_share_ee.go` | `mirror view`/`console` attach only to the caller's own sessions. |
| `enterpriseToolRegistrars` (unexported, `cmd/adssh-mcp`) | `tools_admin_ee.go`, `tools_identity_ee.go` | MCP has `identity_status` and no `admin_*` or `identity_device_login` tool. |
| `directTCPIPAuthorizer` (unexported, `main`) | `main_gateway_ee.go` | The SSH listener gets no authorizer and refuses every `direct-tcpip` channel. |

`ApprovalGate` has three methods. `Check(ctx, engine, sessionID, args)` runs
after policy and entitlements allow a command and returns nil to let it run;
return an error that starts with `cm:` or `foureyes:` so the host can classify
it. `Explain(engine, sessionID, args)` returns the `change_management` and
`four_eyes` stages for `why` and `??`, with no side effects.
`NotifyPolicyDenial(command, requiredRole)` is called in its own goroutine when
policy denies `gateway`, `lease` or `elevate`.

### What a core-only embedder no longer has

- No way to approve a four-eyes request or to set a change ticket. Commands
  those rules cover are refused, not run. Install an `ApprovalGate` if your
  host has its own approval flow.
- No `evidence`, `elevate`, `grant`, `lease`, `identity`, `gateway`, `admin`,
  `4eyes`, `cm`, `grid`, `flight`, `agent`, `worktree` or `repo` virtual
  binary. The names stay registered and return an error that says they are
  enterprise; they never run a program of the same name on `PATH`.
- No attaching to another user's session, and no `mirror share`.
- No SSH `direct-tcpip` forwarding and no `adssh sah`.
- No starter policy bundles. `policy/default.rego` and `policy/examples/`
  remain.

---

## API stability

The `engine` package is the versioned boundary. Until `v1.0.0` its exported
surface changes only by deliberate decision. `security/` is also public and may
change independently; prefer the `engine`/`Session` methods, and reach through
`eng.Security()` only for the security-core operations (`EvaluatePolicy`,
`VerifyChain`, `ExportChain`, `LogEvent`) that the facade does not yet
re-expose. `sys/`, `starlarkext/`, `repl/`, `sysmgmt/`, `devops/`, `i18n/` and
`config/` are internal implementation packages under `internal/` as of the
v0.9.0 API freeze — they are consumed by `engine` and the binaries but are not
importable, and not part of, the embedding surface.
