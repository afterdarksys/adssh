# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

adssh is a security-first, programmable DevOps shell (Go). It is a dual-mode REPL that auto-detects
Starlark (a safe Python dialect) vs. POSIX shell input on every line, giving operators a single shell
where they can run ordinary commands (`ls -la | jq '.name'`) or call cloud/infra SDKs directly
(`aws.ec2.list_instances(region="us-east-1")`), define reusable Starlark functions, and let AI agents
drive the same shell over MCP. Every command — shell or Starlark — passes through the same OPA/Rego
policy, RBAC, and audit-log machinery before it executes.

adssh pairs with a sibling library repo, `adsyslib` (at `../adsyslib`), but this file documents adssh
only — do not assume adsyslib's internals apply here.

## Commands

```bash
make build        # go build -o adssh .                       (main shell binary)
make build-mcp    # go build -o adssh-mcp ./cmd/adssh-mcp      (MCP server binary)
make install      # go install . && go install ./cmd/adssh-mcp
make test         # go test ./...
make lint         # go vet ./...
make clean        # rm -f adssh adssh-mcp
```

Single test / package:
```bash
go test ./security/...              # e.g. security/policy_test.go
go test ./internal/starlarkext/...  # e.g. internal/starlarkext/libagent_test.go
go test ./security/... -run TestName -v
```

Go 1.21+ is required (go.mod currently targets a newer toolchain).

## Architecture

**Entry point (`main.go`)** wires everything together in a fixed sequence: load `AppConfig` from
`ADSSH_*` env vars (`config.LoadFromEnv`), parse CLI flags (flags override env), initialize the flat
audit log plus an HMAC hash-chain ledger (`security.InitAuditLog` / `security.InitChain`), load RBAC
entitlements and the Rego policy file, build a single Starlark `Thread` + `StringDict` of globals via
`starlarkext.SetupExtensions`, then load login/RC profiles (`config.LoadProfiles`) into that same
global dict. Depending on flags, it then either evaluates a one-off `-c` expression, runs a script
file, starts the SSH server, or drops into the interactive REPL — all four paths share the same
`globals` dict and the same security machinery.

**Dual-mode dispatch.** `parser.DetermineMode` is a line-level heuristic (not a full parser) that
decides whether a line of input should be evaluated as Starlark or handed to the shell interpreter
(`mvdan.cc/sh/v3`). `!`/`$ ` forces shell; `def`/`for`/`if`/`print(`/assignment-looking lines go to
Starlark; everything else defaults to shell. The REPL (`internal/repl/repl.go`) uses this to decide, per input
chunk, whether to call `starlark.Eval`/`ExecFile` against the shared globals or hand the line to the
`mvdan.cc/sh/v3` interpreter. `internal/repl/menu.go` provides a restricted, menu-driven REPL variant used for
SSH sessions mapped to a menu by `security.GetMenuForUser`.

**Every shell command is intercepted.** All shell execution — REPL, `-c`, scripts, SSH sessions —
goes through `mvdan.cc/sh/v3/interp` configured with `security.BashInterceptor` as its exec handler
and `security.VirtualOpenHandler` as its open handler. `BashInterceptor` is the real authorization
chokepoint and runs, in order: (1) Rego policy evaluation via `security.EvaluatePolicy`
(fail-closed on error), (2) change-management ticket check (`security.CMSessionCheck`), (3) four-eyes
dual-approval gate (`security.CheckFourEyes`), (4) custom commands registered from Starlark via
`sys.register_command`, (5) built-in shell verbs adssh implements itself (`set`, `alias`, `pushd`,
`popd`, `dirs`, `read`, `time`, `disown`, `type`, `command -v`, ...), (6) the virtual binary registry
(`security.Lookup`/`DispatchVBin`), (7) restricted-mode checks (blocks `/` in command names, `cd`,
`export`), and only then (8) falls through to the real OS exec. Every command is also logged via
`security.LogCommand`/`LogPolicyDecision` regardless of outcome.

**Virtual binaries** are adssh's built-in reimplementations of common tools (`jq`, `yq`, `http`,
`mirror`, `cmdgen`, `package`, `proc`, `grant`, `darkscan`, `memforensics`, ...) that run in-process
instead of shelling out. Each implements the `security.VirtualBinary` interface (`Name`,
`Description`, `Usage`, `Run`) and self-registers via `security.Register` from an `init()`; the
registry is package-global in `security/` (`vbin_*.go` files), with `internal/sysmgmt/` and `internal/starlarkext/`
supplying some of the underlying implementations (e.g. `/proc` access, package management, container
exec). See `docs/VBIN-SPEC.md` for the contract new virtual binaries must follow.

**Starlark standard library (`internal/starlarkext/`).** `SetupExtensions` is the single place that assembles
the Starlark globals: cloud provider namespaces (`aws`, `gcp`, `azure`, `oci`), `k8s`, `secrets`
(Vault/AWS SM/Azure KV/GCP SM), database clients, notifications (Slack/webhook/PagerDuty), Docker
Engine API access, git/GitHub (`git`, `github`), ephemeral audited container exec (`containers`),
security helpers (`sec`), crypto, `net`, `re`, `data` (JSON/YAML), `i18n`, and the `sys` namespace
(`exec_cmd`, `exec_async`, `read_file`, `write_file`, `load_plugin`, `register_command`, ...). In
restricted mode (`-r` / `ADSSH_RESTRICTED`), several of these builtins (file/network/exec access) are
omitted from the dict entirely rather than merely blocked at call time. `main.go` also injects
`sys.enable_ssh`/`disable_ssh` builtins directly (they need access to config not available inside
`starlarkext`).

**Security layer (`security/`)** is the enforcement core shared by the shell, the SSH server, and the
MCP server: Rego/OPA policy (`policy.go`), RBAC entitlements (`entitlements.go`), the audit log and
tamper-evident hash chain (`audit.go`, `audit_chain.go`), change-management gating (`cm.go`,
`cm_hook.go`), four-eyes dual approval (`foureyes.go`, `foureyes_hook.go`), session mirroring
(`mirror.go`), and the virtual binary registry/dispatch described above. Rego policies live in
`policy/` (`default.rego` plus `policy/examples/`) and are evaluated against a `PolicyContext`
(user, groups, command, args, session) built by `security.BuildPolicyContext`.

**`internal/sys/`** owns OS-level session concerns that `security/` and `internal/repl/` build on: the SSH server
(`ssh.go`, using host keys + `authorized_keys` for pubkey-only auth), session tracking
(`session.go`), job control (`job.go`), terminal/ioctl handling (per-OS in `termios_linux.go` /
`termios_darwin.go`), signal setup, and the `pushd`/`popd` directory stack.

**`cmd/adssh-mcp/`** is a separate binary that exposes adssh as a Model Context Protocol server so AI
agents (e.g. Claude) can drive the shell programmatically. `server.go` registers MCP tools
(`eval_starlark`, `run_shell`, `list_sessions`, `cloud_query`, `container_exec`, `audit_log`), each
wrapped in `policyGate`, which runs the exact same `security.EvaluatePolicy` used by the interactive
shell before dispatching to a handler — so MCP-driven commands are subject to the same Rego policy as
a human at the terminal.

**`internal/config/`** handles environment/config loading: `env.go` reads `ADSSH_*` vars into `AppConfig` with
XDG-aware path defaults (`xdg.go`), and `profile.go` loads the Starlark login profile
(`~/.adsshprofile`) and RC script (`~/.adsshrc`) into the shared globals dict at startup.

## Configuration

Behavior is driven by `ADSSH_*` environment variables (see `internal/config/env.go` for the full list and
defaults), including `ADSSH_RESTRICTED`, `ADSSH_SERVE`, `ADSSH_POLICY`, `ADSSH_ENTITLEMENTS`,
`ADSSH_AUDIT_LOG`, `ADSSH_HISTORY`, `ADSSH_HOST_KEY`, `ADSSH_AUTHORIZED_KEYS`, `ADSSH_PROFILE`, and
`ADSSH_RC`. `adssh --init` scaffolds `~/.adssh/` with starter `authorized_keys`, `default.rego`, and
`.adsshrc` files.
