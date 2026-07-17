# adssh Commercial Overhaul — Design

**Date:** 2026-07-16
**Status:** Approved (brainstorming session with Ryan)
**Goal:** Turn adssh from a binary-first app into a production-ready, embeddable Go
library that a closed-source commercial ops platform consumes — with the security
core proven by tests.

## Requirements (from brainstorming)

- **Integration shape:** embedded component — the platform imports adssh's Go
  packages directly. The `adssh` binary becomes a thin consumer of the same API.
- **Consumed surface:** all of it — security/audit engine, Starlark ops runtime,
  intercepted shell execution, and full REPL/SSH sessions.
- **Hard constraints:**
  - Concurrent multi-session: many isolated engines/sessions in one process;
    thread safety and per-instance isolation are non-negotiable.
  - License/IP separation: adssh stays a public repo; its public API must be a
    stable, versioned boundary consumed by closed-source platform code.
- **Test bar:** security-critical first, then broad unit coverage (~70%+),
  integration/E2E harness, and CI with race detection and coverage gating.
- **Approach:** test-first strangler (characterize → refactor under tests → freeze).

## Current-state findings

- Build is clean; existing `security` and `starlarkext` tests pass (Go 1.24.6).
- Only 3 test files across 91 Go files (~17k lines).
- All core state is package-global: vbin registry, audit log, HMAC hash chain,
  policy engine, four-eyes/CM state. One process = one engine today.
- `go.mod` module path is bare `adssh` — unusable as an external import.
- Uncommitted WIP (vbin registry name validation, main.go help integration,
  VBIN-SPEC updates) is coherent and gets committed before the overhaul starts.

## Target architecture

Two layers: embeddable library + thin binary.

### Public API — new `engine` package

- `engine.New(cfg engine.Config) (*Engine, error)` — one Engine per isolated
  tenant/context. Config carries what `ADSSH_*` env vars carry today: policy
  source (Rego bytes or path), entitlements, audit sink, restricted mode,
  profile/RC sources. **Construction fails closed** — bad policy means no engine.
- `Engine` owns everything package-global today: its own vbin registry (seeded
  from the built-in set), policy evaluator, audit log + HMAC hash chain,
  four-eyes/CM state, entitlements. Two Engines in one process share nothing.
- `engine.Session` via `eng.NewSession(user, opts)` — owns a Starlark thread +
  globals dict, shell interpreter state (cwd, dir stack, aliases, jobs), and
  injectable I/O streams (`io.Reader`/`io.Writer`, never direct `os.Stdin/out`).
  Sessions are single-threaded internally; many run in parallel per Engine.
  Shared Engine state (audit chain writes, four-eyes approvals) is mutex-guarded.
- Everything takes `context.Context`; nothing below `main.go` calls `os.Exit`.
- Typed errors so the platform can distinguish deny from failure:
  `ErrPolicyDenied`, `ErrApprovalRequired`, etc.

### Binary

`main.go` and `cmd/adssh-mcp` become consumers: flags/env → `engine.Config` →
Engine → Session → REPL/SSH/MCP. SSH server and MCP tool handlers become library
sub-packages the binary mounts, so the platform can mount them too.

Existing packages (`security/`, `starlarkext/`, `repl/`, `sys/`) keep their names;
their globals move onto Engine/Session structs. Global funcs remain temporarily as
deprecated shims over a default instance.

## Wave 1 — Characterization tests on the security core

Behavior-pinning tests that survive the refactor. All must pass under `-race`.

- **Interceptor chain** (`security/interceptor_test.go`) — table-driven proof of
  the documented order: policy → CM → four-eyes → custom commands → builtins →
  vbins → restricted checks → real exec. Negative cases: policy engine error
  **denies** (fail-closed); denied commands still audited; restricted mode blocks
  `/`-paths, `cd`, `export`; a vbin name never falls through to OS exec.
- **Policy** (extend `security/policy_test.go`) — malformed Rego rejected at load;
  missing policy file behavior; `PolicyContext` fields reach Rego input;
  deny-by-default when no rule matches.
- **Audit chain** (`security/audit_chain_test.go`) — append N entries, verify;
  tamper with any middle entry/HMAC → verification fails; concurrent appends
  don't corrupt the chain.
- **Four-eyes + CM** — approval required, self-approval rejected, expiry,
  wrong-ticket denial.
- **Parser** (`parser/parser_test.go`) — ~50-line table asserting
  Starlark-vs-shell mode decisions.
- **Vbin registry** — finish WIP test file; contract test that every registered
  vbin satisfies VBIN-SPEC basics (non-empty name/usage, error-not-panic on bad
  args).

Where globals make test isolation impossible, that pain is documented — it becomes
the exact Wave 2 refactor list.

## Wave 2 — Refactor to instance-based API

Each step keeps the binary building and Wave 1 tests green:

1. **Module rename** to `github.com/afterdarksys/adssh` (first, while cheap).
2. **`security.Engine` struct** — policy evaluator, entitlements, audit log, hash
   chain, CM/four-eyes state, vbin registry move onto it. Package-level funcs
   become shims over a default instance. `BashInterceptor` becomes
   `(*Engine).ExecHandler(sess *Session)`.
3. **Session extraction** — Starlark thread + globals, shell interpreter,
   cwd/dir-stack/aliases/jobs, injectable I/O. `repl/` and `sys/session.go`
   rebuilt on the Session struct. Concurrency contract enforced and verified by
   `-race` tests running N parallel sessions.
4. **`starlarkext.SetupExtensions`** takes the Session so builtins resolve their
   Engine through it; restricted-mode omission logic unchanged.
5. **Top-level `engine` package** — the public facade. Binaries rewritten as
   consumers. SSH server → `engine/sshserver` (or re-exported from `sys/`); MCP
   handlers become library code.
6. **Kill the shims** — delete or `// Deprecated:`-mark global funcs once both
   binaries compile against `engine`.

Constructors return errors; nothing below main panics except programmer-error
registration (duplicate/invalid vbin names, as the WIP already does).

## Wave 3 — E2E, CI, API freeze

### E2E harness (`e2e/`, build-tagged `//go:build e2e`)

- **Script-driven shell tests** — real `adssh` binary with `-c` and script files
  vs golden outputs: pipelines, vbins (`jq`, `http` against local httptest
  server), Starlark/shell mixing, policy denials, restricted mode.
- **SSH round-trip** — server on random port, test host key + authorized_keys,
  connect via `golang.org/x/crypto/ssh`, assert output and audit entries; bad key
  rejected.
- **MCP round-trip** — spawn `adssh-mcp` over stdio, drive `eval_starlark` /
  `run_shell`, assert the policy gate denies what Rego denies.
- **Concurrency soak** — one Engine, 50 parallel sessions; audit chain verifies
  afterward, `-race` silent. This test proves the commercial requirement.

### CI (GitHub Actions)

On push/PR: build both binaries, `go vet`, `golangci-lint`,
`go test -race ./...`, e2e job on Linux + macOS, coverage ratchet (fail on drop;
~70% overall target, higher bar on `security/`).

### API freeze

- Tag `v0.9.0` once `engine` settles.
- `docs/EMBEDDING.md` with godoc-quality examples (new engine, run session,
  mount SSH/MCP).
- `engine`'s exported surface changes only by deliberate decision until `v1.0.0`.
- Packages the platform shouldn't reach into move under `internal/` — the
  enforcement mechanism for the stable-boundary requirement.

## Rejected alternatives

- **Big-bang restructure** — no safety net under a multi-thousand-line diff of
  security-enforcement code.
- **Facade over globals** — fast but one process = one engine; fails the
  concurrent multi-session requirement outright.
