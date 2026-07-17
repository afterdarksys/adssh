# Wave 1: Security-Core Characterization Tests — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Pin down the current behavior of adssh's security enforcement core with characterization + negative tests, so the Wave 2 instance-based refactor has a safety net.

**Architecture:** Pure unit tests where the code allows (parser, CM validity, chain hashing); interpreter-integration tests for the interceptor using a **sentinel exec handler** placed after `BashInterceptor` in the `mvdan.cc/sh/v3/interp` middleware chain, so we can observe fall-through without executing real binaries. Package globals (`preparedQuery`, `chainPath`/`chainKey`, four-eyes HOME-relative dirs, CM env vars) are reset per test via helpers + `t.Setenv`/`t.TempDir`.

**Tech Stack:** Go 1.24 stdlib `testing`, `mvdan.cc/sh/v3/{syntax,interp}`, `net/http/httptest`, OPA rego (already vendored). All tests must pass `go test -race ./...`.

**Conventions:** Match existing style in `security/policy_test.go` (plain testing pkg, no testify; reset helpers; `t.TempDir()`). Run tests with `ASDF_GOLANG_VERSION=1.24.6` prefix.

**Characterization findings to preserve (do NOT "fix" during Wave 1 — record as `// CHARACTERIZATION:` comments):**
- No policy loaded / policy file missing → **allow-all** (fail-open). Flagged for Wave 2 (engine config must make this explicit).
- Policy *evaluation error* → fail-closed (interceptor returns error, command blocked).
- `CheckFourEyes` ignores its `cmd` param and matches on `strings.Join(args, " ")`.
- `cd`/`export` restricted-mode checks may be dead code (mvdan handles builtins before exec handlers) — the test records whichever behavior is real.

---

### Task 1: Interceptor test harness + policy-gate tests

**Files:**
- Create: `security/interceptor_test.go`

**Step 1: Write the harness + failing tests**

```go
package security

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// sentinelHandler records every command that falls through BashInterceptor
// instead of executing it. It never calls the real exec handler.
type sentinelRecorder struct {
	mu    sync.Mutex
	calls [][]string
}

func (s *sentinelRecorder) middleware(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(ctx context.Context, args []string) error {
		s.mu.Lock()
		s.calls = append(s.calls, args)
		s.mu.Unlock()
		return nil
	}
}

// runShell parses src and runs it through a runner wired exactly like
// main.go:231, with the sentinel in place of real exec.
// Returns stdout, stderr, the runner error, and the recorder.
func runShell(t *testing.T, restricted bool, globals starlark.StringDict, src string) (string, string, error, *sentinelRecorder) {
	t.Helper()
	rec := &sentinelRecorder{}
	var stdout, stderr bytes.Buffer
	r, err := interp.New(
		interp.StdIO(strings.NewReader(""), &stdout, &stderr),
		interp.ExecHandlers(BashInterceptor(restricted, globals), rec.middleware),
	)
	if err != nil {
		t.Fatalf("interp.New: %v", err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(src), "test.sh")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	runErr := r.Run(context.Background(), file)
	return stdout.String(), stderr.String(), runErr, rec
}

func writePolicy(t *testing.T, rego string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.rego")
	if err := os.WriteFile(path, []byte(rego), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- policy gate through the interceptor ---

func TestInterceptor_PolicyDeny_BlocksAndNeverExecs(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	if err := LoadPolicy(writePolicy(t, `package adssh.authz
default allow = false
deny_reason = "nope" { input.command == "dangerous" }`)); err != nil {
		t.Fatal(err)
	}
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "dangerous --arg")
	if runErr == nil {
		t.Fatal("expected error from denied command")
	}
	if !strings.Contains(runErr.Error(), "access denied") {
		t.Errorf("expected access-denied error, got: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("denied command fell through to exec: %v", rec.calls)
	}
}

func TestInterceptor_PolicyAllow_FallsThrough(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	if err := LoadPolicy(writePolicy(t, `package adssh.authz
default allow = true`)); err != nil {
		t.Fatal(err)
	}
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "somecmd a b")
	if runErr != nil {
		t.Fatalf("unexpected error: %v", runErr)
	}
	if len(rec.calls) != 1 || rec.calls[0][0] != "somecmd" {
		t.Errorf("expected somecmd to reach exec, got: %v", rec.calls)
	}
}

// CHARACTERIZATION: a Rego runtime error (division by zero) must DENY, not allow.
func TestInterceptor_PolicyEvalError_FailsClosed(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	if err := LoadPolicy(writePolicy(t, `package adssh.authz
allow = true { 1 / 0 > 0 }`)); err != nil {
		t.Fatal(err)
	}
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "anything")
	if runErr == nil {
		t.Fatal("expected error when policy evaluation errors (fail-closed)")
	}
	if len(rec.calls) != 0 {
		t.Errorf("command executed despite policy eval error: %v", rec.calls)
	}
}
```

Note for implementer: if OPA turns the division-by-zero into an *undefined* result rather than an eval error, the test will fail — in that case find a Rego construct that reliably errors at eval time (e.g. `allow = x { x := {"a": 1}["b"] }` variants) or, failing that, change the test to document the actual reachable behavior and add a `// CHARACTERIZATION-GAP:` note that eval errors could not be triggered from Rego source. Do not weaken the assertion silently.

**Step 2: Run and iterate**

Run: `ASDF_GOLANG_VERSION=1.24.6 go test ./security/ -run TestInterceptor_Policy -v`
Expected: all PASS (these characterize existing behavior; failures mean the harness is wrong or a real finding — investigate, don't force).

**Step 3: Commit**

```bash
git add security/interceptor_test.go
git commit -m "test: interceptor policy-gate characterization (deny blocks exec, fail-closed on eval error)"
```

### Task 2: Interceptor — vbins, restricted mode, custom commands

**Files:**
- Modify: `security/interceptor_test.go` (append)

**Step 1: Add tests**

```go
// fake vbin for registry tests — registered once via init-safe guard.
type fakeVBin struct{ ran *bool }

func (f fakeVBin) Name() string        { return "wave1-fake-vbin" }
func (f fakeVBin) Description() string { return "test vbin" }
func (f fakeVBin) Usage() string       { return "wave1-fake-vbin" }
func (f fakeVBin) Run(ctx context.Context, args []string) error {
	*f.ran = true
	return nil
}

func TestInterceptor_VBinNeverReachesExec(t *testing.T) {
	resetPolicy()
	ran := false
	Register(fakeVBin{ran: &ran}) // panics if name collides — unique name above
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "wave1-fake-vbin")
	if runErr != nil {
		t.Fatalf("unexpected error: %v", runErr)
	}
	if !ran {
		t.Error("vbin did not run")
	}
	if len(rec.calls) != 0 {
		t.Errorf("vbin name fell through to exec: %v", rec.calls)
	}
}

func TestInterceptor_Restricted_SlashCommandBlocked(t *testing.T) {
	resetPolicy()
	_, _, runErr, rec := runShell(t, true, starlark.StringDict{}, "/bin/ls")
	if runErr == nil || !strings.Contains(runErr.Error(), "restricted") {
		t.Fatalf("expected restricted error, got: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("slash command executed in restricted mode: %v", rec.calls)
	}
}

// CHARACTERIZATION: record whether cd/export ever reach the exec handler
// (mvdan may handle them as builtins first — if so this documents dead code
// in the interceptor's restricted check, a Wave 2 fix).
func TestInterceptor_Restricted_CdExport(t *testing.T) {
	resetPolicy()
	for _, src := range []string{"cd /", "export FOO=bar"} {
		_, _, runErr, rec := runShell(t, true, starlark.StringDict{}, src)
		t.Logf("restricted %q => err=%v execCalls=%v", src, runErr, rec.calls)
		// Assert the security outcome: either the interceptor blocks it, or
		// mvdan's builtin handles it without reaching exec. Falling through
		// to a real exec would be the only failure.
		if len(rec.calls) != 0 {
			t.Errorf("%q fell through to real exec in restricted mode", src)
		}
	}
}

func TestInterceptor_CustomCommand_Invoked(t *testing.T) {
	resetPolicy()
	called := false
	fn := starlark.NewBuiltin("mycmd", func(th *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		called = true
		return starlark.None, nil
	})
	cmds := new(starlark.Dict)
	_ = cmds.SetKey(starlark.String("mycmd"), fn)
	globals := starlark.StringDict{"__custom_commands__": cmds}
	_, _, runErr, rec := runShell(t, false, globals, "mycmd arg1")
	if runErr != nil {
		t.Fatalf("unexpected error: %v", runErr)
	}
	if !called {
		t.Error("custom command was not invoked")
	}
	if len(rec.calls) != 0 {
		t.Errorf("custom command fell through to exec: %v", rec.calls)
	}
}
```

**Step 2: Run** `ASDF_GOLANG_VERSION=1.24.6 go test ./security/ -run TestInterceptor -v` → PASS (or documented findings).

**Step 3: Commit** `git commit -m "test: interceptor vbin/restricted/custom-command characterization"`

### Task 3: Audit chain tests

**Files:**
- Create: `security/audit_chain_test.go`

Reset helper (chain state is package-global):

```go
func resetChain() {
	chainMu.Lock()
	defer chainMu.Unlock()
	chainPath, chainKey, chainSession = "", nil, ""
}
```

Tests (full code in the same style as Tasks 1–2):

1. `TestChain_AppendAndVerify` — `InitChain(tmp/ledger.jsonl, tmp/key, "s1")`, `AppendChain` 5 entries (`Type:"cmd"`, distinct `Command`s), `VerifyChain` → `ok=true`. Assert seq numbers are 0..4 and each entry's `PrevHash` equals the previous entry's `Hash` (read the file, unmarshal each line).
2. `TestChain_TamperedEntryDetected` — append 5, rewrite line 2 changing `"cmd"` field text (unmarshal, mutate `Command`, re-marshal, keep old Hash), `VerifyChain` → `ok=false`, `badSeq==2`.
3. `TestChain_TamperedHashDetected` — same but corrupt the `Hash` hex of the last line → `ok=false`.
4. `TestChain_TruncationBreaksNothingButDeletionOfMiddleDetected` — delete middle line entirely → verification fails (prev-hash mismatch on the following entry). *(CHARACTERIZATION: truncating from the tail is NOT detectable by VerifyChain — document with a `t.Log` and comment; Wave 2+ may add a head-anchor.)*
5. `TestChain_ConcurrentAppends` — `InitChain`, 20 goroutines × 5 `AppendChain` each (WaitGroup), then `VerifyChain` → `ok=true` and 100 lines. This is the `-race` workhorse.
6. `TestChain_NoInitIsNoOp` — `resetChain()`, `AppendChain` → no panic, no file created.
7. `TestChain_KeyRoundTrip` — `loadOrCreateChainKey` creates 32-byte key file with 0600 perms; second call returns identical key.

Each test starts with `resetChain()` + `t.Cleanup(resetChain)` and uses `t.TempDir()`.

Run: `ASDF_GOLANG_VERSION=1.24.6 go test ./security/ -run TestChain -race -v` → PASS.
Commit: `test: audit hash-chain characterization (tamper detection, concurrency, no-init no-op)`

### Task 4: Four-eyes + change-management tests

**Files:**
- Create: `security/foureyes_test.go`
- Create: `security/cm_test.go`

**foureyes_test.go** — every test does `t.Setenv("HOME", t.TempDir())` so `FourEyesDir()` lands in the sandbox:

1. `TestFourEyes_RulesCRUD` — `AddFourEyesRule("rm *", "alice", 60)` → `LoadFourEyesRules` returns it; add same pattern again with different approver → replaced not duplicated; `RemoveFourEyesRule` → gone.
2. `TestFourEyes_DefaultTTL` — `AddFourEyesRule("x", "", 0)` → stored TTL is 300.
3. `TestFourEyes_Match` — table: rules `["rm *"]`; `MatchesFourEyes("rm -rf /")` → matched; `MatchesFourEyes("ls")` → not matched.
4. `TestCheckFourEyes_NoRules_NoOp` — no rules file → `CheckFourEyes("rm", []string{"rm","-rf"}, nil)` returns nil instantly.
5. `TestFourEyes_ApproveDenyMarkers` — `ApproveRequest("tok1")` writes marker in approved dir + removes pending; `DenyRequest("tok2")` likewise in denied dir.
6. `TestFourEyes_Timeout` — rule TTL 1 matching pattern `rm *`; `CheckFourEyes` on `rm -rf /` returns "timed out" error after ~2s and pending file is cleaned up. (This test sleeps ~2s — acceptable; do NOT try to test the interactive approve race here, that's Wave 3 E2E.)

**cm_test.go:**

1. `TestIsTicketValid` — table over: nil ticket → false; state "open" → false; "approved" no window → true; approved with future StartWindow → false; approved with past EndWindow → false; approved inside window → true.
2. `TestCMRequiredForCommand` — `t.Setenv("ADSSH_CM_PATTERNS", "rm,kubectl*")`: `rm` true, `/bin/rm` true (basename match), `kubectl` true, `ls` false; empty env → always false.
3. `TestCMSessionCheck_StrictBlocks` — `t.Setenv` patterns + `ADSSH_CM_STRICT=1`, `ClearActiveCMTicket()` + cleanup → `CMSessionCheck("rm", nil)` returns error; non-strict → nil. Valid active ticket (`SetActiveCMTicket(&CMTicket{State:"approved"}, "CHG1")`) → nil; invalid state ticket → error.
4. `TestFetchCMTicket_Generic` — `httptest.NewServer` serving `/tickets/CHG-1` JSON; `t.Setenv("ADSSH_CM_URL", srv.URL)`, provider generic → fields mapped. Also: server 500 → error; `ADSSH_CM_URL` unset → error.
5. `TestFetchCMTicket_UnknownProvider` — provider "bogus" → descriptive error.

Note: CM env access isn't mutex'd, so **do not** mark these `t.Parallel()`.

Run: `ASDF_GOLANG_VERSION=1.24.6 go test ./security/ -run 'TestFourEyes|TestCM|TestCheckFourEyes|TestIsTicket|TestFetchCM' -race -v`
Commit: `test: four-eyes and change-management gate characterization`

### Task 5: Parser mode-detection table test

**Files:**
- Create: `parser/parser_test.go`

One table-driven test, ~40 cases covering: `!cmd`/`$ cmd` → shell; `def f():`, `for x in y:`, `if x:`, `print(...)` → Starlark; `x = 5`, `x=5`, `FOO=bar cmd` *(CHARACTERIZATION: env-prefix assignment currently routes to Starlark — known heuristic quirk, document it)* → Starlark; `x == 5` guard → shell; `ls -la`, `git status`, pipelines, empty string, whitespace-only → shell. Assert exact `EvalMode`. Cases that expose heuristic quirks get a `quirk: true` field and a comment rather than being "fixed".

Run: `ASDF_GOLANG_VERSION=1.24.6 go test ./parser/ -v` → PASS.
Commit: `test: parser mode-detection characterization table`

### Task 6: Policy edge cases + full-suite race gate

**Files:**
- Modify: `security/policy_test.go` (append)

1. `TestLoadPolicy_MalformedRego` — garbage Rego → `LoadPolicy` returns error, and previously loaded policy remains active (load good deny policy first, then bad load, then evaluate → still denies).
2. `TestEvaluatePolicy_InputFieldsReachRego` — policy `allow { input.user == "alice"; "ops" == input.groups[_] }`; alice+ops allowed, bob denied.
3. `TestBuildPolicyContext_Defaults` — empty sessionID → User is current OS user (non-empty), Time parses as RFC3339.

Final gate:
```bash
ASDF_GOLANG_VERSION=1.24.6 go test -race ./... 
ASDF_GOLANG_VERSION=1.24.6 go vet ./...
```
Expected: all packages PASS, vet clean.
Commit: `test: policy edge cases; Wave 1 security-core characterization complete`

---

## Out of scope for Wave 1 (explicitly)

- Fixing anything the characterization reveals (record with `// CHARACTERIZATION:` comments and t.Log; fixes land in Wave 2 under these tests).
- Vbin contract tests beyond the WIP registry test (Wave 1.5 with broad unit coverage).
- CI workflow files, E2E, SSH/MCP tests (Wave 3).
- `RequestApproval` interactive approval race (needs process separation — Wave 3).
