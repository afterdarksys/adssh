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

// sentinelRecorder records every command that falls through BashInterceptor
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

// A Rego construct that DOES reliably produce a Go-level eval error in this
// OPA version is a conflicting complete rule: two `allow` definitions that
// both match the same input and assign different values trigger
// eval_conflict_error, which rego.Eval surfaces as a real error. That is
// used here to characterize the fail-closed path with a real (not weakened)
// assertion.
func TestInterceptor_PolicyEvalError_FailsClosed(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	if err := LoadPolicy(writePolicy(t, `package adssh.authz
allow = "yes" { input.command == "anything" }
allow = "no" { input.command == "anything" }`)); err != nil {
		t.Fatal(err)
	}
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "anything")
	if runErr == nil {
		t.Fatal("expected error when policy evaluation errors (fail-closed)")
	}
	if !strings.Contains(runErr.Error(), "policy evaluation error") {
		t.Errorf("expected policy-evaluation-error message, got: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("command executed despite policy eval error: %v", rec.calls)
	}
}

// GAP CLOSED (Wave 2): builtin runtime errors (e.g. division by zero) used to
// be swallowed by OPA in the default (non-strict) mode that policy.LoadPolicy
// used — the rule silently became undefined and EvaluatePolicy's fallback
// ("no allow key in result => allowed=true") kicked in, so a policy hitting a
// builtin runtime error FAILED OPEN despite the "fail closed on errors
// (T-01-02)" contract. Wave 2 closed this by adding rego.StrictBuiltinErrors(true)
// to the rego.New(...) options in policy.go, so builtin runtime errors now
// surface as Eval errors. EvaluatePolicy returns those as errors and the
// interceptor treats them as deny. This test now pins the correct fail-closed
// behavior: the command must be blocked with a "policy evaluation error" and
// must never fall through to exec.
func TestInterceptor_PolicyBuiltinError_FailsClosed(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	if err := LoadPolicy(writePolicy(t, `package adssh.authz
allow = true { 1 / 0 > 0 }`)); err != nil {
		t.Fatal(err)
	}
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "anything")
	if runErr == nil {
		t.Fatal("expected error when policy hits a builtin runtime error (fail-closed)")
	}
	if !strings.Contains(runErr.Error(), "policy evaluation error") {
		t.Errorf("expected policy-evaluation-error message, got: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("command executed despite policy builtin runtime error: %v", rec.calls)
	}
}

// --- vbins, restricted mode, custom commands ---

// fake vbin for registry tests — registered once via unique name below.
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
