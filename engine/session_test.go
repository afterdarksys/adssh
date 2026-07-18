package engine

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// sentinelRecorder records every command that falls through the security
// interceptor instead of executing it, and never calls real OS exec. It mirrors
// the pattern in security/interceptor_test.go.
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

func (s *sentinelRecorder) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// newTestSession builds a session whose runner falls through to rec instead of
// real exec, and returns the session, its stdout/stderr buffers, and rec.
func newTestSession(t *testing.T, id string, restricted bool) (*Session, *bytes.Buffer, *bytes.Buffer, *sentinelRecorder) {
	t.Helper()
	var out, errb bytes.Buffer
	rec := &sentinelRecorder{}
	s, err := NewSession(SessionOptions{
		SessionID:      id,
		User:           "tester",
		Restricted:     restricted,
		Out:            &out,
		Err:            &errb,
		ExecMiddleware: []func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc{rec.middleware},
	})
	if err != nil {
		t.Fatalf("NewSession(%s): %v", id, err)
	}
	return s, &out, &errb, rec
}

// runSrc parses and runs a shell command through the session's own runner.
func runSrc(t *testing.T, s *Session, src string) error {
	t.Helper()
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "test.sh")
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	return s.Runner.Run(context.Background(), f)
}

func TestSessionGateProgramUsesAuthenticatedIdentity(t *testing.T) {
	sec, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`
package adssh
authz := {"allow": input.user == "alice", "reason": "alice required"}
`)})
	if err != nil {
		t.Fatal(err)
	}
	sessionID := "declaration-identity"
	sys.RegisterSession(&sys.Session{ID: sessionID, User: "alice"})
	t.Cleanup(func() { sys.UnregisterSession(sessionID) })

	s, err := NewSession(SessionOptions{SessionID: sessionID, User: "alice", Engine: sec})
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("export SAFE=1"), "test.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.GateProgram(file); err != nil {
		t.Fatalf("authenticated identity was dropped for declaration gate: %v", err)
	}
}

// TestSession_IsolatedGlobals proves a custom command, a shopt (xtrace), and the
// per-session bag dicts registered in session A are invisible to session B.
func TestSession_IsolatedGlobals(t *testing.T) {
	a, _, aErr, aRec := newTestSession(t, "A", false)
	b, _, _, bRec := newTestSession(t, "B", false)

	// The per-session bag dicts must be distinct objects, not shared pointers.
	for _, key := range []string{"__custom_commands__", "__aliases__", "__completers__", "plugins"} {
		if a.Globals[key] == b.Globals[key] {
			t.Errorf("bag %q is shared between sessions (same pointer)", key)
		}
	}

	// Register a custom command in A only, via A's own Starlark thread/globals.
	regSrc := "def acmd(a):\n    return None\nsys[\"register_command\"](\"acmd\", acmd)\n"
	if _, err := starlark.ExecFile(a.Thread, "<reg>", regSrc, a.Globals); err != nil {
		t.Fatalf("register_command in A: %v", err)
	}

	// A's custom-commands dict has acmd; B's does not.
	aCmds := a.Globals["__custom_commands__"].(*starlark.Dict)
	if _, found, _ := aCmds.Get(starlark.String("acmd")); !found {
		t.Fatal("A did not record custom command acmd")
	}
	bCmds := b.Globals["__custom_commands__"].(*starlark.Dict)
	if _, found, _ := bCmds.Get(starlark.String("acmd")); found {
		t.Error("custom command acmd leaked into B")
	}

	// Through the runner: acmd is invoked in A (never reaches sentinel), while in
	// B it is unknown and falls through to exec/sentinel.
	if err := runSrc(t, a, "acmd x"); err != nil {
		t.Fatalf("A run acmd: %v", err)
	}
	if aRec.count() != 0 {
		t.Errorf("A's custom command fell through to exec: %v", aRec.calls)
	}
	if err := runSrc(t, b, "acmd x"); err != nil {
		t.Fatalf("B run acmd: %v", err)
	}
	if bRec.count() != 1 {
		t.Errorf("B should have fallen through to exec for unknown acmd, got %d calls", bRec.count())
	}

	// shopt isolation: enabling xtrace in A's own __shopts__ makes A echo "+ cmd"
	// while B (no xtrace) stays quiet. This exercises the interceptor reading the
	// per-session __shopts__ dict.
	shopts := starlark.NewDict(1)
	_ = shopts.SetKey(starlark.String("xtrace"), starlark.Bool(true))
	a.Globals["__shopts__"] = shopts

	if err := runSrc(t, a, "xtcmd"); err != nil {
		t.Fatalf("A run xtcmd: %v", err)
	}
	if !strings.Contains(aErr.String(), "+ xtcmd") {
		t.Errorf("A xtrace did not print '+ xtcmd'; stderr=%q", aErr.String())
	}
	// Run the same command in B (no xtrace) and confirm no '+' trace appears.
	if err := runSrc(t, b, "xtcmd"); err != nil {
		t.Fatalf("B run xtcmd: %v", err)
	}
	if strings.Contains(bErrString(b), "+ xtcmd") {
		t.Errorf("B printed xtrace despite no per-session xtrace shopt")
	}
}

// bErrString returns the stderr buffer content of a session created via
// newTestSession. It relies on the Err writer being a *bytes.Buffer.
func bErrString(s *Session) string {
	if buf, ok := s.Err.(*bytes.Buffer); ok {
		return buf.String()
	}
	return ""
}

// TestSession_IsolatedDirStacks proves pushd/cd state in A does not affect B.
func TestSession_IsolatedDirStacks(t *testing.T) {
	a, _, _, _ := newTestSession(t, "A", false)
	b, _, _, _ := newTestSession(t, "B", false)

	if a.Dirs == b.Dirs {
		t.Fatal("sessions share a directory stack")
	}

	// Push a directory onto A's stack; B's stack must be unchanged.
	a.Dirs.Push("/tmp/aaa-session-A")
	aDirs := a.Dirs.Dirs() // top first
	if len(aDirs) == 0 || aDirs[0] != "/tmp/aaa-session-A" {
		t.Fatalf("A's stack did not record the push: %v", aDirs)
	}
	for _, d := range b.Dirs.Dirs() {
		if d == "/tmp/aaa-session-A" {
			t.Fatalf("A's pushd leaked into B's stack: %v", b.Dirs.Dirs())
		}
	}

	// Per-session cwd: cd in A moves only A's runner Dir (no os.Chdir), leaving
	// B's runner Dir untouched.
	bStart := b.Runner.Dir
	if err := runSrc(t, a, "cd /"); err != nil {
		t.Fatalf("A cd /: %v", err)
	}
	if a.Runner.Dir != "/" {
		t.Errorf("A's runner Dir did not become /, got %q", a.Runner.Dir)
	}
	if b.Runner.Dir != bStart {
		t.Errorf("B's runner Dir changed after A's cd: %q != %q", b.Runner.Dir, bStart)
	}
}

// TestSession_IsolatedRestricted proves the restricted flag is per-session: A is
// restricted, B is not, and both sec.is_restricted() and the interceptor's
// slash-command block differ accordingly.
func TestSession_IsolatedRestricted(t *testing.T) {
	a, _, _, aRec := newTestSession(t, "A", true)
	b, _, _, bRec := newTestSession(t, "B", false)

	// sec.is_restricted() differs per session (per-session closure, not a global).
	av, err := starlark.Eval(a.Thread, "<t>", "sec[\"is_restricted\"]()", a.Globals)
	if err != nil {
		t.Fatalf("A sec.is_restricted(): %v", err)
	}
	if av != starlark.True {
		t.Errorf("A sec.is_restricted() = %v, want True", av)
	}
	bv, err := starlark.Eval(b.Thread, "<t>", "sec[\"is_restricted\"]()", b.Globals)
	if err != nil {
		t.Fatalf("B sec.is_restricted(): %v", err)
	}
	if bv != starlark.False {
		t.Errorf("B sec.is_restricted() = %v, want False", bv)
	}

	// A's runner blocks a /-prefixed command; B's runs it (falls to sentinel).
	if err := runSrc(t, a, "/bin/ls"); err == nil || !strings.Contains(err.Error(), "restricted") {
		t.Errorf("A restricted did not block /bin/ls: err=%v", err)
	}
	if aRec.count() != 0 {
		t.Errorf("A restricted let /bin/ls reach exec: %v", aRec.calls)
	}
	if err := runSrc(t, b, "/bin/ls"); err != nil {
		t.Fatalf("B run /bin/ls: %v", err)
	}
	if bRec.count() != 1 {
		t.Errorf("B (unrestricted) should have run /bin/ls through exec, got %d calls", bRec.count())
	}
}

// TestSession_ConcurrentShellSmoke runs 10 sessions in parallel, each executing a
// few shell commands through its own runner with its own sentinel exec
// middleware. It must be -race silent and each session's output must land only
// in its own buffer.
func TestSession_ConcurrentShellSmoke(t *testing.T) {
	const n = 10
	type unit struct {
		s   *Session
		out *bytes.Buffer
		rec *sentinelRecorder
		id  string
	}
	units := make([]unit, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("sess-%02d", i)
		var out bytes.Buffer
		rec := &sentinelRecorder{}
		s, err := NewSession(SessionOptions{
			SessionID:      id,
			Out:            &out,
			ExecMiddleware: []func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc{rec.middleware},
		})
		if err != nil {
			t.Fatalf("NewSession %s: %v", id, err)
		}
		units[i] = unit{s: s, out: &out, rec: rec, id: id}
	}

	var wg sync.WaitGroup
	for i := range units {
		wg.Add(1)
		go func(u unit) {
			defer wg.Done()
			// echo (builtin) -> own buffer; extcmd (external) -> interceptor +
			// default engine + sentinel; alias/set (builtins) exercise the runner.
			for _, src := range []string{"echo " + u.id, "extcmd-" + u.id, "alias x=y", "set +x"} {
				f, perr := syntax.NewParser().Parse(strings.NewReader(src), "smoke.sh")
				if perr != nil {
					t.Errorf("parse %q: %v", src, perr)
					return
				}
				_ = u.s.Runner.Run(context.Background(), f)
			}
		}(units[i])
	}
	wg.Wait()

	for _, u := range units {
		if !strings.Contains(u.out.String(), u.id) {
			t.Errorf("session %s output missing its echo: %q", u.id, u.out.String())
		}
		// The external command for THIS session must have reached its own
		// sentinel exactly once, and no other id may appear in it.
		if u.rec.count() != 1 {
			t.Errorf("session %s sentinel calls = %d, want 1", u.id, u.rec.count())
		} else if got := u.rec.calls[0][0]; got != "extcmd-"+u.id {
			t.Errorf("session %s sentinel saw %q, want extcmd-%s", u.id, got, u.id)
		}
	}
}
