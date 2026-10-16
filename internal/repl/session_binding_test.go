package repl

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

type replSessionProbe struct {
	mu  sync.Mutex
	saw string
}

func (*replSessionProbe) Name() string        { return "repl-session-probe" }
func (*replSessionProbe) Description() string { return "test vbin" }
func (*replSessionProbe) Usage() string       { return "repl-session-probe" }
func (p *replSessionProbe) Run(ctx context.Context, _ []string) error {
	p.mu.Lock()
	p.saw = security.SessionIDFromContext(ctx)
	p.mu.Unlock()
	return nil
}

var replProbe = &replSessionProbe{}

func init() { security.Register(replProbe) }

func TestMergeStarlarkBindingsSkipsReservedNames(t *testing.T) {
	globals := starlark.StringDict{"SESSION_ID": starlark.String("real")}
	var errOut bytes.Buffer
	MergeStarlarkBindings(globals, starlark.StringDict{
		"SESSION_ID":         starlark.String("bob"),
		"__aliases__":        starlark.String("x"),
		"ADSSH_SESSION_USER": starlark.String("x"),
		"ok":                 starlark.MakeInt(1),
	}, &errOut)
	if globals["SESSION_ID"] != starlark.String("real") {
		t.Fatalf("SESSION_ID = %v", globals["SESSION_ID"])
	}
	if _, ok := globals["__aliases__"]; ok {
		t.Fatal("__aliases__ merged")
	}
	if _, ok := globals["ADSSH_SESSION_USER"]; ok {
		t.Fatal("ADSSH_SESSION_USER merged")
	}
	if globals["ok"] == nil {
		t.Fatal("ordinary binding not merged")
	}
	if n := strings.Count(errOut.String(), "\n"); n != 1 || !strings.Contains(errOut.String(), "SESSION_ID") {
		t.Fatalf("warning = %q", errOut.String())
	}
}

// SESSION_ID = "x" at the REPL leaves the gate and vbins on the real id.
func TestREPLSessionIDAssignmentDoesNotMoveGateOrVBins(t *testing.T) {
	globals := starlark.StringDict{"SESSION_ID": starlark.String("repl-real")}
	st := newSessionState(globals, false, nil)
	if st.SessionID != "repl-real" {
		t.Fatalf("SessionID = %q", st.SessionID)
	}
	var errOut bytes.Buffer
	if code := evalStarlark(&starlark.Thread{}, `SESSION_ID = "bob-session"`, globals, &errOut); code != 0 {
		t.Fatalf("eval code %d: %s", code, errOut.String())
	}
	if globals["SESSION_ID"] != starlark.String("repl-real") {
		t.Fatalf("SESSION_ID global = %v", globals["SESSION_ID"])
	}
	// Even with the global forced, the gate and the vbin use the bound id.
	globals["SESSION_ID"] = starlark.String("bob-session")

	var gateIDs []string
	security.SetRemoteGate(func(_ bool, _ []string, id string) error {
		gateIDs = append(gateIDs, id)
		return nil
	})
	t.Cleanup(func() { security.SetRemoteGate(nil) })
	runner, err := interp.New(
		interp.StdIO(nil, &bytes.Buffer{}, &bytes.Buffer{}),
		interp.CallHandler(security.CallInterceptorSession(st)),
		interp.ExecHandlers(security.BashInterceptorSession(st)),
	)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := syntax.NewParser().Parse(strings.NewReader("repl-session-probe"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background(), prog); err != nil {
		t.Fatal(err)
	}
	if len(gateIDs) != 1 || gateIDs[0] != "repl-real" {
		t.Fatalf("gate ids = %v", gateIDs)
	}
	replProbe.mu.Lock()
	saw := replProbe.saw
	replProbe.mu.Unlock()
	if saw != "repl-real" {
		t.Fatalf("vbin saw %q", saw)
	}
}

func TestNewSessionStateMenuAndEmpty(t *testing.T) {
	st := newSessionState(starlark.StringDict{}, true, nil)
	if st.SessionID != "" || !st.Restricted {
		t.Fatalf("state = %+v", st)
	}
}

func TestStartMenuGatesUnderBoundSessionID(t *testing.T) {
	dir := t.TempDir()
	menuPath := dir + "/menu.yaml"
	if err := os.WriteFile(menuPath, []byte("title: t\nitems:\n  - label: probe\n    command: repl-session-probe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var gateIDs []string
	security.SetRemoteGate(func(_ bool, _ []string, id string) error {
		mu.Lock()
		gateIDs = append(gateIDs, id)
		mu.Unlock()
		return nil
	})
	t.Cleanup(func() { security.SetRemoteGate(nil) })
	globals := starlark.StringDict{"SESSION_ID": starlark.String("menu-real")}
	var out, errOut bytes.Buffer
	inPath := dir + "/in"
	if err := os.WriteFile(inPath, []byte("1\n\nexit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(inPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	StartMenu(menuPath, globals, false, in, &out, &errOut)
	mu.Lock()
	defer mu.Unlock()
	if len(gateIDs) == 0 {
		t.Fatalf("gate not called; stderr=%q out=%q", errOut.String(), out.String())
	}
	for _, id := range gateIDs {
		if id != "menu-real" {
			t.Fatalf("gate ids = %v", gateIDs)
		}
	}
	replProbe.mu.Lock()
	saw := replProbe.saw
	replProbe.mu.Unlock()
	if saw != "menu-real" {
		t.Fatalf("vbin saw %q", saw)
	}
}
