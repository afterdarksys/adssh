package security

import (
	"context"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"

	"go.starlark.net/starlark"
)

func TestBindSessionIdentityRejectsEmpty(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.BindSessionIdentity("", "alice", nil); err == nil {
		t.Fatal("empty session ID was bound")
	}
	if err := eng.BindSessionIdentity("s1", "", nil); err == nil {
		t.Fatal("empty user was bound")
	}
	if err := eng.BindSessionIdentity("s1", "alice", []string{"ops"}); err != nil {
		t.Fatal(err)
	}
	if err := eng.BindSessionIdentity("s1", "alice", []string{"admin"}); err == nil {
		t.Fatal("rebinding with other groups was accepted")
	}
	if err := eng.BindSessionIdentity("s1", "alice", []string{"ops"}); err != nil {
		t.Fatalf("identical rebind: %v", err)
	}
	eng.UnbindSessionIdentity("s1")
	if pctx := eng.buildPolicyContext("ls", nil, "s1"); pctx.User != "alice" || pctx.IdentityUnknown {
		t.Fatalf("first unbind dropped a counted binding: %#v", pctx)
	}
	eng.UnbindSessionIdentity("s1")
	if pctx := eng.buildPolicyContext("ls", nil, "s1"); pctx.User != "" || !pctx.IdentityUnknown {
		t.Fatalf("unbound session resolved: %#v", pctx)
	}
	eng.UnbindSessionIdentity("never-bound")
}

func TestBuildPolicyContextResolutionOrder(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	const id = "order-probe"
	if err := sys.RegisterSession(&sys.Session{ID: id, User: "registry-user", Principals: []string{"reg"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })

	if pctx := eng.buildPolicyContext("ls", nil, id); pctx.User != "registry-user" || pctx.IdentityUnknown {
		t.Fatalf("registry identity not used: %#v", pctx)
	}
	if err := eng.BindSessionIdentity(id, "bound-user", []string{"g"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.UnbindSessionIdentity(id) })
	pctx := eng.buildPolicyContext("ls", nil, id)
	if pctx.User != "bound-user" || len(pctx.Groups) != 1 || pctx.Groups[0] != "g" {
		t.Fatalf("engine binding did not win: %#v", pctx)
	}
	// Mutating the returned groups must not change the binding.
	pctx.Groups[0] = "root"
	if again := eng.buildPolicyContext("ls", nil, id); again.Groups[0] != "g" {
		t.Fatalf("binding groups aliased: %#v", again.Groups)
	}
	// Another engine does not see this binding.
	other, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got := other.buildPolicyContext("ls", nil, id).User; got != "registry-user" {
		t.Fatalf("binding leaked across engines: %q", got)
	}

	user, _ := CurrentOSIdentity()
	if got := eng.buildPolicyContext("ls", nil, ""); got.User != user || got.IdentityUnknown {
		t.Fatalf("empty session ID = %#v, want OS user %q", got, user)
	}
}

func TestAuthorizeCommandUnknownSessionDenied(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte("package adssh\nauthz := {\"allow\": true}\n")})
	if err != nil {
		t.Fatal(err)
	}
	err = eng.AuthorizeCommand([]string{"ls"}, "bogus-session-id")
	if err == nil || !strings.Contains(err.Error(), "session identity unknown") {
		t.Fatalf("unknown session authorized: %v", err)
	}
	if last, ok := eng.LastDenial("bogus-session-id"); !ok || last.Command != "ls" {
		t.Fatalf("denial not remembered: %#v ok=%v", last, ok)
	}
	if err := eng.AuthorizeCommand([]string{"ls"}, ""); err != nil {
		t.Fatalf("unnamed command under allow-all: %v", err)
	}
}

func TestExplainUnknownSessionDenied(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte("package adssh\nauthz := {\"allow\": true}\n")})
	if err != nil {
		t.Fatal(err)
	}
	exp, err := eng.ExplainCommand("bogus-explain", []string{"ls"})
	if err != nil {
		t.Fatal(err)
	}
	if exp.Outcome != "denied" || len(exp.Stages) == 0 || exp.Stages[0].Name != "identity" {
		t.Fatalf("explanation = %#v", exp)
	}
}

func TestExecHandlerRefusesReservedSetNames(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	globals := starlark.StringDict{"SESSION_ID": starlark.String("reserved-probe")}
	h := eng.execHandler(false, globals, nil)(func(ctx context.Context, args []string) error {
		t.Fatalf("reserved set reached next: %v", args)
		return nil
	})
	for _, args := range [][]string{
		{"set", "SESSION_ID=nope"},
		{"set", "SESSION_ID", "nope"},
		{"set", "__aliases__=x"},
		{"set", "ADSSH_SESSION_ID=x"},
	} {
		err := h(context.Background(), args)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("%v was not refused: %v", args, err)
		}
		if strings.Contains(err.Error(), "nope") {
			t.Fatalf("error echoes the value: %v", err)
		}
	}
	if got := sessionIDFromGlobals(globals); got != "reserved-probe" {
		t.Fatalf("SESSION_ID changed to %q", got)
	}
}

func TestSessionStateSessionIDWinsOverGlobals(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte("package adssh\nauthz := {\"allow\": input.user == \"alice\"}\n")})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.BindSessionIdentity("fixed-alice", "alice", nil); err != nil {
		t.Fatal(err)
	}
	if err := eng.BindSessionIdentity("fixed-bob", "bob", nil); err != nil {
		t.Fatal(err)
	}
	globals := starlark.StringDict{"SESSION_ID": starlark.String("fixed-alice")}
	handler := eng.callHandler(&SessionState{Globals: globals, SessionID: "fixed-bob"})
	if _, err := handler(context.Background(), []string{"ls"}); err == nil {
		t.Fatal("tampered globals SESSION_ID overrode SessionState.SessionID")
	}
}
