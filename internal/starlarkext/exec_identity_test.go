package starlarkext

import (
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// identityEnv binds s-alice to alice and s-mallory to mallory, sets up a
// session for s-alice, then overwrites the SESSION_ID global with s-mallory.
// Only alice may run commands.
func identityEnv(t *testing.T) starlark.StringDict {
	t.Helper()
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
allow { input.user == "alice" }
deny_reason = "only alice" { input.user != "alice" }
`)})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	for id, user := range map[string]string{"s-alice": "alice", "s-mallory": "mallory"} {
		if err := eng.BindSessionIdentity(id, user, nil); err != nil {
			t.Fatal(err)
		}
	}
	env := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: env, Engine: eng, SessionID: "s-alice"})
	env["SESSION_ID"] = starlark.String("s-mallory")
	return env
}

func TestExecCmdIdentityIgnoresTamperedSessionGlobal(t *testing.T) {
	env := identityEnv(t)
	g, err := evalExec(t, env, `out = sys["exec_cmd"]("echo hi", timeout=5)`)
	if err != nil {
		t.Fatalf("exec_cmd authorized as the tampered session: %v", err)
	}
	if got, _ := starlark.AsString(g["out"]); strings.TrimSpace(got) != "hi" {
		t.Fatalf("out = %q", got)
	}
}

func TestParallelIdentityIgnoresTamperedSessionGlobal(t *testing.T) {
	env := identityEnv(t)
	g, err := evalExec(t, env, `out = sys["parallel"](["echo a", "echo b"], timeout=5)`)
	if err != nil {
		t.Fatalf("parallel authorized as the tampered session: %v", err)
	}
	if list, ok := g["out"].(*starlark.List); !ok || list.Len() != 2 {
		t.Fatalf("out = %v", g["out"])
	}
}
