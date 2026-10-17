package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/adssh/internal/config"
	"github.com/afterdarksys/adssh/internal/starlarkext"
	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// examples/adsshrc must load as written with the real namespaces, so the
// example cannot drift from what adssh supports.
func TestExampleRCLoads(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "examples", "adsshrc"))
	if err != nil {
		t.Fatal(err)
	}
	rc := filepath.Join(t.TempDir(), ".adsshrc")
	if err := os.WriteFile(rc, src, 0o600); err != nil {
		t.Fatal(err)
	}
	env := starlark.StringDict{}
	starlarkext.SetupExtensions(starlarkext.ExtensionOptions{Env: env})
	// As main.go and ssh_session.go do before loading profiles.
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte("package adssh.authz\ndefault allow = true\n")})
	if err != nil {
		t.Fatal(err)
	}
	starlarkext.GovernStarlarkGlobalsInPlace(eng, env)
	got, err := config.LoadProfiles(&starlark.Thread{Name: "test"}, env, false, "", rc)
	if err != nil {
		t.Fatalf("examples/adsshrc failed to load: %v", err)
	}
	for _, name := range []string{"PROMPT", "RPROMPT", "KEYMAP", "__preexec__", "__postcmd__"} {
		if _, ok := got[name]; !ok {
			t.Errorf("examples/adsshrc did not set %s", name)
		}
	}
	cmds, _ := got["__custom_commands__"].(*starlark.Dict)
	if cmds == nil {
		t.Fatal("no __custom_commands__ after loading the example")
	}
	if _, found, _ := cmds.Get(starlark.String("greet")); !found {
		t.Error("examples/adsshrc did not register greet")
	}
}
