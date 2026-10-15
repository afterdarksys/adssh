package starlarkext

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

func pluginTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("ADSSH_PLUGIN_DIR", root)
	t.Cleanup(func() {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if d != nil && d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if d == nil || d.IsDir() || walkErr != nil {
				if cerr := os.Chmod(path, 0o700); cerr != nil && !os.IsNotExist(cerr) {
					t.Errorf("chmod %s: %v", path, cerr)
				}
			}
			return nil
		})
		if err != nil {
			t.Errorf("walk %s: %v", root, err)
		}
	})
	return root
}

func writeStarlarkPlugin(t *testing.T, root, name, star string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := "name: \"" + name + "\"\ndescription: \"says hello\"\n"
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugin.star"), []byte(star), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPluginsArgumentsDoNotOpen(t *testing.T) {
	root := pluginTestRoot(t)
	writeStarlarkPlugin(t, root, "hello", "def greet(args):\n    return \"one\"\nsys[\"register_command\"](\"greet\", greet)\n")
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	env := execEnv(t, allowAllEngine(t), false)
	cases := []struct {
		src  string
		want string
		not  string
	}{
		{`sys["load_plugins"]()`, "load_plugins: pass names or all=True", "not both"},
		{`sys["load_plugins"](names=["hello"], all=True)`, "load_plugins: pass names or all=True, not both", ""},
		{`sys["load_plugins"](names=[])`, "load_plugins: names must not be empty", ""},
		{`sys["load_plugins"](names=[1])`, "plugin: invalid name", ""},
	}
	for _, tc := range cases {
		_, err := evalExec(t, env, tc.src)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s error %v, want %q", tc.src, err, tc.want)
		}
		if tc.not != "" && strings.Contains(err.Error(), tc.not) {
			t.Fatalf("%s error %q contains %q", tc.src, err.Error(), tc.not)
		}
		if strings.Contains(err.Error(), "permission") {
			t.Fatalf("%s opened the directory: %v", tc.src, err)
		}
	}
	if _, ok := env["greet"]; ok {
		t.Fatal("argument error registered greet")
	}
}

func TestLoadPluginsHappyPath(t *testing.T) {
	root := pluginTestRoot(t)
	writeStarlarkPlugin(t, root, "hello", "def greet(args):\n    return \"one\"\nsys[\"register_command\"](\"greet\", greet)\n")
	env := execEnv(t, allowAllEngine(t), false)
	if _, ok := env["__custom_commands__"].(*starlark.Dict); !ok {
		t.Fatal("commands bag was wrapped")
	}
	if _, ok := env["plugins"].(*starlark.Dict); !ok {
		t.Fatal("plugins bag was wrapped")
	}
	mod, err := evalExec(t, env, `out = sys["load_plugins"](names=["hello"])`)
	if err != nil {
		t.Fatal(err)
	}
	out, ok := mod["out"].(*starlark.List)
	if !ok || out.Len() != 1 {
		t.Fatalf("out %v", mod["out"])
	}
	got, ok := out.Index(0).(starlark.String)
	if !ok || string(got) != "hello" {
		t.Fatalf("loaded %v", out.Index(0))
	}
	mod, err = evalExec(t, env, `out = greet(["x"])`)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := starlark.AsString(mod["out"])
	if text != "one" {
		t.Fatalf("greet %q", text)
	}
}

func TestLoadPluginsRollback(t *testing.T) {
	root := pluginTestRoot(t)
	writeStarlarkPlugin(t, root, "aaa", "def greet(args):\n    return \"one\"\nsys[\"register_command\"](\"greet\", greet)\n")
	writeStarlarkPlugin(t, root, "zzz", "fail(\"boom\")\n")
	env := execEnv(t, allowAllEngine(t), false)
	_, err := evalExec(t, env, `sys["load_plugins"](all=True)`)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error %v", err)
	}
	commands := env["__custom_commands__"].(*starlark.Dict)
	_, found, getErr := commands.Get(starlark.String("greet"))
	if getErr != nil || found {
		t.Fatal("rollback left greet registered")
	}
}

func TestLoadPluginsPolicyDenyLoadsNothing(t *testing.T) {
	root := pluginTestRoot(t)
	writeStarlarkPlugin(t, root, "hello", "def greet(args):\n    return \"one\"\nsys[\"register_command\"](\"greet\", greet)\n")
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
allow { input.command != "starlark.sys.load_plugins" }
deny_reason = "load_plugins denied" { input.command == "starlark.sys.load_plugins" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	env := execEnv(t, eng, false)
	_, err = evalExec(t, env, `sys["load_plugins"](names=["hello"])`)
	if err == nil || !strings.Contains(err.Error(), "load_plugins denied") {
		t.Fatalf("error %v", err)
	}
	if strings.Contains(err.Error(), "permission") {
		t.Fatalf("policy denial opened the directory: %v", err)
	}
	if _, ok := env["greet"]; ok {
		t.Fatal("denied load registered greet")
	}
}

func TestSetupExtensionsDoesNotAutoloadPlugins(t *testing.T) {
	root := pluginTestRoot(t)
	writeStarlarkPlugin(t, root, "hello", "def greet(args):\n    return \"one\"\nsys[\"register_command\"](\"greet\", greet)\n")
	env := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: env})
	if _, ok := env["greet"]; ok {
		t.Fatal("startup defined greet")
	}
	plugins := env["plugins"].(*starlark.Dict)
	_, found, err := plugins.Get(starlark.String("hello"))
	if err != nil || found {
		t.Fatal("startup recorded hello")
	}
	if _, ok := env["__completers__"]; ok {
		t.Fatal("startup created __completers__")
	}
}

func TestRestrictedModeDoesNotExposeLoadPlugins(t *testing.T) {
	t.Setenv("ADSSH_PLUGIN_DIR", t.TempDir())
	globals := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: globals, Restricted: true})
	sysValue, ok := globals["sys"].(*starlark.Dict)
	if !ok {
		t.Fatalf("sys is %T", globals["sys"])
	}
	for _, name := range []string{"load_plugins", "load_plugin"} {
		if value, found, err := sysValue.Get(starlark.String(name)); err != nil || found {
			t.Fatalf("restricted sys.%s = (%v, %v, %v)", name, value, found, err)
		}
	}
}

func TestLoadPluginsCompleterRollsBack(t *testing.T) {
	t.Cleanup(func() {
		CompletersMu.Lock()
		delete(CustomCompleters, "greet")
		CompletersMu.Unlock()
	})
	root := pluginTestRoot(t)
	writeStarlarkPlugin(t, root, "hello", "def greet(args):\n    return \"one\"\nsys[\"register_completer\"](\"greet\", greet)\nfail(\"boom\")\n")
	env := execEnv(t, allowAllEngine(t), false)
	_, err := evalExec(t, env, `sys["load_plugins"](names=["hello"])`)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error %v", err)
	}
	if _, ok := env["__completers__"]; ok {
		t.Fatalf("completers survived: %v", env["__completers__"])
	}
	if fmt.Sprintf("%T", env["plugins"]) != "*starlark.Dict" {
		t.Fatal("plugins bag changed type")
	}
}
