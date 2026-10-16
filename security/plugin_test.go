package security

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

const (
	greetOne = "def greet(args):\n    return \"one\"\nsys[\"register_command\"](\"greet\", greet)\n"
	greetTwo = "def greet(args):\n    return \"two\"\nsys[\"register_command\"](\"greet\", greet)\n"
	starOK   = "# ok\n"
)

func usePluginRoot(t *testing.T) string {
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

func writePluginFiles(t *testing.T, root, name, manifest, star string, dirMode, fileMode os.FileMode) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugin.star"), []byte(star), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "manifest.yaml"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "plugin.star"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		t.Fatal(err)
	}
}

func writePlugin(t *testing.T, root, name, desc, star string) {
	t.Helper()
	manifest := "name: " + strconv.Quote(name) + "\n"
	if desc != "" {
		manifest += "description: " + strconv.Quote(desc) + "\n"
	}
	writePluginFiles(t, root, name, manifest, star, 0o700, 0o600)
}

func writeRawPlugin(t *testing.T, root, name, manifest, star string) {
	t.Helper()
	writePluginFiles(t, root, name, manifest, star, 0o700, 0o600)
}

func writeSized(t *testing.T, path, prefix string, size int64, mode os.FileMode) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if prefix != "" {
		if _, err := f.WriteString(prefix); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func testPluginGlobals(t *testing.T) starlark.StringDict {
	t.Helper()
	g := starlark.StringDict{}
	g["__custom_commands__"] = starlark.NewDict(4)
	g["plugins"] = starlark.NewDict(4)
	sysd := starlark.NewDict(2)
	if err := sysd.SetKey(starlark.String("register_command"), starlark.NewBuiltin("register_command", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		var callable starlark.Callable
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "callable", &callable); err != nil {
			return nil, err
		}
		dict, ok := g["__custom_commands__"].(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("register_command: __custom_commands__ is not a dict")
		}
		if err := dict.SetKey(starlark.String(name), callable); err != nil {
			return nil, err
		}
		return starlark.None, nil
	})); err != nil {
		t.Fatal(err)
	}
	if err := sysd.SetKey(starlark.String("register_completer"), starlark.NewBuiltin("register_completer", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var cmd string
		var callable starlark.Callable
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "cmd", &cmd, "callable", &callable); err != nil {
			return nil, err
		}
		dict, ok := g["__completers__"].(*starlark.Dict)
		if !ok {
			dict = starlark.NewDict(4)
			g["__completers__"] = dict
		}
		if err := dict.SetKey(starlark.String(cmd), callable); err != nil {
			return nil, err
		}
		return starlark.None, nil
	})); err != nil {
		t.Fatal(err)
	}
	g["sys"] = sysd
	return g
}

func sealRoot(t *testing.T, root string) {
	t.Helper()
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
}

func commandsDict(g starlark.StringDict) *starlark.Dict {
	d, _ := g["__custom_commands__"].(*starlark.Dict)
	return d
}

func dictHas(d *starlark.Dict, name string) bool {
	if d == nil {
		return false
	}
	_, found, err := d.Get(starlark.String(name))
	return err == nil && found
}

func callGreet(t *testing.T, g starlark.StringDict) string {
	t.Helper()
	fn, ok := g["greet"].(starlark.Callable)
	if !ok {
		t.Fatalf("greet is %T", g["greet"])
	}
	args := starlark.NewList([]starlark.Value{starlark.String("x")})
	v, err := starlark.Call(&starlark.Thread{Name: "call"}, fn, starlark.Tuple{args}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := starlark.AsString(v)
	if !ok {
		t.Fatalf("greet returned %v", v)
	}
	return s
}

func listStrings(t *testing.T, v starlark.Value) []string {
	t.Helper()
	lst, ok := v.(*starlark.List)
	if !ok {
		t.Fatalf("list is %T", v)
	}
	var out []string
	iter := lst.Iterate()
	defer iter.Done()
	var item starlark.Value
	for iter.Next(&item) {
		s, ok := starlark.AsString(item)
		if !ok {
			t.Fatalf("item %v", item)
		}
		out = append(out, s)
	}
	return out
}

func pluginRecord(t *testing.T, g starlark.StringDict, name string) (string, []string) {
	t.Helper()
	plugins, ok := g["plugins"].(*starlark.Dict)
	if !ok {
		t.Fatal("plugins is not a dict")
	}
	rec, found, err := plugins.Get(starlark.String(name))
	if err != nil || !found {
		t.Fatalf("plugins[%s]: found=%v err=%v", name, found, err)
	}
	d, ok := rec.(*starlark.Dict)
	if !ok {
		t.Fatalf("record is %T", rec)
	}
	descV, _, err := d.Get(starlark.String("description"))
	if err != nil {
		t.Fatal(err)
	}
	desc, _ := starlark.AsString(descV)
	exp, found, err := d.Get(starlark.String("exports"))
	if err != nil || !found {
		t.Fatalf("exports: found=%v err=%v", found, err)
	}
	return desc, listStrings(t, exp)
}

func mustSub(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %v, want substring %q", err, substr)
	}
}

func mustNotSub(t *testing.T, err error, substr string) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q contains %q", err.Error(), substr)
	}
}

func mustExact(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("error %v, want %q", err, want)
	}
}

func mustNotOpen(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	mustNotSub(t, err, "permission")
}

func runPlugin(t *testing.T, restricted bool, globals starlark.StringDict, args []string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, io.Discard),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return pluginBinary{}.Run(WithVBinSession(ctx, restricted, globals), args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("plugin-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	return out.String(), runErr
}

func TestPluginDefinedName(t *testing.T) {
	t.Setenv("ADSSH_PLUGIN_DIR", t.TempDir())
	for _, name := range []string{"for", "__hidden", "sys", "plugins"} {
		if pluginDefinedName(name) {
			t.Fatalf("%s was accepted", name)
		}
	}
	for _, name := range []string{"_private", "ok_name", "len", "assert"} {
		if !pluginDefinedName(name) {
			t.Fatalf("%s was rejected", name)
		}
	}
}

func TestValidPluginName(t *testing.T) {
	t.Setenv("ADSSH_PLUGIN_DIR", t.TempDir())
	if !validPluginName(strings.Repeat("a", 64)) || !validPluginName("-abc") {
		t.Fatal("valid names rejected")
	}
	for _, name := range []string{"", ".", "..", "foo/bar", `a\b`, "a b", "héllo", strings.Repeat("a", 65)} {
		if validPluginName(name) {
			t.Fatalf("%q was accepted", name)
		}
	}
}

func TestLoadStarlarkPluginsHappyPath(t *testing.T) {
	root := usePluginRoot(t)
	const star = "marker = 1\n" + greetOne
	writePluginFiles(t, root, "hello", "name: \"hello\"\ndescription: \"says hello\"\n", star, 0o755, 0o644)
	for _, path := range []string{filepath.Join(root, "hello"), filepath.Join(root, "hello", "manifest.yaml"), filepath.Join(root, "hello", "plugin.star")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		switch filepath.Base(path) {
		case "hello":
			if info.Mode().Perm() != 0o755 {
				t.Fatalf("dir mode %o", info.Mode().Perm())
			}
		default:
			if info.Mode().Perm() != 0o644 {
				t.Fatalf("%s mode %o", path, info.Mode().Perm())
			}
		}
	}
	g := testPluginGlobals(t)
	orig := commandsDict(g)
	loaded, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0] != "hello" {
		t.Fatalf("loaded %v", loaded)
	}
	if commandsDict(g) != orig {
		t.Fatal("commands dict replaced on success")
	}
	if !dictHas(commandsDict(g), "greet") {
		t.Fatal("greet was not registered")
	}
	if callGreet(t, g) != "one" {
		t.Fatalf("greet returned %q", callGreet(t, g))
	}
	desc, exports := pluginRecord(t, g, "hello")
	if desc != "says hello" || strings.Join(exports, ",") != "greet,marker" {
		t.Fatalf("record desc=%q exports=%v", desc, exports)
	}
}

func TestPluginShellLoadAndReload(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	root := usePluginRoot(t)
	writePluginFiles(t, root, "hello", "name: \"hello\"\ndescription: \"says hello\"\n", greetOne, 0o755, 0o644)
	g := testPluginGlobals(t)
	stdout, _, err, rec := runShell(t, false, g, "plugin load hello\n")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "loaded hello\n" {
		t.Fatalf("stdout %q", stdout)
	}
	for _, call := range rec.calls {
		if len(call) > 0 && call[0] == "plugin" {
			t.Fatalf("external exec %v", call)
		}
	}
	if callGreet(t, g) != "one" {
		t.Fatal(callGreet(t, g))
	}
	starPath := filepath.Join(root, "hello", "plugin.star")
	if err := os.WriteFile(starPath, []byte(greetTwo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(starPath, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, _, err, _ = runShell(t, false, g, "plugin reload hello\n")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "loaded hello\n" {
		t.Fatalf("reload stdout %q", stdout)
	}
	if callGreet(t, g) != "two" {
		t.Fatal(callGreet(t, g))
	}
}

func TestPluginLoadOrder(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "amy", "", "seen.append(\"amy\")\n")
	writePlugin(t, root, "zed", "", "seen.append(\"zed\")\n")
	g := testPluginGlobals(t)
	seen := starlark.NewList(nil)
	g["seen"] = seen
	if _, err := LoadStarlarkPlugins(g, []string{"zed", "amy"}, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(listStrings(t, seen), ","); got != "zed,amy" {
		t.Fatalf("named order %s", got)
	}
	g = testPluginGlobals(t)
	seen = starlark.NewList(nil)
	g["seen"] = seen
	if _, err := LoadStarlarkPlugins(g, nil, true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(listStrings(t, seen), ","); got != "amy,zed" {
		t.Fatalf("sorted order %s", got)
	}
}

func TestPluginPreflightBeforeExec(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "aaa", "says hello", "seen.append(\"good\")\n"+greetOne)
	writeRawPlugin(t, root, "zzz", "name: \"zzz\"\nSENTINELfield: 1\n", starOK)
	g := testPluginGlobals(t)
	seen := starlark.NewList(nil)
	g["seen"] = seen
	orig := commandsDict(g)
	_, err := LoadStarlarkPlugins(g, nil, true)
	mustSub(t, err, "unknown field")
	mustNotSub(t, err, "SENTINELfield")
	if seen.Len() != 0 || dictHas(commandsDict(g), "greet") || commandsDict(g) != orig {
		t.Fatalf("preflight mutated session: seen=%d greet=%v ptr=%v", seen.Len(), dictHas(commandsDict(g), "greet"), commandsDict(g) != orig)
	}
}

func TestPluginSyntaxErrorLoadsNeither(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "aaa", "says hello", "seen.append(\"good\")\n"+greetOne)
	writePlugin(t, root, "zzz", "says hello", "def (\n")
	g := testPluginGlobals(t)
	seen := starlark.NewList(nil)
	g["seen"] = seen
	_, err := LoadStarlarkPlugins(g, []string{"aaa", "zzz"}, false)
	mustExact(t, err, "plugin: syntax error")
	if seen.Len() != 0 || dictHas(commandsDict(g), "greet") {
		t.Fatal("syntax error loaded a plugin")
	}
	stdout, listErr := runPlugin(t, false, g, []string{"plugin", "list"})
	if listErr != nil {
		t.Fatal(listErr)
	}
	want := fmt.Sprintf("%-24s %s\n", "aaa", "says hello") + fmt.Sprintf("%-24s %s\n", "zzz", "says hello")
	if stdout != want {
		t.Fatalf("list %q", stdout)
	}
}

func TestPluginExecFailureRollsBack(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "aaa", "", "seen.append(\"good\")\n"+greetOne)
	writePlugin(t, root, "zzz", "", "fail(\"boom\")\n")
	g := testPluginGlobals(t)
	seen := starlark.NewList(nil)
	g["seen"] = seen
	orig := commandsDict(g)
	_, err := LoadStarlarkPlugins(g, nil, true)
	mustSub(t, err, "boom")
	if strings.Join(listStrings(t, seen), ",") != "good" {
		t.Fatalf("seen %v", listStrings(t, seen))
	}
	if commandsDict(g) == orig || dictHas(commandsDict(g), "greet") || !dictHas(orig, "greet") {
		t.Fatal("command registration was not restored")
	}
}

func TestPluginStepLimitRollsBack(t *testing.T) {
	root := usePluginRoot(t)
	star := greetOne + "def burn():\n    for i in range(200000):\n        pass\nburn()\n"
	writePlugin(t, root, "hello", "", star)
	g := testPluginGlobals(t)
	orig := commandsDict(g)
	_, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "too many steps")
	if commandsDict(g) == orig || dictHas(commandsDict(g), "greet") || !dictHas(orig, "greet") {
		t.Fatal("step limit left greet registered")
	}
}

func TestPluginCommitRollsBack(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "aaa", "", "marker = 1\n"+greetOne)
	writePlugin(t, root, "zzz", "", "marker = 2\n")
	g := testPluginGlobals(t)
	orig := commandsDict(g)
	_, err := LoadStarlarkPlugins(g, nil, true)
	mustSub(t, err, "already exists")
	if _, ok := g["marker"]; ok || dictHas(commandsDict(g), "greet") || commandsDict(g) == orig {
		t.Fatal("clash commit was not rolled back")
	}

	writePlugin(t, root, "hid", "", greetOne+"__hidden = 1\n")
	g = testPluginGlobals(t)
	_, err = LoadStarlarkPlugins(g, []string{"hid"}, false)
	mustSub(t, err, "cannot be defined")
	if dictHas(commandsDict(g), "greet") {
		t.Fatal("__hidden left greet registered")
	}

	writePlugin(t, root, "re", "", "sys = 1\n")
	g = testPluginGlobals(t)
	_, err = LoadStarlarkPlugins(g, []string{"re"}, false)
	mustSub(t, err, "cannot be defined")
	if _, ok := g["sys"].(*starlark.Dict); !ok {
		t.Fatal("sys was replaced")
	}
}

func TestPluginReloadRebindAndHide(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "", "marker = 1\n")
	g := testPluginGlobals(t)
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
	if g["marker"].String() != "1" {
		t.Fatalf("marker %s", g["marker"].String())
	}
	starPath := filepath.Join(root, "hello", "plugin.star")
	if err := os.WriteFile(starPath, []byte("marker = 2\nfail(\"boom\")\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "boom")
	if g["marker"].String() != "1" {
		t.Fatalf("restored marker %s", g["marker"].String())
	}

	if err := os.WriteFile(starPath, []byte("marker = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
	plugins := g["plugins"].(*starlark.Dict)
	rec, _, err := plugins.Get(starlark.String("hello"))
	if err != nil {
		t.Fatal(err)
	}
	exp, _, err := rec.(*starlark.Dict).Get(starlark.String("exports"))
	if err != nil {
		t.Fatal(err)
	}
	lst := exp.(*starlark.List)
	for _, name := range []string{"sys", "plugins", "__custom_commands__"} {
		if err := lst.Append(starlark.String(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(starPath, []byte("marker = 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := g["sys"].(*starlark.Dict); !ok {
		t.Fatal("sys hidden")
	}
	if _, ok := g["__custom_commands__"].(*starlark.Dict); !ok {
		t.Fatal("commands hidden")
	}
	if g["marker"].String() != "2" {
		t.Fatalf("marker %s", g["marker"].String())
	}

	g = testPluginGlobals(t)
	g["marker"] = starlark.MakeInt(1)
	writePlugin(t, root, "other", "", "marker = 2\n")
	_, err = LoadStarlarkPlugins(g, []string{"other"}, false)
	mustSub(t, err, "already exists")
	if g["marker"].String() != "1" {
		t.Fatalf("existing marker %s", g["marker"].String())
	}
}

func TestPluginBadExportsRestore(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "", starOK)
	g := testPluginGlobals(t)
	plugins := g["plugins"].(*starlark.Dict)
	rec := starlark.NewDict(1)
	if err := rec.SetKey(starlark.String("exports"), starlark.NewList([]starlark.Value{starlark.MakeInt(1)})); err != nil {
		t.Fatal(err)
	}
	if err := plugins.SetKey(starlark.String("hello"), rec); err != nil {
		t.Fatal(err)
	}
	orig := commandsDict(g)
	_, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "plugins record is not valid")
	if commandsDict(g) == orig || dictHas(commandsDict(g), "greet") || dictHas(orig, "greet") {
		t.Fatal("bad exports did not restore a clean clone")
	}
}

func TestPluginCompleterRollsBack(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "", "def greet(args):\n    return \"one\"\nsys[\"register_completer\"](\"greet\", greet)\nfail(\"boom\")\n")
	g := testPluginGlobals(t)
	_, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "boom")
	if _, ok := g["__completers__"]; ok {
		t.Fatal("completers dict survived a failed load")
	}
}

// The process-global completer map is restored through the installed hook on
// a failed load, and left alone on a good one.
func TestPluginCompleterRollbackRestoresGlobal(t *testing.T) {
	globalCompleterMu.Lock()
	prev := globalCompleterSnapshot
	globalCompleterMu.Unlock()
	t.Cleanup(func() { SetGlobalCompleterSnapshot(prev) })
	snapshots, restores := 0, 0
	SetGlobalCompleterSnapshot(func() func() {
		snapshots++
		return func() { restores++ }
	})

	root := usePluginRoot(t)
	writePlugin(t, root, "bad", "", "fail(\"boom\")\n")
	writePlugin(t, root, "good", "", greetOne)
	g := testPluginGlobals(t)
	_, err := LoadStarlarkPlugins(g, []string{"bad"}, false)
	mustSub(t, err, "boom")
	if snapshots != 1 || restores != 1 {
		t.Fatalf("failed load: snapshots=%d restores=%d, want 1 and 1", snapshots, restores)
	}
	if _, err := LoadStarlarkPlugins(g, []string{"good"}, false); err != nil {
		t.Fatal(err)
	}
	if snapshots != 2 || restores != 1 {
		t.Fatalf("good load: snapshots=%d restores=%d, want 2 and 1", snapshots, restores)
	}
}

func TestPluginArgumentChecksDoNotOpen(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "", greetOne)
	sealRoot(t, root)
	g := testPluginGlobals(t)

	_, err := LoadStarlarkPlugins(g, nil, false)
	mustExact(t, err, "plugin: pass names or all=True")
	mustNotSub(t, err, "not both")
	mustNotOpen(t, err)

	_, err = LoadStarlarkPlugins(nil, nil, false)
	mustExact(t, err, "plugin: pass names or all=True")
	mustNotSub(t, err, "not both")

	_, err = LoadStarlarkPlugins(nil, []string{"../x"}, true)
	mustExact(t, err, "plugin: pass names or all, not both")
	mustNotSub(t, err, "invalid name")
	mustNotOpen(t, err)

	_, err = LoadStarlarkPlugins(nil, []string{"../x"}, false)
	mustExact(t, err, "plugin: invalid name")
	mustNotOpen(t, err)

	_, err = LoadStarlarkPlugins(nil, []string{"hello"}, false)
	mustExact(t, err, "plugin: session is not available")
	mustNotOpen(t, err)

	_, err = LoadStarlarkPlugins(nil, nil, true)
	mustExact(t, err, "plugin: session is not available")
	mustNotOpen(t, err)

	_, err = LoadStarlarkPlugins(g, []string{""}, false)
	mustExact(t, err, "plugin: invalid name")
	mustNotOpen(t, err)

	if dictHas(commandsDict(g), "greet") {
		t.Fatal("argument check registered greet")
	}
}

func TestPluginNamesRejectedBeforeOpen(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "", greetOne)
	sealRoot(t, root)
	g := testPluginGlobals(t)

	names := make([]string, 0, 65)
	for i := 0; i <= 64; i++ {
		names = append(names, fmt.Sprintf("n%02d", i))
	}
	_, err := LoadStarlarkPlugins(g, names, false)
	mustExact(t, err, "plugin: too many names")
	mustNotOpen(t, err)

	names[64] = "../x"
	_, err = LoadStarlarkPlugins(g, names, false)
	mustExact(t, err, "plugin: invalid name")
	mustNotSub(t, err, "too many")
	mustNotOpen(t, err)

	dup := make([]string, 0, 65)
	for i := 0; i < 64; i++ {
		dup = append(dup, fmt.Sprintf("p%02d", i))
	}
	dup = append(dup, dup[0])
	_, err = LoadStarlarkPlugins(g, dup, false)
	mustSub(t, err, "already exists")
	mustNotSub(t, err, "too many")
	mustNotOpen(t, err)

	_, err = LoadStarlarkPlugins(g, []string{"../x", "hello", "hello"}, false)
	mustExact(t, err, "plugin: invalid name")
	mustNotSub(t, err, "already exists")

	for _, name := range []string{"../x", "foo/bar", "/tmp/x", "..", ".", "a b", "a\x00b", `a\b`, strings.Repeat("a", 65), "héllo"} {
		_, err = LoadStarlarkPlugins(g, []string{name}, false)
		mustExact(t, err, "plugin: invalid name")
		mustNotOpen(t, err)
	}
	if dictHas(commandsDict(g), "greet") {
		t.Fatal("rejected names registered greet")
	}
}

func TestPluginNameNotFoundAndCharset(t *testing.T) {
	usePluginRoot(t)
	g := testPluginGlobals(t)
	_, err := LoadStarlarkPlugins(g, []string{strings.Repeat("a", 64)}, false)
	mustSub(t, err, "not found")
	mustNotSub(t, err, "invalid name")
	_, err = LoadStarlarkPlugins(g, []string{"-abc"}, false)
	mustSub(t, err, "not found")
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("ADSSH_PLUGIN_DIR", missing)
	_, err = LoadStarlarkPlugins(g, []string{"aaa", "bbb"}, false)
	mustExact(t, err, "plugin: aaa not found")
	loaded, err := LoadStarlarkPlugins(g, nil, true)
	if err != nil || len(loaded) != 0 {
		t.Fatalf("missing --all loaded=%v err=%v", loaded, err)
	}
}

func TestPluginRecordRejectedBeforeOpen(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "", greetOne)
	sealRoot(t, root)

	g := testPluginGlobals(t)
	g["plugins"] = starlark.String("no")
	orig := commandsDict(g)
	_, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: plugins record is not valid")
	mustNotOpen(t, err)
	if commandsDict(g) != orig {
		t.Fatal("record check replaced commands")
	}

	g = testPluginGlobals(t)
	g["__completers__"] = starlark.String("no")
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: plugins record is not valid")
	mustNotOpen(t, err)

	g = testPluginGlobals(t)
	rec := starlark.NewDict(1)
	if err := rec.SetKey(starlark.String("exports"), starlark.None); err != nil {
		t.Fatal(err)
	}
	if err := g["plugins"].(*starlark.Dict).SetKey(starlark.String("hello"), rec); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: plugins record is not valid")
	mustNotOpen(t, err)

	g = testPluginGlobals(t)
	if err := g["plugins"].(*starlark.Dict).SetKey(starlark.String("hello"), starlark.String("no")); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: plugins record is not valid")
	mustNotOpen(t, err)
	if dictHas(commandsDict(g), "greet") {
		t.Fatal("bad record registered greet")
	}
}

func TestPluginManifestRejects(t *testing.T) {
	root := usePluginRoot(t)
	g := testPluginGlobals(t)
	cases := []struct {
		raw  string
		want string
	}{
		{"   \n\t", "plugin: manifest is not valid"},
		{"hello\n", "plugin: manifest is not valid"},
		{"- a\n", "plugin: manifest is not valid"},
		{"name: true\n", "plugin: name must be a string"},
		{"name: true\nname: true\n", "plugin: duplicate field"},
		{"description: hi\n", "plugin: manifest is not valid"},
		{"name: \"other\"\n", "plugin: name does not match directory"},
		{"name: \"\"\n", "plugin: name does not match directory"},
		{"name: \"hello\"\ndescription: null\n", "plugin: description must be a string"},
		{"name: \"hello\"\ndescription: ~\n", "plugin: description must be a string"},
		{"name: \"hello\"\nname: \"hello\"\n", "plugin: duplicate field"},
		{"name: \"hello\"\n---\nname: \"hello\"\n", "plugin: trailing document"},
		{"1: 2\nname: \"hello\"\n", "plugin: manifest is not valid"},
		{"name: \"hello\"\ndescription: \"a\\tb\"\n", "plugin: description contains a control character"},
	}
	for _, tc := range cases {
		writeRawPlugin(t, root, "hello", tc.raw, starOK)
		_, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
		mustExact(t, err, tc.want)
	}
	writeRawPlugin(t, root, "hello", "name: \"hello\"\nSENTINELfield: 1\n", starOK)
	_, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: unknown field")
	mustNotSub(t, err, "SENTINELfield")

	writeRawPlugin(t, root, "hello", "name: \"hello\"\n<<: {SENTINELfield: 1}\n", starOK)
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: unknown field")
	mustNotSub(t, err, "SENTINELfield")

	writeRawPlugin(t, root, "hello", "name: &a hello\ndescription: *a\n", starOK)
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: aliases are not allowed")

	writeRawPlugin(t, root, "hello", "base: &b {a: 1}\nname: hello\n<<: *b\n", starOK)
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: aliases are not allowed")

	long := strings.Repeat("a", 257)
	writeRawPlugin(t, root, "hello", "name: \"hello\"\ndescription: "+strconv.Quote(long)+"\n", starOK)
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: description is too large")

	writeRawPlugin(t, root, "hello", "name: \"hello\"\ndescription: "+strconv.Quote(long+"\t")+"\n", starOK)
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: description is too large")
	mustNotSub(t, err, "control character")

	writeRawPlugin(t, root, "hello", "name: \"hello\"\ndescription: "+strconv.Quote(strings.Repeat("a", 256))+"\n", starOK)
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
	desc, _ := pluginRecord(t, g, "hello")
	if desc != strings.Repeat("a", 256) {
		t.Fatalf("desc len %d", len(desc))
	}
}

func TestPluginManifestAccepts(t *testing.T) {
	root := usePluginRoot(t)
	g := testPluginGlobals(t)
	writeRawPlugin(t, root, "hello", "name: &n hello\n", starOK)
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
	desc, exports := pluginRecord(t, g, "hello")
	if desc != "" || len(exports) != 0 {
		t.Fatalf("anchor record desc=%q exports=%v", desc, exports)
	}

	writeRawPlugin(t, root, "hello", "name: hello\ndescription: yes\n", starOK)
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
	desc, _ = pluginRecord(t, g, "hello")
	if desc != "yes" {
		t.Fatalf("yes stored as %q", desc)
	}

	writeRawPlugin(t, root, "hello", "name: hello\ndescription: None\n", starOK)
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
	desc, _ = pluginRecord(t, g, "hello")
	if desc != "None" {
		t.Fatalf("None stored as %q", desc)
	}

	writeRawPlugin(t, root, "hello", "name: \"hello\"\ndescription: \"héllo\"\n", starOK)
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
	desc, _ = pluginRecord(t, g, "hello")
	if desc != "héllo" {
		t.Fatalf("utf8 stored as %q", desc)
	}

	writePlugin(t, root, "hello", "", starOK)
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
	desc, _ = pluginRecord(t, g, "hello")
	if desc != "" {
		t.Fatalf("empty desc %q", desc)
	}
}

func TestPluginFilesystemRejects(t *testing.T) {
	root := usePluginRoot(t)
	g := testPluginGlobals(t)
	writePlugin(t, root, "hello", "says hello", greetOne)

	manifest := filepath.Join(root, "hello", "manifest.yaml")
	star := filepath.Join(root, "hello", "plugin.star")
	writeSized(t, star, "def (\n", pluginSourceMax+1, 0o600)
	_, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "too large")
	mustNotSub(t, err, "syntax error")
	if dictHas(commandsDict(g), "greet") {
		t.Fatal("oversized star registered greet")
	}
	stdout, listErr := runPlugin(t, false, g, []string{"plugin", "list"})
	if listErr != nil || !strings.Contains(stdout, "too large") {
		t.Fatalf("list err=%v stdout=%q", listErr, stdout)
	}

	writePlugin(t, root, "hello", "says hello", greetOne)
	writeSized(t, manifest, "", pluginManifestMax+1, 0o600)
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "manifest.yaml is too large")

	writePlugin(t, root, "hello", "says hello", greetOne)
	writeSized(t, manifest, "", pluginManifestMax+1, 0o666)
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "group/world writable")
	mustNotSub(t, err, "too large")

	writePlugin(t, root, "hello", "says hello", greetOne)
	if err := os.Chmod(manifest, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "group/world writable")

	writePlugin(t, root, "hello", "says hello", greetOne)
	if err := os.Chmod(filepath.Join(root, "hello"), 0o777); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "group/world writable")

	if err := os.Chmod(filepath.Join(root, "hello"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "manifest.yaml not found")

	writePlugin(t, root, "hello", "says hello", greetOne)
	if err := os.Remove(star); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "plugin.star not found")

	writePlugin(t, root, "hello", "says hello", "def (\n")
	if err := os.WriteFile(filepath.Join(root, "hello", "secret-token"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: unexpected entry")
	mustNotSub(t, err, "secret-token")

	writePlugin(t, root, "hello", "says hello", starOK)
	if err := os.WriteFile(filepath.Join(root, "hello", "secret.star"), []byte(starOK), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: unexpected entry")
	mustNotSub(t, err, "secret.star")

	writePlugin(t, root, "hello", "says hello", starOK)
	if err := os.Remove(star); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(star, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "regular file")

	writePlugin(t, root, "hello", "says hello", greetOne)
	if err := os.WriteFile(filepath.Join(root, "hello", "payload.star"), []byte(greetOne), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(star); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("payload.star", star); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "symlink")
	mustNotSub(t, err, "unexpected entry")
	if dictHas(commandsDict(g), "greet") {
		t.Fatal("symlink star registered greet")
	}
}

func TestPluginSymlinkDirectoryAndRoot(t *testing.T) {
	root := usePluginRoot(t)
	outside := t.TempDir()
	writePlugin(t, outside, "hello", "says hello", greetOne)
	if err := os.Symlink(filepath.Join(outside, "hello"), filepath.Join(root, "hello")); err != nil {
		t.Fatal(err)
	}
	g := testPluginGlobals(t)
	_, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustSub(t, err, "symlink")
	if dictHas(commandsDict(g), "greet") {
		t.Fatal("directory symlink registered greet")
	}

	if err := os.Remove(filepath.Join(root, "hello")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "hello"), filepath.Join(root, ".link")); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, nil, true)
	mustSub(t, err, "unexpected entry")
	mustNotSub(t, err, "symlink")

	link := filepath.Join(t.TempDir(), "plugins")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_PLUGIN_DIR", link)
	_, err = LoadStarlarkPlugins(g, nil, true)
	mustExact(t, err, "plugin: root is a symlink")
	if dictHas(commandsDict(g), "greet") {
		t.Fatal("root symlink registered greet")
	}
}

func TestPluginRootShape(t *testing.T) {
	fileRoot := filepath.Join(t.TempDir(), "plugins")
	if err := os.WriteFile(fileRoot, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_PLUGIN_DIR", fileRoot)
	g := testPluginGlobals(t)
	_, err := LoadStarlarkPlugins(g, nil, true)
	mustExact(t, err, "plugin: root is not a directory")

	if err := os.Chmod(fileRoot, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, nil, true)
	mustExact(t, err, "plugin: root is group/world writable")

	root := usePluginRoot(t)
	if err := os.WriteFile(filepath.Join(root, "hello"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: unexpected entry")

	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
	mustExact(t, err, "plugin: root is group/world writable")

	sealRoot(t, root)
	if os.Geteuid() == 0 {
		// root reads a 0000 directory, so there is no permission error.
		return
	}
	err = pluginBinary{}.Run(WithVBinSession(context.Background(), false, nil), []string{"plugin", "list"})
	mustSub(t, err, "permission")
}

// A context without the shell's handler context is an error, not a panic.
// Seen as root, where the sealed root above is readable and the list ran on.
func TestPluginOutputWithoutShellContext(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "says hello", greetOne)
	mustExact(t, runPluginList(context.Background()), "plugin: no shell context")
	mustExact(t, printLoaded(context.Background(), []string{"hello"}), "plugin: no shell context")
	mustExact(t, pluginBinary{}.Run(WithVBinSession(context.Background(), false, nil), []string{"plugin", "list"}), "plugin: no shell context")
}

func TestPluginEntryLimit(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "says hello", greetOne)
	for i := 0; i < 64; i++ {
		path := filepath.Join(root, fmt.Sprintf("j%02d", i))
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g := testPluginGlobals(t)
	loaded, err := LoadStarlarkPlugins(g, []string{"hello"}, false)
	if err != nil || len(loaded) != 1 || !dictHas(commandsDict(g), "greet") {
		t.Fatalf("named load among 65: loaded=%v err=%v", loaded, err)
	}
	_, err = LoadStarlarkPlugins(g, nil, true)
	mustExact(t, err, "plugin: too many entries")
	mustNotSub(t, err, "unexpected entry")
	stdout, listErr := runPlugin(t, false, nil, []string{"plugin", "list"})
	if listErr == nil || stdout != "" || !strings.Contains(listErr.Error(), "too many entries") {
		t.Fatalf("list err=%v stdout=%q", listErr, stdout)
	}
}

func TestPluginSixtyFourAll(t *testing.T) {
	root := usePluginRoot(t)
	for i := 0; i < 64; i++ {
		writePlugin(t, root, fmt.Sprintf("p%02d", i), "", starOK)
	}
	g := testPluginGlobals(t)
	loaded, err := LoadStarlarkPlugins(g, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 64 {
		t.Fatalf("loaded %d", len(loaded))
	}
	for i, name := range loaded {
		want := fmt.Sprintf("p%02d", i)
		if name != want {
			t.Fatalf("loaded[%d]=%s", i, name)
		}
	}
}

func TestPluginListAndSessionEdges(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "says hello", greetOne)
	if err := os.WriteFile(filepath.Join(root, ".DS_Store"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, err := runPlugin(t, true, nil, []string{"plugin", "list"})
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%-24s ERROR: plugin: unexpected entry\n", ".DS_Store") + fmt.Sprintf("%-24s %s\n", "hello", "says hello")
	if stdout != want {
		t.Fatalf("list %q", stdout)
	}
	g := testPluginGlobals(t)
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
	if !dictHas(commandsDict(g), "greet") {
		t.Fatal("named load ignored a good plugin because of .DS_Store")
	}
	_, err = LoadStarlarkPlugins(g, nil, true)
	mustSub(t, err, "unexpected entry")
	if callGreet(t, g) != "one" {
		t.Fatal("failed --all rolled back an earlier load")
	}

	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_PLUGIN_DIR", empty)
	if err := (pluginBinary{}).Run(WithVBinSession(context.Background(), false, g), []string{"plugin", "list"}); err != nil {
		t.Fatal(err)
	}
	if err := (pluginBinary{}).Run(WithVBinSession(context.Background(), false, g), []string{"plugin", "load", "--all"}); err != nil {
		t.Fatal(err)
	}
}

func TestPluginRestrictedAndUsage(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "says hello", greetOne)
	sealRoot(t, root)
	g := testPluginGlobals(t)

	_, err := runPlugin(t, true, g, []string{"plugin", "load", "hello"})
	mustSub(t, err, "restricted")
	mustNotOpen(t, err)
	if dictHas(commandsDict(g), "greet") {
		t.Fatal("restricted load registered greet")
	}
	_, err = runPlugin(t, true, g, []string{"plugin", "load", "../x"})
	mustSub(t, err, "restricted")
	mustNotSub(t, err, "invalid name")
	mustNotOpen(t, err)

	for _, args := range [][]string{
		{"plugin"},
		{"plugin", "load", "a", "b"},
		{"plugin", "load", "--all", "NAME"},
		{"plugin", "load", "--all", "--all"},
		{"plugin", "load", "--nope"},
		{"plugin", "list", "extra"},
		{"plugin", "load", ""},
	} {
		_, err = runPlugin(t, false, g, args)
		mustSub(t, err, "usage")
		mustNotOpen(t, err)
	}

	err = pluginBinary{}.Run(context.Background(), []string{"plugin"})
	mustSub(t, err, "session is not available")
	mustNotSub(t, err, "usage")
	err = pluginBinary{}.Run(nil, []string{"plugin", "load", "hello"}) //nolint:staticcheck // SA1012: a nil context is the case under test.
	mustSub(t, err, "session is not available")
	mustNotOpen(t, err)
	err = pluginBinary{}.Run(context.Background(), []string{"plugin", "load", "hello"})
	mustSub(t, err, "session is not available")
	mustNotOpen(t, err)
	if dictHas(commandsDict(g), "greet") {
		t.Fatal("session-less load registered greet")
	}
}

func TestPluginSiblingDoesNotBlockNamedLoad(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "says hello", greetOne)
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := testPluginGlobals(t)
	stdout, err := runPlugin(t, false, g, []string{"plugin", "load", "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "loaded hello\n" || callGreet(t, g) != "one" {
		t.Fatalf("stdout %q greet failed", stdout)
	}
	_, err = LoadStarlarkPlugins(g, nil, true)
	mustSub(t, err, "unexpected entry")
}

// A root, plugin directory, or plugin file owned by another user is refused.
// The test cannot chown, so it swaps the ownership check for one that
// reports the named entry as foreign.
func TestPluginForeignOwnerRefused(t *testing.T) {
	cases := []struct {
		foreign string
		want    string
	}{
		{foreign: "root", want: "plugin: root is not owned by the current user"},
		{foreign: "hello", want: "plugin: hello is not owned by the current user"},
		{foreign: "manifest.yaml", want: "plugin: manifest.yaml is not owned by the current user"},
		{foreign: "plugin.star", want: "plugin: plugin.star is not owned by the current user"},
	}
	for _, tc := range cases {
		t.Run(tc.foreign, func(t *testing.T) {
			root := usePluginRoot(t)
			writePlugin(t, root, "hello", "", greetOne)
			prev := pluginOwned
			t.Cleanup(func() { pluginOwned = prev })
			rootInfo, err := os.Stat(root)
			if err != nil {
				t.Fatal(err)
			}
			pluginOwned = func(info os.FileInfo) bool {
				if tc.foreign == "root" {
					return !os.SameFile(info, rootInfo)
				}
				return info.Name() != tc.foreign
			}
			g := testPluginGlobals(t)
			_, err = LoadStarlarkPlugins(g, []string{"hello"}, false)
			mustExact(t, err, tc.want)
			if dictHas(commandsDict(g), "greet") {
				t.Fatal("foreign plugin registered greet")
			}
		})
	}
}

// The default ownership check accepts files the test process created.
func TestPluginOwnedByEUIDAccepted(t *testing.T) {
	root := usePluginRoot(t)
	writePlugin(t, root, "hello", "", greetOne)
	g := testPluginGlobals(t)
	if _, err := LoadStarlarkPlugins(g, []string{"hello"}, false); err != nil {
		t.Fatal(err)
	}
}
