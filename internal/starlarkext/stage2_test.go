package starlarkext

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// governedEnv builds the full extension surface and wraps it with an allow-all
// security engine, matching real usage: scripts reach builtins through the
// govern wrapper. Module entries are called by subscript (str["split"](...),
// fs["exists"](...)) — the codebase convention, since a dict exposes its dict
// methods via .attr, not its keys. An engine with no policy is allow-by-default,
// so this exercises the govern path without denying anything.
func governedEnv(t *testing.T, restricted bool) starlark.StringDict {
	t.Helper()
	eng, err := security.NewEngine(security.EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	env := starlark.StringDict{}
	SetupExtensions(ExtensionOptions{Env: env, Restricted: restricted})
	GovernStarlarkGlobalsInPlace(eng, env)
	return env
}

func runScript(t *testing.T, src string) starlark.StringDict {
	t.Helper()
	env := governedEnv(t, false)
	globals, err := starlark.ExecFile(&starlark.Thread{Name: "test"}, "test.star", src, env)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	return globals
}

func TestStrModule(t *testing.T) {
	g := runScript(t, `
parts = str["split"]("a,b,c", ",")
joined = str["join"](parts, "-")
fields = str["fields"]("  x   y z ")
trimmed = str["trim"]("  hi  ")
has = str["has_prefix"]("hello", "he")
rep = str["replace"]("aaa", "a", "b", 2)
up = str["upper"]("go")
fmtd = str["sprintf"]("%s=%d", "n", 7)
`)
	assertStr(t, g, "joined", "a-b-c")
	assertStr(t, g, "trimmed", "hi")
	assertStr(t, g, "rep", "bba")
	assertStr(t, g, "up", "GO")
	assertStr(t, g, "fmtd", "n=7")
	if l := g["fields"].(*starlark.List); l.Len() != 3 {
		t.Fatalf("fields len = %d, want 3", l.Len())
	}
	if g["has"] != starlark.Bool(true) {
		t.Fatalf("has_prefix = %v, want True", g["has"])
	}
}

func TestReExtModule(t *testing.T) {
	g := runScript(t, `
first = re["find"]("[0-9]+", "abc123def456")
all = re["findall"]("[0-9]+", "a1b22c333")
repl = re["replace"]("[0-9]", "a1b2", "#")
segs = re["split"](",", "x,y,z")
grp = re["find"]("(\\w+)@(\\w+)", "user@host")
`)
	assertStr(t, g, "first", "123")
	assertStr(t, g, "repl", "a#b#")
	if l := g["all"].(*starlark.List); l.Len() != 3 {
		t.Fatalf("findall len = %d, want 3", l.Len())
	}
	if l := g["segs"].(*starlark.List); l.Len() != 3 {
		t.Fatalf("split len = %d, want 3", l.Len())
	}
	if l := g["grp"].(*starlark.List); l.Len() != 3 {
		t.Fatalf("find-with-groups len = %d, want 3", l.Len())
	}
}

func TestFsReadAndTests(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(fpath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "nope.txt")

	env := governedEnv(t, false)
	env["FPATH"] = starlark.String(fpath)
	env["MISSING"] = starlark.String(missing)
	env["DIR"] = starlark.String(dir)

	g, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `
exists = fs["exists"](FPATH)
missing_exists = fs["exists"](MISSING)
is_file = fs["is_file"](FPATH)
is_dir = fs["is_dir"](DIR)
content = fs["read"](FPATH)
size = fs["stat"](FPATH)["size"]
missing_stat = fs["stat"](MISSING)
`, env)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if g["exists"] != starlark.Bool(true) || g["missing_exists"] != starlark.Bool(false) {
		t.Fatalf("exists tests wrong: %v / %v", g["exists"], g["missing_exists"])
	}
	if g["is_file"] != starlark.Bool(true) || g["is_dir"] != starlark.Bool(true) {
		t.Fatalf("type tests wrong: %v / %v", g["is_file"], g["is_dir"])
	}
	assertStr(t, g, "content", "hello")
	if g["size"].(starlark.Int).String() != "5" {
		t.Fatalf("size = %v, want 5", g["size"])
	}
	if g["missing_stat"] != starlark.None {
		t.Fatalf("stat of missing = %v, want None", g["missing_stat"])
	}
}

func TestFsReadRefusedWhenRestricted(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(fpath, []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := governedEnv(t, true)
	env["FPATH"] = starlark.String(fpath)

	// Content read must refuse in a restricted session.
	if _, err := starlark.ExecFile(&starlark.Thread{Name: "t"}, "t.star", `x = fs["read"](FPATH)`, env); err == nil {
		t.Fatalf("expected fs.read to refuse in restricted session")
	}
	// But a metadata test still works (no content disclosed).
	g, err := starlark.ExecFile(&starlark.Thread{Name: "t2"}, "t2.star", `x = fs["exists"](FPATH)`, env)
	if err != nil {
		t.Fatalf("fs.exists should work in restricted: %v", err)
	}
	if g["x"] != starlark.Bool(true) {
		t.Fatalf("fs.exists = %v, want True", g["x"])
	}
}

func assertStr(t *testing.T, g starlark.StringDict, name, want string) {
	t.Helper()
	got, ok := starlark.AsString(g[name])
	if !ok {
		t.Fatalf("%s is not a string: %v", name, g[name])
	}
	if got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}
