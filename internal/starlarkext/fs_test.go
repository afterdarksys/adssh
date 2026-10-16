package starlarkext

import (
	"os"
	"path/filepath"
	"testing"

	"go.starlark.net/starlark"
)

// callFS pulls one builtin out of the fs namespace built for the given
// restricted flag and calls it with the given args.
func callFS(t *testing.T, restricted bool, fn string, args starlark.Tuple) (starlark.Value, error) {
	t.Helper()
	env := starlark.StringDict{}
	SetupFilesystemAPI(env, restricted)
	fsVal, ok := env["fs"]
	if !ok {
		t.Fatal("fs namespace not registered")
	}
	d := fsVal.(*starlark.Dict)
	b, _, err := d.Get(starlark.String(fn))
	if err != nil || b == nil {
		t.Fatalf("fs.%s not found", fn)
	}
	return starlark.Call(&starlark.Thread{Name: "test"}, b.(*starlark.Builtin), args, nil)
}

func TestFSWriteThenReadBack(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.txt")
	if _, err := callFS(t, false, "write", starlark.Tuple{starlark.String(p), starlark.String("hello")}); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "hello" {
		t.Fatalf("read back = %q, %v; want %q", got, err, "hello")
	}
}

func TestFSWriteTruncatesAndAppendAdds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.txt")
	for _, step := range []struct{ fn, content string }{
		{"write", "aaa"},
		{"write", "b"}, // truncates
		{"append", "c"},
	} {
		if _, err := callFS(t, false, step.fn, starlark.Tuple{starlark.String(p), starlark.String(step.content)}); err != nil {
			t.Fatalf("fs.%s: %v", step.fn, err)
		}
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "bc" {
		t.Fatalf("got %q; want %q", got, "bc")
	}
}

func TestFSRefusedInRestrictedSession(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nope.txt")
	if _, err := callFS(t, true, "write", starlark.Tuple{starlark.String(p), starlark.String("x")}); err == nil {
		t.Fatal("expected fs.write to be refused in restricted session")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("restricted fs.write must not create the file")
	}
	if _, err := callFS(t, true, "mkdir", starlark.Tuple{starlark.String(filepath.Join(t.TempDir(), "d"))}); err == nil {
		t.Fatal("expected fs.mkdir to be refused in restricted session")
	}
}

func TestFSWriteRejectsOversizeContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.txt")
	big := make([]byte, maxWriteBytes+1)
	if _, err := callFS(t, false, "write", starlark.Tuple{starlark.String(p), starlark.String(big)}); err == nil {
		t.Fatal("expected oversize content to be rejected")
	}
}

func TestFSMkdirCreatesParents(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a", "b", "c")
	if _, err := callFS(t, false, "mkdir", starlark.Tuple{starlark.String(p)}); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
		t.Fatalf("mkdir did not create %q: %v", p, err)
	}
}
