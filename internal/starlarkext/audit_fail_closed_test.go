package starlarkext

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
)

// brokenDefaultEngine installs a default engine whose chain ledger is a
// directory, so every audit write through the package shims fails.
func brokenDefaultEngine(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	chain := filepath.Join(dir, "chain")
	eng, err := security.NewEngine(security.EngineConfig{ChainPath: chain, ChainKeyPath: filepath.Join(dir, "key")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(chain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent("TEST_PROBE"); err == nil {
		t.Fatal("broken chain still accepted an event")
	}
	prev := security.DefaultEngine()
	security.SetDefaultEngine(eng)
	t.Cleanup(func() { security.SetDefaultEngine(prev) })
}

func TestFSWritesFailClosedWhenAuditFails(t *testing.T) {
	brokenDefaultEngine(t)
	dir := t.TempDir()
	for _, fn := range []string{"write", "append"} {
		p := filepath.Join(dir, fn+".txt")
		if _, err := callFS(t, false, fn, starlark.Tuple{starlark.String(p), starlark.String("x")}); err == nil {
			t.Fatalf("fs.%s succeeded with a failing audit sink", fn)
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("fs.%s created the file although the audit write failed: %v", fn, err)
		}
	}
	d := filepath.Join(dir, "sub")
	if _, err := callFS(t, false, "mkdir", starlark.Tuple{starlark.String(d)}); err == nil {
		t.Fatal("fs.mkdir succeeded with a failing audit sink")
	}
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		t.Fatalf("fs.mkdir created the directory although the audit write failed: %v", err)
	}
}

func TestSecAuditReportsAuditFailure(t *testing.T) {
	brokenDefaultEngine(t)
	env := starlark.StringDict{}
	SetupSecurityAPI(env, false)
	audit, _, err := env["sec"].(*starlark.Dict).Get(starlark.String("audit"))
	if err != nil || audit == nil {
		t.Fatal("sec.audit not registered")
	}
	if _, err := starlark.Call(&starlark.Thread{Name: "test"}, audit, starlark.Tuple{starlark.String("hello")}, nil); err == nil {
		t.Fatal("sec.audit returned success with a failing audit sink")
	}
}
