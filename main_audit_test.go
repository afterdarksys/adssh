package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
)

func TestEvalOnceFailsClosedWhenAuditFails(t *testing.T) {
	dir := t.TempDir()
	chain := filepath.Join(dir, "chain")
	broken, err := security.NewEngine(security.EngineConfig{ChainPath: chain, ChainKeyPath: filepath.Join(dir, "key")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(chain, 0o700); err != nil {
		t.Fatal(err)
	}
	prev := security.DefaultEngine()
	security.SetDefaultEngine(broken)
	t.Cleanup(func() { security.SetDefaultEngine(prev) })

	sess, out, _ := flowSession(t, nil)
	if err := evalOnce(sess, "echo unaudited"); err == nil {
		t.Fatal("evalOnce ran with a failing audit sink")
	}
	if strings.Contains(out.String(), "unaudited") {
		t.Fatalf("command ran although the audit write failed: %q", out.String())
	}
}
