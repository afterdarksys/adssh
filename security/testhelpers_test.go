package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Chain and four-eyes helpers shared by core and enterprise tests.

// chainEngine returns an engine with a flat audit log and an HMAC chain, plus
// the chain path.
func chainEngine(t *testing.T) (*Engine, string, string) {
	t.Helper()
	dir := t.TempDir()
	chain := filepath.Join(dir, "chain")
	auditLog := filepath.Join(dir, "audit.log")
	eng, err := NewEngine(EngineConfig{
		AuditLogPath: auditLog,
		ChainPath:    chain,
		ChainKeyPath: filepath.Join(dir, "key"),
		FourEyesDir:  filepath.Join(dir, "foureyes"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.ensureFourEyesDirs(); err != nil {
		t.Fatal(err)
	}
	return eng, chain, auditLog
}

func seedPending(t *testing.T, eng *Engine, id, requester, approver string) string {
	t.Helper()
	data, err := json.Marshal(FourEyesPending{Token: "tok-" + id, RequestID: id, Requester: requester, Command: "rm -rf /srv", Rule: FourEyesRule{Approver: approver}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(eng.fourEyesPendingDir(), id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// breakChain makes every later chain append fail by replacing the ledger file
// with a directory.
func breakChain(t *testing.T, eng *Engine, chain string) {
	t.Helper()
	if err := eng.LogEvent("TEST_SEED"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(chain); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(chain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent("TEST_PROBE"); err == nil {
		t.Fatal("broken chain still accepted an event")
	}
}
