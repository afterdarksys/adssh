package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
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
	for _, sub := range []string{"pending", "approved", "denied"} {
		if err := os.MkdirAll(filepath.Join(dir, "foureyes", sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return eng, chain, auditLog
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

func registerTestSession(t *testing.T, s *sys.Session) {
	t.Helper()
	if err := sys.RegisterSession(s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(s.ID) })
}

// setDefaultCMPatterns replaces the default engine's startup patterns for
// one test; the engine reads ADSSH_CM_PATTERNS only when it is built.
func setDefaultCMPatterns(t *testing.T, raw string) {
	t.Helper()
	defaultEngine.cmMu.Lock()
	prev := defaultEngine.cmDefaultPatterns
	defaultEngine.cmDefaultPatterns = parseCMPatterns(raw)
	defaultEngine.cmMu.Unlock()
	t.Cleanup(func() {
		defaultEngine.cmMu.Lock()
		defaultEngine.cmDefaultPatterns = prev
		defaultEngine.cmMu.Unlock()
	})
}

// writeFourEyesRules writes the four-eyes rules file the way 4eyes add does,
// without the enterprise code.
func writeFourEyesRules(t *testing.T, eng *Engine, rules ...FourEyesRule) {
	t.Helper()
	if err := os.MkdirAll(eng.fourEyesBaseDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eng.fourEyesRulesPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
