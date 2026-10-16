package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestElevateFailsWithoutMutatingWhenAuditFails(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	session := &sys.Session{ID: "audit-first-elevate", User: "alice"}
	registerTestSession(t, session)
	breakChain(t, eng, chain)
	if _, err := runElevateVBin(t, eng, session.ID, []string{"elevate", "request", "ops", "--for", "5m", "--reason", "INC-1"}); err == nil {
		t.Fatal("elevation granted with a failing audit sink")
	}
	if session.ActiveElevation() != nil {
		t.Fatal("elevation activated although the audit write failed")
	}
}

func TestLeaseFailsWithoutRunningWhenAuditFails(t *testing.T) {
	t.Setenv("ADSSH_LEASE_SOURCE", "super-secret")
	eng, chain, _ := chainEngine(t)
	breakChain(t, eng, chain)
	marker := filepath.Join(t.TempDir(), "ran")
	if _, err := runLeaseVBin(t, eng, []string{
		"lease", "--from", "env:ADSSH_LEASE_SOURCE", "--as", "TOKEN", "--", "/usr/bin/touch", marker,
	}); err == nil {
		t.Fatal("lease ran with a failing audit sink")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("leased command ran although the audit write failed: %v", err)
	}
}
