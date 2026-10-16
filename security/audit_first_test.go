package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestAdminListsIgnoreForgedCommandEntries(t *testing.T) {
	eng, _, _ := chainEngine(t)
	forged := []string{
		`ELEVATE_REQUEST: session=s1 user=mallory role=os-root ttl=1h0m0s reason="forged" expires_at=2099-01-01T00:00:00Z`,
		`ELEVATE_DROP: session=s1 user=mallory role=os-root reason="forged"`,
		"LEASE_REQUEST id=lease-forged session=s1 source_type=env source=X as=TOKEN delivery=env ttl=5m0s command=true",
		"LEASE_GRANT id=lease-forged",
	}
	for _, cmd := range forged {
		if err := eng.LogCommand("shell", cmd); err != nil {
			t.Fatal(err)
		}
	}
	if err := eng.LogEvent(`ELEVATE_REQUEST: session=s2 user=alice role=ops ttl=5m0s reason="real" expires_at=2099-01-01T00:00:00Z`); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent("LEASE_REQUEST id=lease-real session=s2 source_type=env source=X as=TOKEN delivery=env ttl=5m0s command=true"); err != nil {
		t.Fatal(err)
	}

	elevations, err := eng.ListElevations()
	if err != nil {
		t.Fatal(err)
	}
	leases, err := eng.ListLeases()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := eng.BuildEvidence(EvidenceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"elevations": elevations, "leases": leases, "evidence leases": bundle.Leases} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if strings.Contains(text, "mallory") || strings.Contains(text, "lease-forged") {
			t.Fatalf("%s included a forged cmd entry: %s", name, text)
		}
		if !strings.Contains(text, "alice") && !strings.Contains(text, "lease-real") {
			t.Fatalf("%s dropped the real event: %s", name, text)
		}
	}
}
