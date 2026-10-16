//go:build ee

package security

import (
	"encoding/json"
	"strings"
	"testing"
)

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
