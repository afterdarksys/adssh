package grid

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/security"
)

// Importing internal/grid registers its binaries in the process registry,
// which is what main and adssh-mcp rely on through a blank import.
func TestGridPackageRegistersVBins(t *testing.T) {
	for _, name := range []string{"grid", "flight", "agent", "worktree", "repo"} {
		vb, ok := security.Lookup(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		if vb.Name() != name {
			t.Fatalf("%s registered as %s", name, vb.Name())
		}
	}
}

func TestNilGateRefusesEveryOperation(t *testing.T) {
	dir := withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	session := gridOpsSession(t)
	listenURL, tokenPath, certFile := serveGrid(t, testID(t, "grid"), eng)
	worktreeID := testID(t, "w")
	if _, err := procGrid.createWorktree(worktreeID); err != nil {
		t.Fatal(err)
	}

	SetGate(nil)
	t.Cleanup(func() { SetGate(defaultEngineGate{}) })

	for _, args := range [][]string{
		{"grid", "status"},
		{"grid", "init", "--token-out", filepath.Join(dir, "other-token")},
		{"grid", "drain"},
		{"grid", "serve", "--listen", "127.0.0.1:0", "--cert", certFile, "--key", certFile, "--token-file", tokenPath},
		{"flight", "place", "--id", testID(t, "f"), "--agent", testID(t, "a"), "--worktree", testID(t, "w2"), "--for", "1m"},
		{"flight", "rehearse", "--id", testID(t, "f"), "--", "repo"},
		{"flight", "cancel", "--id", testID(t, "f")},
		{"flight", "status", "--id", testID(t, "f")},
		{"agent", "status"},
		{"worktree", "create", "--id", testID(t, "w3")},
		{"worktree", "destroy", "--id", worktreeID},
		{"worktree", "checkout", "--id", worktreeID, "--from", dir, "--rev", strings.Repeat("a", 40)},
		{"repo", "cat", "--id", worktreeID, "--path", "x"},
	} {
		_, err := runVBin(t, eng, session.ID, args)
		if err == nil || !strings.Contains(err.Error(), errNoGate.Error()) {
			t.Fatalf("%v: err = %v", args, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "other-token")); !os.IsNotExist(err) {
		t.Fatal("grid init wrote a token with a nil gate")
	}
	if _, err := os.Lstat(filepath.Join(procGrid.currentScratchRoot(), worktreeID)); err != nil {
		t.Fatal("worktree destroy ran with a nil gate")
	}

	// A listener installed before SetGate(nil) refuses every action too.
	token := readToken(t, tokenPath)
	for _, action := range []string{"place", "rehearse", "cancel", "status"} {
		body, err := json.Marshal(flightWire{
			Action: action, FlightID: testID(t, "rf"), AgentID: testID(t, "ra"),
			WorktreeID: testID(t, "rw"), TTLSeconds: 60, Command: []string{"repo"},
		})
		if err != nil {
			t.Fatal(err)
		}
		status, text := postRaw(t, listenURL, certFile, token, body)
		if status != http.StatusForbidden || !strings.Contains(text, "policy_required") {
			t.Fatalf("%s: status=%d body=%q", action, status, text)
		}
	}

	// The internal entry points refuse a nil gate without the vbin layer.
	if _, err := procGrid.placeFlight(placeOpts{
		FlightID: testID(t, "pf"), AgentID: testID(t, "pa"), WorktreeID: testID(t, "pw"),
		TTL: time.Minute, User: "alice",
	}); err == nil || err.Error() != "policy_required" {
		t.Fatalf("place: err = %v", err)
	}
	if _, err := procGrid.rehearseFlight(nil, testID(t, "pf"), []string{"repo"}, false); err == nil || err.Error() != "policy_required" {
		t.Fatalf("rehearse: err = %v", err)
	}
	if _, err := postFlight(nil, flightClientOpts{
		Host: listenURL, CAFile: certFile, TokenFile: tokenPath, Action: "place",
	}); err == nil || err.Error() != "policy_required" {
		t.Fatalf("postFlight: err = %v", err)
	}
}

func TestFlightCASymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	certFile, _ := writeGridCert(t, dir)
	link := filepath.Join(dir, "ca-link.pem")
	if err := os.Symlink(certFile, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFlightCA(certFile); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFlightCA(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v", err)
	}
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, make([]byte, gridMaxCA+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFlightCA(big); err == nil || err.Error() != "flight: ca file is too large" {
		t.Fatalf("err = %v", err)
	}
}
