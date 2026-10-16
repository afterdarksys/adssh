package grid

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
)

// placeAliceFlight places a local flight as alice, a live gridops session.
func placeAliceFlight(t *testing.T, eng *security.Engine) string {
	t.Helper()
	alice := gridOpsSession(t)
	flightID := testID(t, "f")
	if _, err := runVBin(t, eng, alice.ID, []string{
		"flight", "place", "--id", flightID, "--agent", testID(t, "ag"),
		"--worktree", testID(t, "wt"), "--for", "10m",
	}); err != nil {
		t.Fatal(err)
	}
	return flightID
}

// Another user without a live gridops elevation can neither cancel, rehearse,
// nor read alice's flight, nor list agents, locally or over an SSH Run.
func TestFlightOfAnotherUserRequiresGridOps(t *testing.T) {
	withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	initTestGrid(t, testID(t, "grid"))
	flightID := placeAliceFlight(t, eng)
	bob := plainSession(t, "bob", "bob")

	for _, args := range [][]string{
		{"flight", "cancel", "--id", flightID},
		{"flight", "rehearse", "--id", flightID, "--", "repo"},
		{"flight", "status", "--id", flightID},
		{"agent", "status"},
	} {
		if _, err := runVBin(t, eng, bob.ID, args); err == nil || !strings.Contains(err.Error(), "requires an active gridops elevation") {
			t.Fatalf("%v by bob: %v", args, err)
		}
		var stdout, stderr bytes.Buffer
		code, err := eng.RunVBinForSession(context.Background(), bob.ID, args, nil, &stdout, &stderr)
		if code == 0 || (err == nil && !strings.Contains(stderr.String(), "gridops")) {
			t.Fatalf("%v by bob over Run: code=%d err=%v stderr=%q", args, code, err, stderr.String())
		}
		if strings.Contains(stdout.String(), flightID) {
			t.Fatalf("%v by bob over Run disclosed the flight: %q", args, stdout.String())
		}
	}
	status, err := procGrid.flightStatus(flightID, false)
	if err != nil || status.Status != "placed" {
		t.Fatalf("alice's flight changed: %+v %v", status, err)
	}
}

// A gridops elevation that has lapsed is not live.
func TestFlightCancelRefusesLapsedGridOps(t *testing.T) {
	withGrid(t)
	eng := policyEngine(t, allowAllPolicy)
	initTestGrid(t, testID(t, "grid"))
	flightID := placeAliceFlight(t, eng)
	carol := elevatedSession(t, "carol", "carol")
	carol.DropElevation()
	if _, err := runVBin(t, eng, carol.ID, []string{"flight", "cancel", "--id", flightID}); err == nil {
		t.Fatal("flight cancel accepted without a live gridops elevation")
	}
	if status, err := procGrid.flightStatus(flightID, false); err != nil || status.Status != "placed" {
		t.Fatalf("flight changed: %+v %v", status, err)
	}
}
