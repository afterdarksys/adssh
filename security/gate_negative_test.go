package security

// Threats:
//   This file proves the four-eyes dual-approval gate and the change-management
//   (CM) gate actually BLOCK execution when driven through the real interceptor
//   chain (not just via their unit helpers): a four-eyes-matched command times
//   out and never reaches exec; a CM-required command with no ticket (strict) or
//   an invalid/expired ticket is blocked before exec. It also gives the RBAC
//   IsAuthorized helper a negative/fail-closed test.
//
//   These run through the process-global defaultEngine via runShell. Four-eyes
//   tests sandbox HOME (t.Setenv) so ~/.adssh/foureyes is a temp dir; CM tests
//   isolate ADSSH_CM_* env (t.Setenv) and the active ticket (ClearActiveCMTicket
//   + t.Cleanup). resetPolicy keeps the policy stage allow-by-default so the gate
//   under test — not an incidental policy deny — is what blocks.
//
//   NOTE: IsAuthorized is exercised as a unit — it is NOT wired into the
//   interceptor chain in this codebase (only Rego policy gates exec; grep shows
//   IsAuthorized has no production caller), so it cannot be driven through
//   runShell. That wiring gap is called out in the report.
//
//   NOT covered here: the four-eyes IPC approve/deny happy path (foureyes_test.go)
//   and CM provider fetching (cm_test.go).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.starlark.net/starlark"
)

// E.1: a four-eyes rule matching the command blocks it through the interceptor
// (times out) and the command never reaches exec.
func TestGateNeg_FourEyes_BlocksThroughInterceptor(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	t.Setenv("HOME", t.TempDir())

	// TTL=1; RequestApproval's poll loop makes this ~2s wall-clock.
	if err := AddFourEyesRule("neg4eyes*", "", 1); err != nil {
		t.Fatalf("AddFourEyesRule: %v", err)
	}

	start := time.Now()
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "neg4eyes-cmd")
	elapsed := time.Since(start)

	if runErr == nil || !strings.Contains(runErr.Error(), "timed out") {
		t.Fatalf("expected four-eyes timeout error blocking the command, got: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("SECURITY: four-eyes-gated command reached exec instead of being blocked: %v", rec.calls)
	}
	if elapsed < time.Second {
		t.Errorf("four-eyes gate returned too fast (%v) — did it actually wait for approval?", elapsed)
	}
}

// E.2: CM strict mode + a CM-required pattern + no active ticket blocks the
// command through the interceptor.
func TestGateNeg_CMStrict_NoTicket_BlocksThroughInterceptor(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	ClearActiveCMTicket()
	t.Cleanup(ClearActiveCMTicket)

	t.Setenv("ADSSH_CM_STRICT", "1")
	t.Setenv("ADSSH_CM_PATTERNS", "negcmstrict*")

	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "negcmstrict-cmd")
	if runErr == nil || !strings.Contains(runErr.Error(), "requires an active change ticket") {
		t.Fatalf("expected CM strict block for missing ticket, got: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("SECURITY: CM-required command reached exec with no ticket in strict mode: %v", rec.calls)
	}
}

// E.3: a CM ticket in a non-approved state, and a ticket whose approval window
// has already closed, are both blocked through the interceptor.
func TestGateNeg_CMInvalidTicket_BlocksThroughInterceptor(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	t.Cleanup(ClearActiveCMTicket)

	t.Setenv("ADSSH_CM_PATTERNS", "negcmticket*")

	// Non-approved (open) ticket => blocked regardless of strict mode.
	SetActiveCMTicket(&CMTicket{ID: "CHG-OPEN", State: "open"}, "CHG-OPEN")
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "negcmticket-cmd")
	if runErr == nil || !strings.Contains(runErr.Error(), "not valid") {
		t.Fatalf("expected block for open-state ticket, got: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("SECURITY: command with an open (unapproved) CM ticket reached exec: %v", rec.calls)
	}

	// Approved but the end window is in the past => expired => blocked.
	SetActiveCMTicket(&CMTicket{
		ID:        "CHG-EXP",
		State:     "approved",
		EndWindow: time.Now().Add(-time.Hour),
	}, "CHG-EXP")
	_, _, runErr2, rec2 := runShell(t, false, starlark.StringDict{}, "negcmticket-cmd")
	if runErr2 == nil || !strings.Contains(runErr2.Error(), "not valid") {
		t.Fatalf("expected block for expired ticket window, got: %v", runErr2)
	}
	if len(rec2.calls) != 0 {
		t.Errorf("SECURITY: command with an expired CM ticket window reached exec: %v", rec2.calls)
	}
}

// writeNegEntitlements writes a RBAC entitlements yaml file and returns its path.
func writeNegEntitlements(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "entitlements.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// E.4: the RBAC IsAuthorized enforcement helper rejects unauthorized
// user/command combinations and fails closed when no entitlements are loaded.
//
// The production shell and MCP gates both invoke this enforcement helper; this
// test independently locks down its fail-closed default-deny posture.
func TestGateNeg_Entitlements_UnauthorizedRejected(t *testing.T) {
	path := writeNegEntitlements(t, `groups:
  ops:
    - kubectl
users:
  alice:
    - ls
`)
	eng, err := NewEngine(EngineConfig{EntitlementsPath: path})
	if err != nil {
		t.Fatalf("NewEngine with entitlements: %v", err)
	}

	if eng.IsAuthorized("mallory", nil, "rm") {
		t.Error("SECURITY: unknown user 'mallory' authorized for 'rm'")
	}
	if eng.IsAuthorized("alice", nil, "rm") {
		t.Error("SECURITY: 'alice' authorized for 'rm', which is not in her allow-list")
	}
	if eng.IsAuthorized("bob", []string{"ops"}, "rm") {
		t.Error("SECURITY: group 'ops' member authorized for 'rm', not in the group allow-list")
	}

	// Sanity: explicitly-granted combinations ARE authorized.
	if !eng.IsAuthorized("alice", nil, "ls") {
		t.Error("expected 'alice' to be authorized for 'ls'")
	}
	if !eng.IsAuthorized("bob", []string{"ops"}, "kubectl") {
		t.Error("expected 'ops' group member to be authorized for 'kubectl'")
	}

	// Fail-closed: an engine with no entitlements loaded default-denies.
	engEmpty, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if engEmpty.IsAuthorized("alice", []string{"ops"}, "ls") {
		t.Error("SECURITY: engine with no entitlements loaded did not fail closed (default-deny)")
	}
}
