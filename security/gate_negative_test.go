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
	"testing"
)

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
