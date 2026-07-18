package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestExplainCommandReportsPolicyDenial(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh
authz := {"allow": false, "deny_reason": "production freeze"}
`)})
	if err != nil {
		t.Fatal(err)
	}
	sys.RegisterSession(&sys.Session{ID: "why-policy", User: "alice", Principals: []string{"ops"}})
	t.Cleanup(func() { sys.UnregisterSession("why-policy") })

	explanation, err := eng.ExplainCommand("why-policy", []string{"deploy", "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.Outcome != "denied" || explanation.User != "alice" {
		t.Fatalf("unexpected explanation: %#v", explanation)
	}
	if len(explanation.Stages) == 0 || explanation.Stages[0].Reason != "production freeze" {
		t.Fatalf("policy reason missing: %#v", explanation.Stages)
	}
}

func TestExplainCommandFindsFourEyesWithoutCreatingRequest(t *testing.T) {
	dir := t.TempDir()
	eng, err := NewEngine(EngineConfig{FourEyesDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.SaveFourEyesRules([]FourEyesRule{{Pattern: "deploy *", Approver: "bob", TTL: 60}}); err != nil {
		t.Fatal(err)
	}
	explanation, err := eng.ExplainCommand("", []string{"deploy", "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.Outcome != "approval_required" {
		t.Fatalf("outcome = %q, want approval_required", explanation.Outcome)
	}
	if _, err := os.Stat(filepath.Join(dir, "pending")); !os.IsNotExist(err) {
		t.Fatalf("dry-run explanation created pending approval state: %v", err)
	}
}
