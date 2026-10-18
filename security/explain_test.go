package security

import (
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
	if err := sys.RegisterSession(&sys.Session{ID: "why-policy", User: "alice", Principals: []string{"ops"}}); err != nil {
		t.Fatal(err)
	}
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
