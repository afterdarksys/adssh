package security

import (
	"strings"
	"testing"
)

func TestExplainUsesRequiredRoleFromPolicy(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
required_role := "ops"
`)})
	if err != nil {
		t.Fatal(err)
	}
	explanation, err := eng.ExplainCommand("", []string{"rm", "-rf", "/tmp/x"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.RequiredRole != "ops" || explanation.Outcome != "denied" {
		t.Fatalf("explanation = %#v", explanation)
	}
	joined := strings.Join(explanation.NextSteps, "\n")
	if !strings.Contains(joined, "elevate request ops --for 10m") {
		t.Fatalf("next steps = %#v", explanation.NextSteps)
	}

	meta, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
metadata := {"required_role": "netops"}
`)})
	if err != nil {
		t.Fatal(err)
	}
	explanation, err = meta.ExplainCommand("", []string{"lease"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.RequiredRole != "netops" {
		t.Fatalf("metadata role = %#v", explanation)
	}

	invalid, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
required_role := "ops; drop"
`)})
	if err != nil {
		t.Fatal(err)
	}
	explanation, err = invalid.ExplainCommand("", []string{"elevate"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.RequiredRole != "" || !strings.Contains(strings.Join(explanation.NextSteps, "\n"), "elevate request <role>") {
		t.Fatalf("invalid role was accepted: %#v", explanation)
	}
}
