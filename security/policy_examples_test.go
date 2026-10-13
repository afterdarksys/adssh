package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyExamplesCompile(t *testing.T) {
	dir := filepath.Join("..", "policy", "examples")
	names := []string{"cert_principal.rego", "lease_bounds.rego", "agent-destructive.rego", "agent-session.rego"}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewEngine(EngineConfig{RequirePolicy: true, PolicySource: data}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
