//go:build ee

package security

import (
	"os"
	"path/filepath"
	"testing"
)

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
