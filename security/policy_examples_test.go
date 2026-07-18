package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShippedPolicyExamplesCompile(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "policy", "examples", "*.rego"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no policy examples found")
	}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewEngine(EngineConfig{PolicySource: source}); err != nil {
				t.Fatalf("shipped policy does not compile: %v", err)
			}
		})
	}
}
