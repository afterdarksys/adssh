package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShippedPolicyExamplesCompile(t *testing.T) {
	paths := globPolicyFiles(t, filepath.Join("..", "policy", "examples", "*.rego"))
	paths = append(paths, globPolicyFiles(t, filepath.Join("..", "policy", "bundles", "*.rego"))...)
	if len(paths) == 0 {
		t.Fatal("no policy examples or bundles found")
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

func globPolicyFiles(t *testing.T, pattern string) []string {
	t.Helper()
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return paths
}
