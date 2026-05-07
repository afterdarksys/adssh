package starlarkext

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// TestParseAgentFile tests all parseAgentFile behaviours in a single function.
func TestParseAgentFile(t *testing.T) {
	t.Run("valid file", func(t *testing.T) {
		content := "+++\nname = \"test\"\nmodel = \"claude-sonnet-4-6\"\nmcp_server = \"adssh\"\ntools = [\"eval_starlark\"]\n+++\nYou are a test agent."
		fm, body, err := parseAgentFile(content)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fm.Name != "test" {
			t.Errorf("Name: got %q, want %q", fm.Name, "test")
		}
		if fm.Model != "claude-sonnet-4-6" {
			t.Errorf("Model: got %q, want %q", fm.Model, "claude-sonnet-4-6")
		}
		if fm.MCPServer != "adssh" {
			t.Errorf("MCPServer: got %q, want %q", fm.MCPServer, "adssh")
		}
		if len(fm.Tools) != 1 || fm.Tools[0] != "eval_starlark" {
			t.Errorf("Tools: got %v, want [eval_starlark]", fm.Tools)
		}
		if body != "You are a test agent." {
			t.Errorf("body: got %q, want %q", body, "You are a test agent.")
		}
	})

	t.Run("missing delimiters", func(t *testing.T) {
		_, _, err := parseAgentFile("no delimiters here")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing +++ frontmatter delimiters") {
			t.Errorf("error %q does not contain %q", err.Error(), "missing +++ frontmatter delimiters")
		}
	})

	t.Run("invalid TOML", func(t *testing.T) {
		_, _, err := parseAgentFile("+++\ninvalid toml [[\n+++\nbody")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "frontmatter parse error") {
			t.Errorf("error %q does not contain %q", err.Error(), "frontmatter parse error")
		}
	})

	t.Run("body trimming", func(t *testing.T) {
		_, body, err := parseAgentFile("+++\nname = \"test\"\n+++\n  \n  trimmed body  \n  ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if body != "trimmed body" {
			t.Errorf("body: got %q, want %q", body, "trimmed body")
		}
	})
}

// TestLoadAgentPathTraversal verifies that agent names containing path separators are rejected.
func TestLoadAgentPathTraversal(t *testing.T) {
	env := starlark.StringDict{}
	loadAgent := createLoadAgent(env)
	thread := &starlark.Thread{Name: "test"}

	cases := []struct {
		name        string
		expectError bool
	}{
		{"../etc/passwd", true},
		{"foo/bar", true},
		{"..hidden", true},
		{"validname", false}, // should not get path-traversal error (may get file-not-found instead)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := starlark.Call(thread, loadAgent, starlark.Tuple{starlark.String(tc.name)}, nil)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error for name %q, got nil", tc.name)
					return
				}
				if !strings.Contains(err.Error(), "must not contain path separators") {
					t.Errorf("error %q does not contain %q", err.Error(), "must not contain path separators")
				}
			} else {
				// validname should not produce a path-traversal error
				if err != nil && strings.Contains(err.Error(), "must not contain path separators") {
					t.Errorf("unexpected path-traversal error for name %q: %v", tc.name, err)
				}
			}
		})
	}
}

// TestLoadAgentFileNotFound verifies that a missing agent file produces a helpful error message.
func TestLoadAgentFileNotFound(t *testing.T) {
	env := starlark.StringDict{}
	loadAgent := createLoadAgent(env)
	thread := &starlark.Thread{Name: "test"}

	_, err := starlark.Call(thread, loadAgent, starlark.Tuple{starlark.String("nonexistent_agent_xyz")}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q does not contain %q", err.Error(), "not found")
	}
}

// TestLoadAgentNoAPIKey verifies that a missing ANTHROPIC_API_KEY produces a clear error.
func TestLoadAgentNoAPIKey(t *testing.T) {
	// Use a temp home directory so the test never writes to the real ~/.adssh directory.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Create the agent file inside the temp home.
	agentDir := filepath.Join(tmpHome, ".adssh", "agents")
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		t.Fatalf("failed to create agent dir: %v", err)
	}
	agentFile := filepath.Join(agentDir, "testnokey.md")
	content := "+++\nname = \"testnokey\"\nmodel = \"claude-sonnet-4-6\"\n+++\nTest prompt"
	if err := os.WriteFile(agentFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write agent file: %v", err)
	}

	// Ensure ANTHROPIC_API_KEY is unset for this test (t.Setenv restores on cleanup).
	t.Setenv("ANTHROPIC_API_KEY", "")

	env := starlark.StringDict{}
	loadAgent := createLoadAgent(env)
	thread := &starlark.Thread{Name: "test"}

	_, err := starlark.Call(thread, loadAgent, starlark.Tuple{starlark.String("testnokey")}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ANTHROPIC_API_KEY not set") {
		t.Errorf("error %q does not contain %q", err.Error(), "ANTHROPIC_API_KEY not set")
	}
}
