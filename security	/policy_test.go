package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// resetPolicy resets the package-level policy state between tests.
func resetPolicy() {
	policyMu.Lock()
	defer policyMu.Unlock()
	preparedQuery = nil
}

// Test 1: EvaluatePolicy returns (true, "", nil) when no policy is loaded
func TestEvaluatePolicy_NoPolicyLoaded(t *testing.T) {
	resetPolicy()
	allowed, reason, err := EvaluatePolicy(PolicyContext{
		User:      "alice",
		Groups:    []string{"staff"},
		Command:   "ls",
		Args:      []string{"-la"},
		Time:      "2026-05-06T00:00:00Z",
		SessionID: "test-session",
	})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !allowed {
		t.Errorf("expected allowed=true when no policy loaded, got false")
	}
	if reason != "" {
		t.Errorf("expected empty deny reason, got: %q", reason)
	}
}

// Test 2: LoadPolicy returns nil error when path does not exist (graceful degradation)
func TestLoadPolicy_FileNotExist(t *testing.T) {
	resetPolicy()
	err := LoadPolicy("/nonexistent/path/policy.rego")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
}

// Test 3: LoadPolicy with valid allow-all policy succeeds, EvaluatePolicy returns true
func TestLoadPolicy_AllowAll(t *testing.T) {
	resetPolicy()
	dir := t.TempDir()
	path := filepath.Join(dir, "allow_all.rego")
	policy := `package adssh.authz
default allow = true
default deny_reason = ""`
	if err := os.WriteFile(path, []byte(policy), 0644); err != nil {
		t.Fatal(err)
	}

	if err := LoadPolicy(path); err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	allowed, reason, err := EvaluatePolicy(PolicyContext{
		User:      "alice",
		Groups:    []string{"staff"},
		Command:   "ls",
		Args:      []string{},
		Time:      "2026-05-06T00:00:00Z",
		SessionID: "test-session",
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy error: %v", err)
	}
	if !allowed {
		t.Errorf("expected allowed=true, got false")
	}
	if reason != "" {
		t.Errorf("expected empty deny reason, got: %q", reason)
	}
}

// Test 4: LoadPolicy with deny policy returns allowed=false and deny_reason string
func TestLoadPolicy_DenyPolicy(t *testing.T) {
	resetPolicy()
	dir := t.TempDir()
	path := filepath.Join(dir, "deny.rego")
	policy := `package adssh.authz
default allow = false
deny_reason = "blocked by test" { input.command == "rm" }`
	if err := os.WriteFile(path, []byte(policy), 0644); err != nil {
		t.Fatal(err)
	}

	if err := LoadPolicy(path); err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	allowed, reason, err := EvaluatePolicy(PolicyContext{
		User:      "alice",
		Groups:    []string{"staff"},
		Command:   "rm",
		Args:      []string{"-rf", "/"},
		Time:      "2026-05-06T00:00:00Z",
		SessionID: "test-session",
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy error: %v", err)
	}
	if allowed {
		t.Errorf("expected allowed=false for deny policy, got true")
	}
	if reason != "blocked by test" {
		t.Errorf("expected deny_reason='blocked by test', got: %q", reason)
	}
}

// Test 5: PolicyContext struct marshals all 6 fields to JSON correctly
func TestPolicyContext_JSONMarshal(t *testing.T) {
	pctx := PolicyContext{
		User:      "bob",
		Groups:    []string{"ops", "dev"},
		Command:   "kubectl",
		Args:      []string{"get", "pods"},
		Time:      "2026-05-06T12:00:00Z",
		SessionID: "session-xyz",
	}

	data, err := json.Marshal(pctx)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	checks := map[string]interface{}{
		"user":       "bob",
		"command":    "kubectl",
		"time":       "2026-05-06T12:00:00Z",
		"session_id": "session-xyz",
	}
	for field, expected := range checks {
		if got := result[field]; got != expected {
			t.Errorf("field %q: expected %v, got %v", field, expected, got)
		}
	}

	groups, ok := result["groups"].([]interface{})
	if !ok || len(groups) != 2 {
		t.Errorf("expected groups to be array of 2, got: %v", result["groups"])
	}

	args, ok := result["args"].([]interface{})
	if !ok || len(args) != 2 {
		t.Errorf("expected args to be array of 2, got: %v", result["args"])
	}
}
