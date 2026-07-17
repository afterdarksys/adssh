package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// resetPolicy resets the default engine's policy state between tests.
// (Wave 2: policy state moved from package globals onto the Engine; this helper
// now resets defaultEngine's fields but its assertions are unchanged.)
func resetPolicy() {
	defaultEngine.policyMu.Lock()
	defer defaultEngine.policyMu.Unlock()
	defaultEngine.preparedQuery = nil
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

// Test 6: LoadPolicy with malformed Rego returns an error, and any
// previously-loaded policy remains active (LoadPolicy does not clear
// preparedQuery before compiling the new module).
func TestLoadPolicy_MalformedRego(t *testing.T) {
	resetPolicy()
	dir := t.TempDir()

	// First load a good deny-everything policy.
	goodPath := filepath.Join(dir, "good.rego")
	goodPolicy := `package adssh.authz
default allow = false
deny_reason = "blocked by good policy" { input.command == "rm" }`
	if err := os.WriteFile(goodPath, []byte(goodPolicy), 0644); err != nil {
		t.Fatal(err)
	}
	if err := LoadPolicy(goodPath); err != nil {
		t.Fatalf("LoadPolicy(good) failed: %v", err)
	}

	// Now attempt to load garbage Rego.
	badPath := filepath.Join(dir, "bad.rego")
	badPolicy := `this is not valid rego at all { { {`
	if err := os.WriteFile(badPath, []byte(badPolicy), 0644); err != nil {
		t.Fatal(err)
	}
	if err := LoadPolicy(badPath); err == nil {
		t.Fatal("expected LoadPolicy to return an error for malformed rego, got nil")
	}

	// The previously loaded (good) policy must still be active.
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
		t.Errorf("expected allowed=false (good policy still active after failed reload), got true")
	}
	if reason != "blocked by good policy" {
		t.Errorf("expected deny_reason from the still-active good policy, got: %q", reason)
	}
}

// Test 7: EvaluatePolicy's PolicyContext fields actually reach the Rego
// input document — allow is keyed on both input.user and input.groups.
func TestEvaluatePolicy_InputFieldsReachRego(t *testing.T) {
	resetPolicy()
	dir := t.TempDir()
	path := filepath.Join(dir, "fields.rego")
	policy := `package adssh.authz
default allow = false
allow { input.user == "alice"; input.groups[_] == "ops" }
deny_reason = "user/group mismatch" { not allow }`
	if err := os.WriteFile(path, []byte(policy), 0644); err != nil {
		t.Fatal(err)
	}
	if err := LoadPolicy(path); err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	// alice + ops -> allowed
	allowed, reason, err := EvaluatePolicy(PolicyContext{
		User:      "alice",
		Groups:    []string{"ops"},
		Command:   "kubectl",
		Args:      []string{"get", "pods"},
		Time:      "2026-05-06T00:00:00Z",
		SessionID: "test-session",
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy error: %v", err)
	}
	if !allowed {
		t.Errorf("expected allowed=true for user=alice groups=[ops], got false (reason=%q)", reason)
	}

	// bob (wrong user, same group) -> denied
	allowed, reason, err = EvaluatePolicy(PolicyContext{
		User:      "bob",
		Groups:    []string{"ops"},
		Command:   "kubectl",
		Args:      []string{"get", "pods"},
		Time:      "2026-05-06T00:00:00Z",
		SessionID: "test-session",
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy error: %v", err)
	}
	if allowed {
		t.Errorf("expected allowed=false for user=bob, got true")
	}
	if reason != "user/group mismatch" {
		t.Errorf("expected deny_reason='user/group mismatch', got: %q", reason)
	}
}

// Test 8: BuildPolicyContext with an empty sessionID falls back to the
// current OS user/groups (no session to look up), and stamps a
// RFC3339-parseable Time.
func TestBuildPolicyContext_Defaults(t *testing.T) {
	pctx := BuildPolicyContext("ls", []string{"-la"}, "")

	if pctx.User == "" {
		t.Error("expected User to be populated from the current OS user, got empty string")
	}
	if pctx.Command != "ls" {
		t.Errorf("expected Command=%q, got %q", "ls", pctx.Command)
	}
	if len(pctx.Args) != 1 || pctx.Args[0] != "-la" {
		t.Errorf("expected Args=[-la], got %v", pctx.Args)
	}
	if pctx.SessionID != "" {
		t.Errorf("expected SessionID to remain empty, got %q", pctx.SessionID)
	}
	if _, err := time.Parse(time.RFC3339, pctx.Time); err != nil {
		t.Errorf("expected Time to parse as RFC3339, got %q: %v", pctx.Time, err)
	}
}
