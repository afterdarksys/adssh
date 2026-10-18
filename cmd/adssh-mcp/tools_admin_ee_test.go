//go:build ee

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestAdminListApprovalsOmitsToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pending := filepath.Join(home, ".adssh", "foureyes", "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	const token = "super-secret-approval-token"
	body := []byte(`{"token":"` + token + `","request_id":"abc123","command":"rm","requester":"alice","hostname":"h","timestamp":"t","rule":{"pattern":"rm *","approver":"bob","ttl":10}}`)
	if err := os.WriteFile(filepath.Join(pending, "abc123.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), mcpSecurityEngineContextKey{}, eng.Security())
	result, err := handleAdminListApprovals()(ctx, mcp.CallToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(mcp.TextContent).Text
	if result.IsError || strings.Contains(text, token) || strings.Contains(text, `"token"`) || !strings.Contains(text, "abc123") {
		t.Fatalf("approvals = %#v %s", result, text)
	}
}

func TestAdminExplainDoesNotExecute(t *testing.T) {
	eng, err := engine.New(engine.Config{EngineConfig: security.EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
required_role := "ops"
`)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), mcpSecurityEngineContextKey{}, eng.Security())
	result, err := handleAdminExplain()(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{
		Arguments: map[string]any{"command": "rm -rf /tmp/adssh-explain-test"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(mcp.TextContent).Text
	var explanation security.CommandExplanation
	if result.IsError || json.Unmarshal([]byte(text), &explanation) != nil || explanation.Outcome != "denied" || explanation.RequiredRole != "ops" {
		t.Fatalf("explain = %#v %s", result, text)
	}
}

// The enterprise build registers the read-only admin tools, and still none
// that can decide a four-eyes request.
func TestEnterpriseRegistersReadOnlyAdminTools(t *testing.T) {
	eng, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s := server.NewMCPServer("test", "0", server.WithToolCapabilities(false))
	registerGovernedAdminTools(s, &sync.Mutex{}, eng, mcpAgentConfig{})
	tools := s.ListTools()
	for _, name := range []string{"admin_list_sessions", "admin_list_approvals", "admin_list_recordings", "admin_list_elevations", "admin_list_leases", "admin_explain", "identity_status", "identity_device_login"} {
		if _, ok := tools[name]; !ok {
			t.Errorf("enterprise build lacks %s", name)
		}
	}
}

// The MCP process forbids four-eyes decisions (TestMain), so even the Go API
// cannot approve from inside it.
func TestMCPProcessCannotDecideFourEyes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pending"), 0o700); err != nil {
		t.Fatal(err)
	}
	pending := `{"request_id":"req-mcp","requester":"alice","rule":{"pattern":"*"}}`
	if err := os.WriteFile(filepath.Join(dir, "pending", "req-mcp.json"), []byte(pending), 0o600); err != nil {
		t.Fatal(err)
	}
	sec, err := security.NewEngine(security.EngineConfig{FourEyesDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.DecideRequest("req-mcp", "bob", security.FourEyesSurfaceShell, true); err == nil {
		t.Fatal("the MCP process decided a four-eyes request")
	}
	if _, err := os.Stat(filepath.Join(dir, "pending", "req-mcp.json")); err != nil {
		t.Fatalf("pending request changed: %v", err)
	}
}
