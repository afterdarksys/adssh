package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestMain(m *testing.M) {
	if os.Getenv("BE_MCP_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestAgentToolsFileMissingExits2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestAgentToolsFileMissingExits2$")
	cmd.Env = append(envWithout("BE_MCP_MAIN", "ADSSH_AGENT_TOOLS_FILE"),
		"BE_MCP_MAIN=1",
		"ADSSH_AGENT_TOOLS_FILE="+filepath.Join(t.TempDir(), "missing-tools"),
	)
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("missing tools file exit = %v", err)
	}
}

func TestSelectAgentToolsFileFlagOverridesEnv(t *testing.T) {
	if got := selectAgentToolsFile([]string{"adssh-mcp"}, "from-env"); got != "from-env" {
		t.Fatalf("env path = %q", got)
	}
	args := []string{"adssh-mcp", "--agent-tools-file", "/tmp/from-flag"}
	if got := selectAgentToolsFile(args, "from-env"); got != "/tmp/from-flag" {
		t.Fatalf("flag path = %q", got)
	}
	empty := []string{"adssh-mcp", "--agent-tools-file", ""}
	if got := selectAgentToolsFile(empty, "from-env"); got != "" {
		t.Fatalf("empty flag = %q", got)
	}
}

func TestLoadAgentToolsEmptyFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tools")
	if err := os.WriteFile(path, []byte("# comment\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadAgentTools(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.ToolsConfigured || len(loaded.Tools) != 0 {
		t.Fatalf("empty file = %#v", loaded)
	}
	if _, err := loadAgentTools(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing tools file was accepted")
	}
}

func TestPolicyGateEntitlementPrecedesDryRun(t *testing.T) {
	eng, err := engine.New(engine.Config{EngineConfig: security.EngineConfig{PolicySource: []byte("package adssh\nauthz := {\"allow\": true}")}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := policyGate(eng, "run_shell", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called = true
		return mcp.NewToolResultText("unexpected"), nil
	}, mcpAgentConfig{ID: "planner", RequireDryRun: true, ToolsConfigured: true, Tools: []string{}})
	result, err := handler(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name:      "run_shell",
		Arguments: map[string]any{"command": "kubectl delete pod web-0"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("unentitled tool handler ran")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !result.IsError || text != "agent: tool is not entitled" || strings.Contains(text, "dry_run") {
		t.Fatalf("entitlement denial = %#v", result)
	}
}

func TestPolicyGateBindsSessionAndIgnoresToolArguments(t *testing.T) {
	eng, err := engine.New(engine.Config{EngineConfig: security.EngineConfig{PolicySource: []byte(`
package adssh
default allow = false
allow {
    input.agent.id == "bound-agent"
    input.agent.session_id == "sess-1"
    input.agent.session_id != ""
    input.args[_] == "agent_id=other"
    input.args[_] == "session_id=other"
}
authz := {"allow": allow}
`)}})
	if err != nil {
		t.Fatal(err)
	}
	// prepareMCP registers the agent session; a named session that nothing
	// registered or bound is denied as identity unknown.
	if err := sys.RegisterSession(&sys.Session{ID: "sess-1", User: "bound-agent"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession("sess-1") })
	called := false
	var sawSession string
	handler := policyGate(eng, "admin_explain", func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called = true
		sawSession = security.SessionIDFromContext(ctx)
		args := policyArgs(req)
		if !containsArg(args, "agent_id=other") || !containsArg(args, "session_id=other") {
			return mcp.NewToolResultError("arguments dropped"), nil
		}
		return mcp.NewToolResultText("ok"), nil
	}, mcpAgentConfig{ID: "bound-agent", SessionID: "sess-1"})
	result, err := handler(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name: "admin_explain",
		Arguments: map[string]any{
			"command":    "ls",
			"agent_id":   "other",
			"session_id": "other",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || !called || sawSession != "sess-1" {
		t.Fatalf("session binding = called %v session %q result %#v", called, sawSession, result)
	}
}

func TestClassifyAdminTools(t *testing.T) {
	if classifyAgentRisk("admin_list_sessions", mcp.CallToolRequest{}) != "read" {
		t.Fatal("list sessions risk")
	}
	if classifyAgentRisk("admin_explain", mcp.CallToolRequest{}) != "read" {
		t.Fatal("explain risk")
	}
	if classifyAgentRisk("identity_status", mcp.CallToolRequest{}) != "read" {
		t.Fatal("identity status risk")
	}
	if classifyAgentRisk("admin_approve", mcp.CallToolRequest{}) != "unknown" {
		t.Fatal("removed approve tool still classified")
	}
	if classifyAgentRisk("identity_device_login", mcp.CallToolRequest{}) != "mutable" {
		t.Fatal("device login risk")
	}
}

func TestIdentityStatusOmitsTokenAndElevation(t *testing.T) {
	eng, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	session := &sys.Session{ID: "mcp-status", User: "bound-agent"}
	sys.RegisterSession(session)
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	session.ActivateElevation("ops", "ticket", time.Now().Add(time.Hour))
	ctx := context.WithValue(context.Background(), mcpSecurityEngineContextKey{}, eng.Security())
	ctx = security.WithSessionID(ctx, session.ID)
	result, err := handleIdentityStatus()(ctx, mcp.CallToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(mcp.TextContent).Text
	if result.IsError || strings.Contains(text, "token") || strings.Contains(text, "elevation") || !strings.Contains(text, `"principals":[]`) || !strings.Contains(text, `"session_id":"mcp-status"`) {
		t.Fatalf("identity status = %#v %s", result, text)
	}
}

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

func TestIdentityDeviceLoginRequiresSessionAndRejectsBadInterval(t *testing.T) {
	eng, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), mcpSecurityEngineContextKey{}, eng.Security())
	result, err := handleIdentityDeviceLogin()(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{
		Arguments: map[string]any{"url": "https://127.0.0.1/oauth", "username": "alice"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !result.IsError || text != "identity: requires an active registered session" {
		t.Fatalf("missing session = %s", text)
	}

	login, err := deviceLoginRequestFromTool(mcp.CallToolRequest{Params: mcp.CallToolParams{
		Arguments: map[string]any{"url": "https://example.com", "username": "alice", "interval": "0"},
	}})
	if err != nil || !login.IntervalSet || login.Interval != 0 || login.Timeout != 0 {
		t.Fatalf("string zero = %+v %v", login, err)
	}
	login, err = deviceLoginRequestFromTool(mcp.CallToolRequest{Params: mcp.CallToolParams{
		Arguments: map[string]any{"interval": float64(0), "timeout": "10s"},
	}})
	if err != nil || !login.IntervalSet || login.Interval != 0 || login.Timeout != 10*time.Second {
		t.Fatalf("numeric zero = %+v %v", login, err)
	}
	if _, err := deviceLoginRequestFromTool(mcp.CallToolRequest{Params: mcp.CallToolParams{
		Arguments: map[string]any{"interval": map[string]any{"url": "http://169.254.169.254"}},
	}}); err == nil {
		t.Fatal("map interval was accepted")
	}
	absent, err := deviceLoginRequestFromTool(mcp.CallToolRequest{Params: mcp.CallToolParams{
		Arguments: map[string]any{"url": "https://example.com", "username": "alice"},
	}})
	if err != nil || absent.IntervalSet {
		t.Fatalf("absent interval = %+v %v", absent, err)
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

func TestToolWithoutEngineFailsClosed(t *testing.T) {
	result, err := handleIdentityStatus()(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !result.IsError || text != "agent: security engine is not bound" {
		t.Fatalf("unbound engine = %s", text)
	}
}

func envWithout(keys ...string) []string {
	drop := map[string]struct{}{}
	for _, key := range keys {
		drop[key] = struct{}{}
	}
	var out []string
	for _, item := range os.Environ() {
		name, _, ok := strings.Cut(item, "=")
		if ok {
			if _, skip := drop[name]; skip {
				continue
			}
		}
		out = append(out, item)
	}
	return out
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func TestAdminToolsCannotApproveOrDeny(t *testing.T) {
	eng, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s := server.NewMCPServer("test", "0", server.WithToolCapabilities(false))
	registerGovernedAdminTools(s, &sync.Mutex{}, eng, mcpAgentConfig{})
	tools := s.ListTools()
	for _, name := range []string{"admin_approve", "admin_deny"} {
		if _, ok := tools[name]; ok {
			t.Fatalf("tool %s is still registered", name)
		}
	}
	if _, ok := tools["admin_list_approvals"]; !ok {
		t.Fatal("read-only approval list is missing")
	}
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
