package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"github.com/mark3labs/mcp-go/mcp"
	"go.starlark.net/starlark"
)

// brokenDefaultEngine installs a default engine whose chain ledger is a
// directory, so every audit write through the package shims fails.
func brokenDefaultEngine(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	chain := filepath.Join(dir, "chain")
	eng, err := security.NewEngine(security.EngineConfig{ChainPath: chain, ChainKeyPath: filepath.Join(dir, "key")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(chain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogEvent("TEST_PROBE"); err == nil {
		t.Fatal("broken chain still accepted an event")
	}
	prev := security.DefaultEngine()
	security.SetDefaultEngine(eng)
	t.Cleanup(func() { security.SetDefaultEngine(prev) })
}

func markerBuiltin(called *bool) *starlark.Builtin {
	return starlark.NewBuiltin("run", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		*called = true
		return starlark.None, nil
	})
}

func callTool(t *testing.T, h func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error), name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := h(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: args}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestEvalStarlarkFailsClosedWhenAuditFails(t *testing.T) {
	brokenDefaultEngine(t)
	called := false
	h := handleEvalStarlark(starlark.StringDict{"run": markerBuiltin(&called)})
	if result := callTool(t, h, "eval_starlark", map[string]any{"code": "run()"}); !result.IsError {
		t.Fatal("eval_starlark succeeded with a failing audit sink")
	}
	if called {
		t.Fatal("Starlark ran although the audit write failed")
	}
}

func TestCloudQueryFailsClosedWhenAuditFails(t *testing.T) {
	brokenDefaultEngine(t)
	called := false
	ns := starlark.NewDict(1)
	if err := ns.SetKey(starlark.String("list"), markerBuiltin(&called)); err != nil {
		t.Fatal(err)
	}
	h := handleCloudQuery(starlark.StringDict{"aws": ns})
	if result := callTool(t, h, "cloud_query", map[string]any{"namespace": "aws", "function": "list"}); !result.IsError {
		t.Fatal("cloud_query succeeded with a failing audit sink")
	}
	if called {
		t.Fatal("cloud function ran although the audit write failed")
	}
}

func TestAuditLogToolFailsClosedWhenAuditFails(t *testing.T) {
	brokenDefaultEngine(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("secret-line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := callTool(t, handleAuditLog(path), "audit_log", map[string]any{})
	if !result.IsError {
		t.Fatal("audit_log succeeded with a failing audit sink")
	}
	if strings.Contains(result.Content[0].(mcp.TextContent).Text, "secret-line") {
		t.Fatal("audit_log disclosed entries although its own read was not recorded")
	}
}

func TestListSessionsFailsClosedWhenAuditFails(t *testing.T) {
	brokenDefaultEngine(t)
	if result := callTool(t, handleListSessions(), "list_sessions", map[string]any{}); !result.IsError {
		t.Fatal("list_sessions succeeded with a failing audit sink")
	}
}
