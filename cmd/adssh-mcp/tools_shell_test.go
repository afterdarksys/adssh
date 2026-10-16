package main

import (
	"context"
	"testing"

	"github.com/afterdarksys/adssh/security"
	"github.com/mark3labs/mcp-go/mcp"
	"go.starlark.net/starlark"
)

func shellRequest(command string) mcp.CallToolRequest {
	return mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name:      "run_shell",
		Arguments: map[string]any{"command": command},
	}}
}

func TestRunShellHonorsRestrictedMode(t *testing.T) {
	result, err := handleRunShell(starlark.StringDict{}, true)(context.Background(), shellRequest("/usr/bin/true"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("restricted MCP shell allowed an absolute command path")
	}
}

func TestRunShellHonorsRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := handleRunShell(starlark.StringDict{}, false)(ctx, shellRequest("printf should-not-run"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("canceled MCP shell request still executed")
	}
}

// run_shell gates under the session bound when the handler was built, not a
// later SESSION_ID global.
func TestRunShellUsesBoundSessionID(t *testing.T) {
	var ids []string
	security.SetRemoteGate(func(_ bool, _ []string, id string) error {
		ids = append(ids, id)
		return nil
	})
	t.Cleanup(func() { security.SetRemoteGate(nil) })
	globals := starlark.StringDict{"SESSION_ID": starlark.String("mcp-real")}
	handler := handleRunShell(globals, false)
	globals["SESSION_ID"] = starlark.String("bob-session")
	result, err := handler(context.Background(), shellRequest("true"))
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("run_shell error: %+v", result.Content)
	}
	if len(ids) == 0 {
		t.Fatal("gate not called")
	}
	for _, id := range ids {
		if id != "mcp-real" {
			t.Fatalf("gate ids = %v", ids)
		}
	}
}
