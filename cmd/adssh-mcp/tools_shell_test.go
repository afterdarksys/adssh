package main

import (
	"context"
	"testing"

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
