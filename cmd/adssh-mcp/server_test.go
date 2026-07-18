package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestPolicyGateIncludesToolArguments(t *testing.T) {
	eng, err := engine.New(engine.Config{EngineConfig: security.EngineConfig{PolicySource: []byte(`
package adssh
authz := {"allow": true} {
    input.command == "run_shell"
    input.args == ["command=echo allowed"]
}
`)}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := policyGate(eng, "run_shell", server.ToolHandlerFunc(func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called = true
		return mcp.NewToolResultText("ok"), nil
	}))

	req := mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name:      "run_shell",
		Arguments: map[string]any{"command": "echo allowed"},
	}}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || !called {
		t.Fatal("policy could not authorize using the actual tool arguments")
	}
}

func TestSerializedHandlerPreventsConcurrentToolExecution(t *testing.T) {
	var mu sync.Mutex
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	handler := serializedHandler(&mu, func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		entered <- struct{}{}
		<-release
		return mcp.NewToolResultText("ok"), nil
	})

	done := make(chan struct{}, 2)
	go func() { _, _ = handler(context.Background(), mcp.CallToolRequest{}); done <- struct{}{} }()
	<-entered
	go func() { _, _ = handler(context.Background(), mcp.CallToolRequest{}); done <- struct{}{} }()

	select {
	case <-entered:
		t.Fatal("second tool call entered while the first held shared state")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-done
	<-done
}
