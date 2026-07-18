package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.starlark.net/starlark"
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

func TestPolicyGateEnforcesConfiguredEntitlements(t *testing.T) {
	user := security.BuildPolicyContext("", nil, "").User
	entitlements := filepath.Join(t.TempDir(), "entitlements.yaml")
	contents := fmt.Sprintf("users:\n  %q: [list_sessions]\n", user)
	if err := os.WriteFile(entitlements, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{EngineConfig: security.EngineConfig{
		PolicySource:     []byte("package adssh\nauthz := {\"allow\": true}"),
		EntitlementsPath: entitlements,
	}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := policyGate(eng, "container_exec", func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called = true
		return mcp.NewToolResultText("unexpected"), nil
	})
	result, err := handler(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("MCP tool absent from configured entitlements executed")
	}
	if !result.IsError || !strings.Contains(result.Content[0].(mcp.TextContent).Text, "entitlements") {
		t.Fatalf("entitlement denial was not surfaced: %#v", result)
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

func TestEvalStarlarkReauthorizesEachBuiltinOperation(t *testing.T) {
	eng, err := engine.New(engine.Config{EngineConfig: security.EngineConfig{PolicySource: []byte(`
package adssh
authz := {"allow": input.command == "eval_starlark"}
`)}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	danger := starlark.NewDict(1)
	if err := danger.SetKey(starlark.String("run"), starlark.NewBuiltin("run", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		called = true
		return starlark.None, nil
	})); err != nil {
		t.Fatal(err)
	}
	handler := policyGate(eng, "eval_starlark", handleEvalStarlark(starlark.StringDict{"danger": danger}))
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name:      "eval_starlark",
		Arguments: map[string]any{"code": `danger["run"]("payload")`},
	}}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("denied nested Starlark operation executed")
	}
	denial := result.Content[0].(mcp.TextContent).Text
	if !result.IsError || !strings.Contains(denial, "starlark.danger.run") {
		t.Fatalf("nested denial was not surfaced clearly: %#v", result)
	}
}

func TestEvalStarlarkCannotExtractUngovernedBuiltinThroughContainer(t *testing.T) {
	eng, err := engine.New(engine.Config{EngineConfig: security.EngineConfig{PolicySource: []byte(`
package adssh
default allow = false
allow = true { input.command == "eval_starlark" }
allow = true { input.command == "starlark.danger.items" }
authz := {"allow": allow}
`)}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	danger := starlark.NewDict(1)
	if err := danger.SetKey(starlark.String("run"), starlark.NewBuiltin("run", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		called = true
		return starlark.None, nil
	})); err != nil {
		t.Fatal(err)
	}
	handler := policyGate(eng, "eval_starlark", handleEvalStarlark(starlark.StringDict{"danger": danger}))
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name:      "eval_starlark",
		Arguments: map[string]any{"code": "entries = danger.items()\nentry = entries[0]\nfn = entry[1]\nfn()"},
	}}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("builtin extracted through a list/tuple bypassed operation policy")
	}
	denial := result.Content[0].(mcp.TextContent).Text
	if !result.IsError || !strings.Contains(denial, "starlark.danger.items") || !strings.Contains(denial, ".run") {
		t.Fatalf("container-extracted builtin was not denied: %#v", result)
	}
}

func TestEvalStarlarkAuthorizesBuiltinWithCanonicalArguments(t *testing.T) {
	eng, err := engine.New(engine.Config{EngineConfig: security.EngineConfig{PolicySource: []byte(`
package adssh
default allow = false
allow = true { input.command == "eval_starlark" }
allow = true {
    input.command == "starlark.danger.run"
    input.args == ["arg0=\"payload\""]
}
authz := {"allow": allow}
`)}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	danger := starlark.NewDict(1)
	if err := danger.SetKey(starlark.String("run"), starlark.NewBuiltin("run", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		called = true
		return starlark.None, nil
	})); err != nil {
		t.Fatal(err)
	}
	handler := policyGate(eng, "eval_starlark", handleEvalStarlark(starlark.StringDict{"danger": danger}))
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name:      "eval_starlark",
		Arguments: map[string]any{"code": `danger["run"]("payload")`},
	}}
	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || !called {
		t.Fatalf("authorized nested operation did not execute: %#v", result)
	}
}
