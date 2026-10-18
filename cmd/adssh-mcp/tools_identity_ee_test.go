//go:build ee

package main

import (
	"context"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/engine"
	"github.com/mark3labs/mcp-go/mcp"
)

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
