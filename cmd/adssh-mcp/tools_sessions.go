package main

import (
	"context"
	"encoding/json"

	"adssh/security"
	"adssh/sys"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// handleListSessions returns active SSH session IDs as a JSON array.
// Calls sys.ListSessions() which reads from the global session registry.
func handleListSessions() server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ids := sys.ListSessions()
		security.LogCommand("MCP:list_sessions", "")

		data, err := json.Marshal(ids)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal sessions"), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	}
}
