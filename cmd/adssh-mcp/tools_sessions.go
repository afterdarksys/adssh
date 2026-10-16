package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// handleListSessions returns active SSH session IDs as a JSON array.
// Calls sys.ListSessions() which reads from the global session registry.
func handleListSessions() server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := security.LogCommand("MCP:list_sessions", ""); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("audit log failed: %v", err)), nil
		}
		ids := sys.ListSessions()

		data, err := json.Marshal(ids)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal sessions"), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	}
}
