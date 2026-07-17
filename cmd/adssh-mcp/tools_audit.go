package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/afterdarksys/adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// handleAuditLog returns a handler that reads recent audit log entries.
// Reads from the audit log file at auditLogPath (default ~/.adssh/audit.log).
// Accepts "limit" (default 50) and optional "filter" string parameters.
// Returns the last N lines, optionally filtered by substring match.
func handleAuditLog(auditLogPath string) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Parse limit param (default 50)
		limit := int(req.GetFloat("limit", 50))

		// Parse optional filter param
		filter := req.GetString("filter", "")

		data, err := os.ReadFile(auditLogPath)
		if err != nil {
			if os.IsNotExist(err) {
				return mcp.NewToolResultText("(no audit log entries)"), nil
			}
			return mcp.NewToolResultError(fmt.Sprintf("cannot read audit log: %v", err)), nil
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")

		// Apply filter if specified
		if filter != "" {
			var filtered []string
			for _, line := range lines {
				if strings.Contains(line, filter) {
					filtered = append(filtered, line)
				}
			}
			lines = filtered
		}

		// Tail to last `limit` entries
		if len(lines) > limit {
			lines = lines[len(lines)-limit:]
		}

		security.LogCommand("MCP:audit_log", fmt.Sprintf("limit=%d filter=%q", limit, filter))
		return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
	}
}
