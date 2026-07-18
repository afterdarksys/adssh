package main

import (
	"bufio"
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
		if limit <= 0 {
			return mcp.NewToolResultError("limit must be greater than zero"), nil
		}
		if limit > 10000 {
			return mcp.NewToolResultError("limit must not exceed 10000"), nil
		}

		// Parse optional filter param
		filter := req.GetString("filter", "")

		file, err := os.Open(auditLogPath)
		if err != nil {
			if os.IsNotExist(err) {
				return mcp.NewToolResultText("(no audit log entries)"), nil
			}
			return mcp.NewToolResultError(fmt.Sprintf("cannot read audit log: %v", err)), nil
		}
		defer file.Close()

		// Keep only a bounded ring of matching lines instead of reading an
		// arbitrarily large audit file into memory.
		lines := make([]string, 0, limit)
		next := 0
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if filter != "" && !strings.Contains(line, filter) {
				continue
			}
			if len(lines) < limit {
				lines = append(lines, line)
				continue
			}
			lines[next] = line
			next = (next + 1) % limit
		}
		if err := scanner.Err(); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("cannot scan audit log: %v", err)), nil
		}
		if len(lines) == limit && next != 0 {
			ordered := make([]string, 0, limit)
			ordered = append(ordered, lines[next:]...)
			ordered = append(ordered, lines[:next]...)
			lines = ordered
		}

		security.LogCommand("MCP:audit_log", fmt.Sprintf("limit=%d filter=%q", limit, filter))
		return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
	}
}
