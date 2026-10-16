//go:build ee

package main

import (
	"context"
	"strings"

	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// The read-only admin_* MCP tools are part of the enterprise layer
// (ee/LICENSE). They register through enterpriseToolRegistrars, after
// registerGovernedAdminTools has already called ForbidFourEyesDecisions.
func init() {
	enterpriseToolRegistrars = append(enterpriseToolRegistrars, func(add toolAdder) {
		add(mcp.NewTool("admin_list_sessions",
			mcp.WithDescription("List sessions registered in this process. Does not provision a machine or open a shell."),
		), "admin_list_sessions", handleAdminListSessions())
		add(mcp.NewTool("admin_list_approvals",
			mcp.WithDescription("List pending four-eyes requests by public request id. The approval token is not included."),
		), "admin_list_approvals", handleAdminListApprovals())
		add(mcp.NewTool("admin_list_recordings",
			mcp.WithDescription("List regular JSONL recording files. Symlinks are skipped."),
		), "admin_list_recordings", handleAdminListRecordings())
		add(mcp.NewTool("admin_list_elevations",
			mcp.WithDescription("List elevation requests, drops, and active grants from the HMAC chain and this process. A missing chain fails closed."),
		), "admin_list_elevations", handleAdminListElevations())
		add(mcp.NewTool("admin_list_leases",
			mcp.WithDescription("List lease metadata from the HMAC chain. Command text and secret values are not included. A missing chain fails closed."),
		), "admin_list_leases", handleAdminListLeases())
		add(mcp.NewTool("admin_explain",
			mcp.WithDescription("Explain whether a command would be allowed. The command is split on whitespace and is not passed to a shell. Nothing is executed."),
			mcp.WithString("command", mcp.Required(), mcp.Description("Command and arguments separated by whitespace")),
		), "admin_explain", handleAdminExplain())
	})
}

func handleAdminListSessions() server.ToolHandlerFunc {
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if _, err := securityEngineFromMCP(ctx); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		infos := sys.ListSessionInfo()
		items := make([]sessionListItem, 0, len(infos))
		for _, info := range infos {
			principals := info.Principals
			if principals == nil {
				principals = []string{}
			}
			items = append(items, sessionListItem{
				ID:             info.ID,
				User:           info.User,
				Principals:     principals,
				CreatedAt:      info.CreatedAt,
				LastActive:     info.LastActive,
				CurrentCommand: info.CurrentCommand,
				Terminated:     info.Terminated,
				Recording:      info.Recording,
				Elevation:      info.Elevation,
			})
		}
		return mcpJSONResult(items)
	}
}

func handleAdminListApprovals() server.ToolHandlerFunc {
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		eng, err := securityEngineFromMCP(ctx)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		items, err := eng.ListApprovalsPublic()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if items == nil {
			items = []security.ApprovalPublic{}
		}
		return mcpJSONResult(items)
	}
}

func handleAdminListRecordings() server.ToolHandlerFunc {
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		eng, err := securityEngineFromMCP(ctx)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		items, err := eng.ListRecordings()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcpJSONResult(items)
	}
}

func handleAdminListElevations() server.ToolHandlerFunc {
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		eng, err := securityEngineFromMCP(ctx)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		items, err := eng.ListElevations()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcpJSONResult(items)
	}
}

func handleAdminListLeases() server.ToolHandlerFunc {
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		eng, err := securityEngineFromMCP(ctx)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		items, err := eng.ListLeases()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcpJSONResult(items)
	}
}

func handleAdminExplain() server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		eng, err := securityEngineFromMCP(ctx)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		command, _ := mcpStringArg(req, "command")
		explanation, err := eng.ExplainCommand(security.SessionIDFromContext(ctx), strings.Fields(command))
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcpJSONResult(explanation)
	}
}
