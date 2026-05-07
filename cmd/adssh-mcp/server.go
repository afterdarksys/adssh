package main

import (
	"context"
	"fmt"

	"adssh/config"
	"adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.starlark.net/starlark"
)

// serveMCP creates the MCP server, registers all tools, and starts stdio transport.
func serveMCP(cfg config.AppConfig, globals starlark.StringDict, apiKey string) error {
	s := server.NewMCPServer(
		"adssh-mcp",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	// Register eval_starlark tool
	s.AddTool(
		mcp.NewTool("eval_starlark",
			mcp.WithDescription("Execute a Starlark expression in the adssh environment. Returns output (print statements) and result value."),
			mcp.WithString("code",
				mcp.Required(),
				mcp.Description("Starlark code to evaluate"),
			),
		),
		policyGate("eval_starlark", handleEvalStarlark(globals)),
	)

	// Register run_shell tool
	s.AddTool(
		mcp.NewTool("run_shell",
			mcp.WithDescription("Execute a POSIX shell command. Returns exit_code, stdout, and stderr."),
			mcp.WithString("command",
				mcp.Required(),
				mcp.Description("Shell command to execute"),
			),
		),
		policyGate("run_shell", handleRunShell(globals)),
	)

	security.LogEvent("adssh-mcp serving on stdio")
	return server.ServeStdio(s)
}

// policyGate wraps a tool handler with Rego policy evaluation.
// Every tool invocation is evaluated before execution (MCP-08).
func policyGate(toolName string, handler server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		pctx := security.BuildPolicyContext(toolName, []string{}, "")
		allowed, reason, policyErr := security.EvaluatePolicy(pctx)
		if policyErr != nil {
			security.LogPolicyDecision(pctx.User, toolName, false, fmt.Sprintf("error: %v", policyErr))
			return mcp.NewToolResultError(fmt.Sprintf("policy evaluation error: %v", policyErr)), nil
		}
		if !allowed {
			security.LogPolicyDecision(pctx.User, toolName, false, reason)
			if reason != "" {
				return mcp.NewToolResultError(fmt.Sprintf("access denied: %s", reason)), nil
			}
			return mcp.NewToolResultError(fmt.Sprintf("access denied for '%s' by policy", toolName)), nil
		}
		security.LogPolicyDecision(pctx.User, toolName, true, "")
		return handler(ctx, req)
	}
}
