package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// handleRunShell returns a tool handler that executes POSIX shell commands.
// Uses the same runner construction as starlarkext/exec.go: separate stdout/stderr
// buffers, BashInterceptor for policy enforcement on subcommands, VirtualOpenHandler.
// Returns structured output with exit_code, stdout, stderr.
func handleRunShell(globals starlark.StringDict) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cmd, err := req.RequireString("command")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: command"), nil
		}

		// Parse shell command (from starlarkext/exec.go pattern)
		parserFile, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("parse error: %v", err)), nil
		}

		// Separate stdout and stderr buffers (MCP-03: returns exit_code, stdout, stderr)
		var stdout, stderr bytes.Buffer
		runner, err := interp.New(
			interp.StdIO(nil, &stdout, &stderr),
			interp.ExecHandlers(security.BashInterceptor(false, globals)),
			interp.OpenHandler(security.VirtualOpenHandler()),
		)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("runner init error: %v", err)), nil
		}

		exitCode := 0
		if err := runner.Run(context.Background(), parserFile); err != nil {
			if status, ok := interp.IsExitStatus(err); ok {
				exitCode = int(status)
			} else {
				security.LogCommand("MCP:run_shell", cmd)
				return mcp.NewToolResultError(fmt.Sprintf("exec error: %v", err)), nil
			}
		}

		security.LogCommand("MCP:run_shell", cmd)

		// Return structured output with exit_code, stdout, stderr
		result := fmt.Sprintf("exit_code: %d\nstdout: %s\nstderr: %s",
			exitCode, stdout.String(), stderr.String())
		return mcp.NewToolResultText(result), nil
	}
}
