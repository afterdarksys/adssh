package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/afterdarksys/adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// handleRunShell returns a tool handler that executes POSIX shell commands.
// Uses the same runner construction as starlarkext/exec.go: separate stdout/stderr
// buffers, BashInterceptor for policy enforcement on subcommands, OpenInterceptorSession.
// Returns structured output with exit_code, stdout, stderr.
//
// The session id is read once, when the handler is built. A later write to
// the SESSION_ID global does not move the gate or vbins.
func handleRunShell(globals starlark.StringDict, restricted bool) server.ToolHandlerFunc {
	sid := ""
	if v, ok := globals["SESSION_ID"].(starlark.String); ok {
		sid = string(v)
	}
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cmd, err := req.RequireString("command")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: command"), nil
		}
		if requestDryRun(req) {
			if err := security.LogCommand("MCP:run_shell:dry_run", cmd); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("audit log failed: %v", err)), nil
			}
			return mcp.NewToolResultText(fmt.Sprintf("dry_run: true\ncommand: %s", cmd)), nil
		}

		// Parse shell command (from starlarkext/exec.go pattern)
		parserFile, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("parse error: %v", err)), nil
		}

		state := &security.SessionState{Restricted: restricted, Globals: globals, SessionID: sid}
		// Separate stdout and stderr buffers (MCP-03: returns exit_code, stdout, stderr)
		var stdout, stderr bytes.Buffer
		runner, err := interp.New(
			interp.Env(security.NewSessionEnviron(sid)),
			interp.StdIO(nil, &stdout, &stderr),
			interp.CallHandler(security.CallInterceptorSession(state)),
			interp.ExecHandlers(security.BashInterceptorSession(state), security.SessionExecHandler),
			interp.OpenHandler(security.OpenInterceptorSession(state)),
		)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("runner init error: %v", err)), nil
		}

		// DeclClause keywords (export/readonly/declare/...) bypass the call and
		// exec handlers; gate them via the AST pre-scan before running.
		if err := security.GateProgramSession(state, parserFile); err != nil {
			if logErr := security.LogCommand("MCP:run_shell", cmd); logErr != nil {
				return mcp.NewToolResultError(fmt.Sprintf("exec error: %v (audit: %v)", err, logErr)), nil
			}
			return mcp.NewToolResultError(fmt.Sprintf("exec error: %v", err)), nil
		}

		exitCode := 0
		if err := runner.Run(ctx, parserFile); err != nil {
			if status, ok := interp.IsExitStatus(err); ok {
				exitCode = int(status)
			} else {
				if logErr := security.LogCommand("MCP:run_shell", cmd); logErr != nil {
					return mcp.NewToolResultError(fmt.Sprintf("exec error: %v (audit: %v)", err, logErr)), nil
				}
				return mcp.NewToolResultError(fmt.Sprintf("exec error: %v", err)), nil
			}
		}

		if err := security.LogCommand("MCP:run_shell", cmd); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("audit log failed: %v", err)), nil
		}

		// Return structured output with exit_code, stdout, stderr
		result := fmt.Sprintf("exit_code: %d\nstdout: %s\nstderr: %s",
			exitCode, stdout.String(), stderr.String())
		return mcp.NewToolResultText(result), nil
	}
}
