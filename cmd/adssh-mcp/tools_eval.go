package main

import (
	"bytes"
	"context"
	"fmt"

	"github.com/afterdarksys/adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.starlark.net/starlark"
)

// handleEvalStarlark returns a tool handler that executes Starlark code using
// the shared globals dict. A new thread is created per call (never reused).
// Returns JSON with "output" (print statements) and "result" (expression value).
func handleEvalStarlark(globals starlark.StringDict) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		code, err := req.RequireString("code")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: code"), nil
		}

		evalGlobals := globals
		if sec, ok := ctx.Value(mcpSecurityEngineContextKey{}).(*security.Engine); ok && sec != nil {
			evalGlobals = governStarlarkGlobals(sec, globals)
		}

		// New thread per evaluation (from starlarkext/exec.go pattern)
		thread := &starlark.Thread{Name: "mcp-eval"}
		var buf bytes.Buffer
		thread.Print = func(_ *starlark.Thread, msg string) { buf.WriteString(msg + "\n") }

		// Record before evaluating; a failed write runs nothing.
		if err := security.LogCommand("MCP:eval_starlark", code); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("audit log failed: %v", err)), nil
		}

		// ExecFile supports both multi-statement code and single expressions
		val, err := starlark.ExecFile(thread, "<mcp>", code, evalGlobals)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("starlark error: %v", err)), nil
		}

		// Build result with output and result value as separate fields
		result := fmt.Sprintf("output: %s\nresult: %v", buf.String(), val)
		return mcp.NewToolResultText(result), nil
	}
}
