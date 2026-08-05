package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/afterdarksys/adssh/internal/starlarkext"
	"github.com/afterdarksys/adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// handleContainerExec returns a handler that runs ephemeral Docker containers.
// Replicates the execution pattern from starlarkext/containers.go runContainer().
// Container is created, started, waited on, logs captured, and removed.
// Returns JSON with session_id, exit_code, stdout, stderr, duration_ms.
func handleContainerExec() server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		image, err := req.RequireString("image")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: image"), nil
		}
		cmdStr, err := req.RequireString("cmd")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: cmd"), nil
		}

		// Parse cmd as JSON array of strings
		var cmdArgs []string
		if err := json.Unmarshal([]byte(cmdStr), &cmdArgs); err != nil {
			// Fallback: treat as single command string
			cmdArgs = strings.Fields(cmdStr)
		}

		rec, runErr := starlarkext.RunEphemeralContainer(ctx, "", image, cmdArgs, nil, "")

		security.LogCommand("MCP:container_exec", fmt.Sprintf("%s %s", image, strings.Join(cmdArgs, " ")))

		// Return structured result
		result := map[string]interface{}{
			"session_id":  rec.SessionID,
			"exit_code":   rec.ExitCode,
			"stdout":      rec.Stdout,
			"stderr":      rec.Stderr,
			"duration_ms": rec.DurationMs,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		if runErr != nil {
			return mcp.NewToolResultError(string(data)), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	}
}
