package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/security"

	"github.com/docker/docker/api/types/container"
	dockerimage "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
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

		// Generate session ID
		b := make([]byte, 8)
		rand.Read(b)
		sessionID := hex.EncodeToString(b)

		// Docker client (from starlarkext/containers.go pattern)
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("docker client error: %v", err)), nil
		}
		defer cli.Close()

		// Pull image if needed
		rc, pullErr := cli.ImagePull(ctx, image, dockerimage.PullOptions{})
		if pullErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("image pull failed: %v", pullErr)), nil
		}
		_, _ = io.Copy(io.Discard, rc) // best-effort: draining pull progress stream
		rc.Close()

		start := time.Now()
		resp, err := cli.ContainerCreate(ctx, &container.Config{
			Image: image,
			Cmd:   cmdArgs,
			Labels: map[string]string{
				"adssh.session": sessionID,
				"adssh.managed": "true",
			},
		}, &container.HostConfig{
			AutoRemove: false,
		}, nil, nil, "adssh-mcp-"+sessionID)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("container create error: %v", err)), nil
		}

		if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
			_ = cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true}) // best-effort cleanup
			return mcp.NewToolResultError(fmt.Sprintf("container start error: %v", err)), nil
		}

		statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
		var exitCode int64
		select {
		case err := <-errCh:
			if err != nil {
				_ = cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true}) // best-effort cleanup
				return mcp.NewToolResultError(fmt.Sprintf("container wait error: %v", err)), nil
			}
		case status := <-statusCh:
			exitCode = status.StatusCode
		}

		// Capture logs
		logReader, err := cli.ContainerLogs(ctx, resp.ID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
		if err != nil {
			_ = cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true}) // best-effort cleanup
			return mcp.NewToolResultError(fmt.Sprintf("logs error: %v", err)), nil
		}
		var stdout, stderr bytes.Buffer
		if _, err := stdcopy.StdCopy(&stdout, &stderr, logReader); err != nil {
			fmt.Fprintf(os.Stderr, "adssh-mcp: container_exec: log capture incomplete for %s: %v\n", resp.ID, err)
		}
		logReader.Close()

		durationMs := time.Since(start).Milliseconds()

		// Remove container
		_ = cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true}) // best-effort cleanup

		// Write audit record (same JSONL format as starlarkext/containers.go)
		auditRec := map[string]interface{}{
			"session_id":  sessionID,
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
			"image":       image,
			"cmd":         cmdArgs,
			"exit_code":   exitCode,
			"stdout":      stdout.String(),
			"stderr":      stderr.String(),
			"duration_ms": durationMs,
			"source":      "MCP:container_exec",
		}
		home, _ := os.UserHomeDir()
		auditPath := filepath.Join(home, ".adssh", "container_audit.jsonl")
		if err := os.MkdirAll(filepath.Dir(auditPath), 0700); err != nil {
			fmt.Fprintf(os.Stderr, "adssh-mcp: container_exec: failed to create audit dir: %v\n", err)
		}
		if f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			if err := json.NewEncoder(f).Encode(auditRec); err != nil {
				fmt.Fprintf(os.Stderr, "adssh-mcp: container_exec: failed to write audit record: %v\n", err)
			}
			f.Close()
		}

		security.LogCommand("MCP:container_exec", fmt.Sprintf("%s %s", image, strings.Join(cmdArgs, " ")))

		// Return structured result
		result := map[string]interface{}{
			"session_id":  sessionID,
			"exit_code":   exitCode,
			"stdout":      stdout.String(),
			"stderr":      stderr.String(),
			"duration_ms": durationMs,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}
}
