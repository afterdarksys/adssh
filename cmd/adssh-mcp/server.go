package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/internal/config"
	"github.com/afterdarksys/adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.starlark.net/starlark"
)

type mcpAgentConfig struct {
	ID            string
	RequireDryRun bool
}

// serveMCP creates the MCP server, registers all tools, and starts stdio transport.
// Every tool is gated by the engine's Rego policy via policyGate.
func serveMCP(cfg config.AppConfig, eng *engine.Engine, globals starlark.StringDict, apiKey string, agent mcpAgentConfig) error {
	s := server.NewMCPServer(
		"adssh-mcp",
		"1.0.0",
		server.WithToolCapabilities(false),
	)
	// Starlark dictionaries and several extension objects are mutable and are
	// shared by all MCP tools. Serialize tool execution at their common boundary.
	toolMu := &sync.Mutex{}

	// Register eval_starlark tool
	s.AddTool(
		mcp.NewTool("eval_starlark",
			mcp.WithDescription("Execute a Starlark expression in the adssh environment. Returns output (print statements) and result value."),
			mcp.WithString("code",
				mcp.Required(),
				mcp.Description("Starlark code to evaluate"),
			),
		),
		serializedHandler(toolMu, policyGate(eng, "eval_starlark", handleEvalStarlark(globals), agent)),
	)

	// Register run_shell tool
	s.AddTool(
		mcp.NewTool("run_shell",
			mcp.WithDescription("Execute a POSIX shell command. Returns exit_code, stdout, and stderr."),
			mcp.WithString("command",
				mcp.Required(),
				mcp.Description("Shell command to execute"),
			),
			mcp.WithBoolean("dry_run",
				mcp.Description("Authorize and report the command plan without executing it"),
			),
		),
		serializedHandler(toolMu, policyGate(eng, "run_shell", handleRunShell(globals, cfg.Restricted), agent)),
	)

	// Register list_sessions tool
	s.AddTool(
		mcp.NewTool("list_sessions",
			mcp.WithDescription("List active SSH sessions. Returns a JSON array of session IDs."),
		),
		serializedHandler(toolMu, policyGate(eng, "list_sessions", handleListSessions(), agent)),
	)

	// Register cloud_query tool
	s.AddTool(
		mcp.NewTool("cloud_query",
			mcp.WithDescription("Execute a cloud namespace function. Supports aws, gcp, oci namespaces."),
			mcp.WithString("namespace",
				mcp.Required(),
				mcp.Description("Cloud provider namespace: aws, gcp, oci, or cloud"),
			),
			mcp.WithString("function",
				mcp.Required(),
				mcp.Description("Function name within the namespace to call"),
			),
		),
		serializedHandler(toolMu, policyGate(eng, "cloud_query", handleCloudQuery(globals), agent)),
	)

	// Register container_exec tool
	s.AddTool(
		mcp.NewTool("container_exec",
			mcp.WithDescription("Run a command in an ephemeral Docker container. Container is created, executed, and removed. Returns session_id, exit_code, stdout, stderr, duration_ms."),
			mcp.WithString("image",
				mcp.Required(),
				mcp.Description("Docker image to use (e.g. ubuntu:22.04)"),
			),
			mcp.WithString("cmd",
				mcp.Required(),
				mcp.Description("Command to run, as a JSON array of strings (e.g. [\"ls\",\"-la\"]) or a single command string"),
			),
		),
		serializedHandler(toolMu, policyGate(eng, "container_exec", handleContainerExec(), agent)),
	)

	// Register audit_log tool
	s.AddTool(
		mcp.NewTool("audit_log",
			mcp.WithDescription("Query recent audit log entries. Returns the last N lines from the audit log, optionally filtered by substring."),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of entries to return (default 50)"),
				mcp.DefaultNumber(50),
			),
			mcp.WithString("filter",
				mcp.Description("Optional substring filter to match against log entries"),
			),
		),
		serializedHandler(toolMu, policyGate(eng, "audit_log", handleAuditLog(cfg.AuditLogPath), agent)),
	)

	eng.Security().LogEvent("adssh-mcp serving on stdio")
	return server.ServeStdio(s)
}

func serializedHandler(mu *sync.Mutex, handler server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		mu.Lock()
		defer mu.Unlock()
		return handler(ctx, req)
	}
}

// policyGate wraps a tool handler with the engine's Rego policy evaluation.
// Every tool invocation is evaluated against eng before execution (MCP-08).
func policyGate(eng *engine.Engine, toolName string, handler server.ToolHandlerFunc, configs ...mcpAgentConfig) server.ToolHandlerFunc {
	sec := eng.Security()
	agent := mcpAgentConfig{ID: "mcp-agent"}
	if len(configs) > 0 {
		agent = configs[0]
		if agent.ID == "" {
			agent.ID = "mcp-agent"
		}
	}
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := append([]string{toolName}, policyArgs(req)...)
		risk := classifyAgentRisk(toolName, req)
		dryRun := requestDryRun(req)
		if agent.RequireDryRun && risk == "destructive" && !dryRun {
			return mcp.NewToolResultError("agent: destructive action requires dry_run=true"), nil
		}
		if err := sec.AuthorizeCommandWithExtra(args, "", security.PolicyContextExtra{
			Agent: &security.AgentClaim{
				ID:     agent.ID,
				Kind:   "mcp",
				Risk:   risk,
				DryRun: dryRun,
			},
		}); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return handler(context.WithValue(ctx, mcpSecurityEngineContextKey{}, sec), req)
	}
}

func requestDryRun(req mcp.CallToolRequest) bool {
	value, ok := req.GetArguments()["dry_run"]
	if !ok {
		return false
	}
	switch value := value.(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(value, "true") || value == "1" || strings.EqualFold(value, "yes")
	default:
		return false
	}
}

func classifyAgentRisk(toolName string, req mcp.CallToolRequest) string {
	switch toolName {
	case "list_sessions", "audit_log", "cloud_query":
		return "read"
	case "container_exec", "eval_starlark":
		return "mutable"
	case "run_shell":
		command, _ := req.GetArguments()["command"].(string)
		if shellCommandLooksDestructive(command) {
			return "destructive"
		}
		return "mutable"
	default:
		return "unknown"
	}
}

func shellCommandLooksDestructive(command string) bool {
	lower := strings.ToLower(command)
	destructiveFragments := []string{
		"rm -", "rm ", " rmdir ", "delete", "destroy", "terminate",
		"kubectl delete", "terraform apply", "terraform destroy", "tofu apply", "tofu destroy",
		"docker rm", "docker rmi", "git push --force", "chmod 777",
	}
	for _, fragment := range destructiveFragments {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

func policyArgs(req mcp.CallToolRequest) []string {
	arguments := req.GetArguments()
	keys := make([]string, 0, len(arguments))
	for key := range arguments {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	args := make([]string, 0, len(keys))
	for _, key := range keys {
		value := arguments[key]
		if str, ok := value.(string); ok {
			args = append(args, key+"="+str)
			continue
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			encoded = []byte(fmt.Sprint(value))
		}
		args = append(args, key+"="+string(encoded))
	}
	return args
}
