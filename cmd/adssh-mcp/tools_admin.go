package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Threats: these tools read the local admin surfaces and run the device-login
// client. They do not print bearers or approval tokens. A missing security
// engine fails closed. Tool arguments named agent_id or session_id stay
// command arguments and do not replace the process claim. Device login stores
// an opaque bearer and does not import groups. This does not wire provision,
// enroll, or execute.

func registerGovernedAdminTools(s *server.MCPServer, toolMu *sync.Mutex, eng *engine.Engine, agent mcpAgentConfig) {
	add := func(tool mcp.Tool, name string, handler server.ToolHandlerFunc) {
		s.AddTool(tool, serializedHandler(toolMu, policyGate(eng, name, handler, agent)))
	}
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
	add(mcp.NewTool("admin_approve",
		mcp.WithDescription("Approve a pending four-eyes request by its public request id. The response does not include the approval token."),
		mcp.WithString("approver", mcp.Required(), mcp.Description("Distinct approver identity")),
		mcp.WithString("request_id", mcp.Description("Public request id")),
		mcp.WithString("id", mcp.Description("Public request id when request_id is omitted")),
	), "admin_approve", handleAdminDecision(true))
	add(mcp.NewTool("admin_deny",
		mcp.WithDescription("Deny a pending four-eyes request by its public request id. The response does not include the approval token."),
		mcp.WithString("approver", mcp.Required(), mcp.Description("Distinct approver identity")),
		mcp.WithString("request_id", mcp.Description("Public request id")),
		mcp.WithString("id", mcp.Description("Public request id when request_id is omitted")),
	), "admin_deny", handleAdminDecision(false))
	add(mcp.NewTool("identity_status",
		mcp.WithDescription("Return the bound MCP session id, user, and principals. No token and no elevation are returned."),
	), "identity_status", handleIdentityStatus())
	add(mcp.NewTool("identity_device_login",
		mcp.WithDescription("Device-login client for the systemapi control plane. Stores an opaque bearer in a 0600 file and sets the session user with no groups. The authorization server stays in systemapi. The bearer is not printed."),
		mcp.WithString("url", mcp.Required(), mcp.Description("Control-plane base URL")),
		mcp.WithString("username", mcp.Required(), mcp.Description("Username for the device flow")),
		mcp.WithString("token_file", mcp.Description("Absolute token file path. The default is ~/.adssh/device.token")),
		mcp.WithString("interval", mcp.Description("Poll interval as a Go duration or integer seconds")),
		mcp.WithString("timeout", mcp.Description("Overall timeout as a Go duration or integer seconds")),
	), "identity_device_login", handleIdentityDeviceLogin())
}

func securityEngineFromMCP(ctx context.Context) (*security.Engine, error) {
	eng, _ := ctx.Value(mcpSecurityEngineContextKey{}).(*security.Engine)
	if eng == nil {
		return nil, errors.New("agent: security engine is not bound")
	}
	return eng, nil
}

func mcpJSONResult(value any) (*mcp.CallToolResult, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return mcp.NewToolResultError("agent: response encoding failed"), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

type sessionListItem struct {
	ID             string         `json:"id"`
	User           string         `json:"user"`
	Principals     []string       `json:"principals"`
	CreatedAt      time.Time      `json:"created_at"`
	LastActive     time.Time      `json:"last_active"`
	CurrentCommand string         `json:"current_command,omitempty"`
	Terminated     bool           `json:"terminated,omitempty"`
	Recording      string         `json:"recording,omitempty"`
	Elevation      *sys.Elevation `json:"elevation,omitempty"`
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

func handleAdminDecision(approve bool) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		eng, err := securityEngineFromMCP(ctx)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		approver, _ := mcpStringArg(req, "approver")
		requestID, ok := mcpStringArg(req, "request_id")
		if !ok {
			requestID, _ = mcpStringArg(req, "id")
		}
		if approve {
			err = eng.ApproveRequestAs(requestID, approver)
		} else {
			err = eng.DenyRequestAs(requestID, approver)
		}
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcpJSONResult(map[string]bool{"ok": true})
	}
}

func handleIdentityStatus() server.ToolHandlerFunc {
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if _, err := securityEngineFromMCP(ctx); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		session := sys.GetSession(security.SessionIDFromContext(ctx))
		if session == nil {
			return mcp.NewToolResultError("identity: requires an active registered session"), nil
		}
		info := session.Info()
		principals := info.Principals
		if principals == nil {
			principals = []string{}
		}
		return mcpJSONResult(map[string]any{
			"session_id": info.ID,
			"user":       info.User,
			"principals": principals,
		})
	}
}

func handleIdentityDeviceLogin() server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if _, err := securityEngineFromMCP(ctx); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		login, err := deviceLoginRequestFromTool(req)
		if err != nil {
			return mcp.NewToolResultError("device_login_failed"), nil
		}
		result, err := security.DeviceLogin(ctx, login)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcpJSONResult(map[string]string{
			"token_file":  result.TokenFile,
			"fingerprint": result.Fingerprint,
		})
	}
}

func deviceLoginRequestFromTool(req mcp.CallToolRequest) (security.DeviceLoginRequest, error) {
	url, _ := mcpStringArg(req, "url")
	username, _ := mcpStringArg(req, "username")
	tokenFile, _ := mcpStringArg(req, "token_file")
	login := security.DeviceLoginRequest{URL: url, Username: username, TokenFile: tokenFile}
	arguments := req.GetArguments()
	if raw, ok := arguments["interval"]; ok {
		interval, err := mcpFlexibleDuration(raw)
		if err != nil {
			return security.DeviceLoginRequest{}, err
		}
		login.Interval = interval
		login.IntervalSet = true
	}
	if raw, ok := arguments["timeout"]; ok {
		timeout, err := mcpFlexibleDuration(raw)
		if err != nil {
			return security.DeviceLoginRequest{}, err
		}
		login.Timeout = timeout
	}
	return login, nil
}

func mcpStringArg(req mcp.CallToolRequest, key string) (string, bool) {
	value, ok := req.GetArguments()[key]
	if !ok || value == nil {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	return text, true
}

func mcpFlexibleDuration(value any) (time.Duration, error) {
	switch value := value.(type) {
	case string:
		return security.ParseFlexibleDuration(value)
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return 0, errors.New("duration")
		}
		return time.Duration(value * float64(time.Second)), nil
	default:
		return 0, errors.New("duration")
	}
}
