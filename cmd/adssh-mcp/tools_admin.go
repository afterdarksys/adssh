package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Threats: these tools read the local admin surfaces and run the device-login
// client. They cannot approve or deny a four-eyes request, and the process
// refuses every decision once they are registered. They do not print bearers
// or approval tokens. A missing security
// engine fails closed. Tool arguments named agent_id or session_id stay
// command arguments and do not replace the process claim. Device login stores
// an opaque bearer and does not import groups. This does not wire provision,
// enroll, or execute.

// registerGovernedAdminTools registers the identity tools, then whatever the
// enterprise build adds (the read-only admin_* tools, tools_admin_ee.go).
// There is no approve or deny tool: an agent must not decide a four-eyes
// request. ForbidFourEyesDecisions runs in every build, core included, and
// also closes run_shell and eval_starlark paths to `4eyes approve` in this
// process.
func registerGovernedAdminTools(s *server.MCPServer, toolMu *sync.Mutex, eng *engine.Engine, agent mcpAgentConfig) {
	security.ForbidFourEyesDecisions()
	add := func(tool mcp.Tool, name string, handler server.ToolHandlerFunc) {
		s.AddTool(tool, serializedHandler(toolMu, policyGate(eng, name, handler, agent)))
	}
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
	for _, register := range enterpriseToolRegistrars {
		register(add)
	}
}

// toolAdder registers one policy-gated, serialized MCP tool.
type toolAdder func(tool mcp.Tool, name string, handler server.ToolHandlerFunc)

// enterpriseToolRegistrars is filled by *_ee.go files in the enterprise build.
var enterpriseToolRegistrars []func(add toolAdder)

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
		payload := map[string]any{
			"session_id": info.ID,
			"user":       info.User,
			"principals": principals,
		}
		if info.OIDCProvider != "" {
			payload["oidc_provider"] = info.OIDCProvider
		}
		if len(info.EligibleRoles) > 0 {
			payload["eligible_roles"] = info.EligibleRoles
		}
		return mcpJSONResult(payload)
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
