package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

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

// registerGovernedAdminTools registers identity_status, then whatever the
// enterprise build adds (identity_device_login in tools_identity_ee.go, the
// read-only admin_* tools in tools_admin_ee.go).
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
