//go:build ee

package main

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/afterdarksys/adssh/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// identity_device_login is part of the enterprise layer (ee/LICENSE): it is
// the MCP face of security.DeviceLogin (device_login_ee.go). It registers
// through enterpriseToolRegistrars like the admin_* tools.
func init() {
	enterpriseToolRegistrars = append(enterpriseToolRegistrars, func(add toolAdder) {
		add(mcp.NewTool("identity_device_login",
			mcp.WithDescription("Device-login client for the systemapi control plane. Stores an opaque bearer in a 0600 file and sets the session user with no groups. The authorization server stays in systemapi. The bearer is not printed."),
			mcp.WithString("url", mcp.Required(), mcp.Description("Control-plane base URL")),
			mcp.WithString("username", mcp.Required(), mcp.Description("Username for the device flow")),
			mcp.WithString("token_file", mcp.Description("Absolute token file path. The default is ~/.adssh/device.token")),
			mcp.WithString("interval", mcp.Description("Poll interval as a Go duration or integer seconds")),
			mcp.WithString("timeout", mcp.Description("Overall timeout as a Go duration or integer seconds")),
		), "identity_device_login", handleIdentityDeviceLogin())
	})
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
