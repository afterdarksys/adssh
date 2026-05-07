package main

import (
	"context"
	"fmt"

	"adssh/security"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.starlark.net/starlark"
)

// handleCloudQuery returns a handler that executes cloud namespace functions.
// Accesses the shared globals dict to find cloud provider namespaces (aws, gcp, oci, cloud).
// The "namespace" param selects the provider dict, "function" selects the callable within it.
func handleCloudQuery(globals starlark.StringDict) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		namespace, err := req.RequireString("namespace")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: namespace"), nil
		}
		fn, err := req.RequireString("function")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: function"), nil
		}

		nsVal, ok := globals[namespace]
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("unknown namespace: %s", namespace)), nil
		}
		nsDict, ok := nsVal.(*starlark.Dict)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("namespace %s is not a dict", namespace)), nil
		}

		callable, found, err := nsDict.Get(starlark.String(fn))
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("error accessing %s.%s: %v", namespace, fn, err)), nil
		}
		if !found {
			return mcp.NewToolResultError(fmt.Sprintf("unknown function: %s.%s", namespace, fn)), nil
		}

		callFn, ok := callable.(starlark.Callable)
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("%s.%s is not callable", namespace, fn)), nil
		}

		thread := &starlark.Thread{Name: "mcp-cloud"}
		result, err := starlark.Call(thread, callFn, nil, nil)
		if err != nil {
			security.LogCommand("MCP:cloud_query", fmt.Sprintf("%s.%s", namespace, fn))
			return mcp.NewToolResultError(fmt.Sprintf("error calling %s.%s: %v", namespace, fn, err)), nil
		}

		security.LogCommand("MCP:cloud_query", fmt.Sprintf("%s.%s", namespace, fn))
		return mcp.NewToolResultText(result.String()), nil
	}
}
