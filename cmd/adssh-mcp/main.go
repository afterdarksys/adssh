package main

import (
	"fmt"
	"os"

	"go.starlark.net/resolve"
	"go.starlark.net/starlark"

	"github.com/afterdarksys/adssh/config"
	"github.com/afterdarksys/adssh/security"
	"github.com/afterdarksys/adssh/starlarkext"
)

func init() {
	resolve.AllowSet = true
	resolve.AllowGlobalReassign = true
	resolve.AllowRecursion = true
}

func main() {
	// 1. Load config from ADSSH_* env vars
	cfg := config.LoadFromEnv()

	// 2. Parse MCP-specific CLI flags
	apiKey := os.Getenv("ADSSH_MCP_API_KEY")
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case (arg == "--policy") && i+1 < len(os.Args):
			cfg.PolicyPath = os.Args[i+1]
			i++
		case (arg == "--api-key") && i+1 < len(os.Args):
			apiKey = os.Args[i+1]
			i++
		}
	}

	// 3. Init audit logging
	security.InitAuditLog(cfg.AuditLogPath, cfg.AuditURL, cfg.AuditToken)

	// 4. Load Rego policy engine
	if err := security.LoadPolicy(cfg.PolicyPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load policy from %s: %v\n", cfg.PolicyPath, err)
	} else {
		security.LogEvent(fmt.Sprintf("Policy loaded from %s", cfg.PolicyPath))
	}

	// 5. Build Starlark env (shared across all tool calls)
	globals := starlark.StringDict{}
	starlarkext.SetupExtensions(globals, false)

	// 6. Start MCP server
	security.LogEvent("adssh-mcp server starting")
	if err := serveMCP(cfg, globals, apiKey); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}
