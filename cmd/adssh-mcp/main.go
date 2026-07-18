package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.starlark.net/resolve"
	"go.starlark.net/starlark"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/internal/config"
	"github.com/afterdarksys/adssh/internal/starlarkext"
	"github.com/afterdarksys/adssh/security"
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

	// 3. Build the security engine from configuration (fail-closed: a malformed
	// policy aborts startup). As in the shell binary, this configures the audit
	// log, HMAC chain, RBAC entitlements, restricted mode, and Rego policy the
	// MCP server enforces.
	eng, err := engine.New(engine.Config{
		EngineConfig: security.EngineConfig{
			PolicyPath:       cfg.PolicyPath,
			AuditLogPath:     cfg.AuditLogPath,
			AuditLogURL:      cfg.AuditURL,
			AuditLogToken:    cfg.AuditToken,
			ChainPath:        cfg.AuditLogPath + ".chain",
			ChainKeyPath:     filepath.Join(config.XDGDataHome(), "audit.key"),
			SessionID:        fmt.Sprintf("mcp-%d", time.Now().UnixNano()),
			EntitlementsPath: cfg.EntitlementsPath,
			Restricted:       cfg.Restricted,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "adssh-mcp: %v\n", err)
		os.Exit(1)
	}

	// TODO(engine-facade): the Starlark exec builtins (eval_starlark) and the
	// run_shell interceptor still resolve the process-global default engine.
	// Point the default at the engine we built so those tool paths authorize
	// through the same policy and audit log as policyGate.
	security.SetDefaultEngine(eng.Security())
	if _, statErr := os.Stat(cfg.PolicyPath); statErr == nil {
		eng.Security().LogEvent(fmt.Sprintf("Policy loaded from %s", cfg.PolicyPath))
	}

	// 4. Build Starlark env (shared across all tool calls)
	globals := starlark.StringDict{}
	starlarkext.SetupExtensions(starlarkext.ExtensionOptions{Env: globals, Restricted: cfg.Restricted, Engine: eng.Security()})

	// 5. Start MCP server
	eng.Security().LogEvent("adssh-mcp server starting")
	if err := serveMCP(cfg, eng, globals, apiKey); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}
