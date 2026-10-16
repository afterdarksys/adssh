package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.starlark.net/resolve"
	"go.starlark.net/starlark"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/internal/config"
	"github.com/afterdarksys/adssh/internal/guard"
	"github.com/afterdarksys/adssh/internal/starlarkext"
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"
)

func init() {
	resolve.AllowSet = true
	resolve.AllowGlobalReassign = true
	resolve.AllowRecursion = true
}

type preparedMCP struct {
	cfg       config.AppConfig
	eng       *engine.Engine
	agent     mcpAgentConfig
	sessionID string
}

func main() {
	sys.MaybeRunSessionChild()
	prepared, exitCode, err := prepareMCPProcess(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adssh-mcp: %v\n", err)
		os.Exit(exitCode)
	}
	defer sys.UnregisterSession(prepared.sessionID)

	// TODO(engine-facade): the Starlark exec builtins (eval_starlark) and the
	// run_shell interceptor still resolve the process-global default engine.
	// Point the default at the engine we built so those tool paths authorize
	// through the same policy and audit log as policyGate.
	security.SetDefaultEngine(prepared.eng.Security())
	guard.SetRecorder(func(ev guard.Event) {
		prepared.eng.Security().LogEvent(fmt.Sprintf("GUARD action=%s addr=%s reason=%s", ev.Action, ev.Addr, ev.Reason))
	})
	if err := guard.Configure(guard.Options{
		ConfigPath: prepared.cfg.GuardConfigPath,
		StatePath:  prepared.cfg.GuardStatePath,
		Switch:     prepared.cfg.GuardSwitch,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "adssh-mcp: guard: %v\n", err)
	}
	if _, statErr := os.Stat(prepared.cfg.PolicyPath); statErr == nil {
		prepared.eng.Security().LogEvent(fmt.Sprintf("Policy loaded from %s", prepared.cfg.PolicyPath))
	}

	globals := starlark.StringDict{}
	starlarkext.SetupExtensions(starlarkext.ExtensionOptions{
		Env:        globals,
		Restricted: prepared.cfg.Restricted,
		SessionID:  prepared.sessionID,
		Engine:     prepared.eng.Security(),
	})

	prepared.eng.Security().LogEvent("adssh-mcp server starting")
	if err := serveMCP(prepared.cfg, prepared.eng, globals, prepared.agent); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		sys.UnregisterSession(prepared.sessionID)
		os.Exit(1)
	}
}

// prepareMCPProcess binds one session id into the engine, the registry, and
// the agent claim. The tools file is checked before the engine is built. A
// missing file exits 2. A malformed policy still exits 1. The session is
// registered only after the engine is created.
func prepareMCPProcess(args []string) (preparedMCP, int, error) {
	if err := sys.ConfigureHostFromEnv(); err != nil {
		return preparedMCP{}, 1, err
	}
	cfg := config.LoadFromEnv()
	agentID := os.Getenv("ADSSH_AGENT_ID")
	requireDryRun := strings.EqualFold(os.Getenv("ADSSH_AGENT_REQUIRE_DRY_RUN"), "true")
	toolsFile := selectAgentToolsFile(args, os.Getenv("ADSSH_AGENT_TOOLS_FILE"))
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--policy" && i+1 < len(args):
			cfg.PolicyPath = args[i+1]
			i++
		case arg == "--agent-id" && i+1 < len(args):
			agentID = args[i+1]
			i++
		case arg == "--require-agent-dry-run":
			requireDryRun = true
		case arg == "--agent-tools-file" && i+1 < len(args):
			i++
		}
	}
	if agentID == "" {
		agentID = fmt.Sprintf("mcp-%d", os.Getpid())
	}
	loaded := mcpAgentConfig{}
	if toolsFile != "" {
		var err error
		loaded, err = loadAgentTools(toolsFile)
		if err != nil {
			return preparedMCP{}, 2, fmt.Errorf("agent tools file: %w", err)
		}
	}
	sessionID := fmt.Sprintf("mcp-%d", time.Now().UnixNano())
	eng, err := engine.New(engine.Config{
		EngineConfig: security.EngineConfig{
			PolicyPath:       cfg.PolicyPath,
			AuditLogPath:     cfg.AuditLogPath,
			AuditLogURL:      cfg.AuditURL,
			AuditLogToken:    cfg.AuditToken,
			ChainPath:        cfg.AuditLogPath + ".chain",
			ChainKeyPath:     filepath.Join(config.XDGDataHome(), "audit.key"),
			SessionID:        sessionID,
			EntitlementsPath: cfg.EntitlementsPath,
			Restricted:       cfg.Restricted,
		},
	})
	if err != nil {
		return preparedMCP{}, 1, err
	}
	if err := sys.RegisterSession(&sys.Session{ID: sessionID, User: agentID}); err != nil {
		return preparedMCP{}, 1, err
	}
	return preparedMCP{
		cfg:       cfg,
		eng:       eng,
		sessionID: sessionID,
		agent: mcpAgentConfig{
			ID:              agentID,
			RequireDryRun:   requireDryRun,
			SessionID:       sessionID,
			Tools:           loaded.Tools,
			ToolsConfigured: loaded.ToolsConfigured,
		},
	}, 0, nil
}
