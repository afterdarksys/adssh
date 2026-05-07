package main

import (
	"fmt"
	"os"
	"strings"

	"go.starlark.net/resolve"
	"go.starlark.net/starlark"
	"io"

	"adssh/config"
	"adssh/repl"
	"adssh/security"
	"adssh/starlarkext"
	"adssh/sys"
)

func init() {
	// Enable helpful Starlark features
	resolve.AllowSet = true
	resolve.AllowGlobalReassign = true
	resolve.AllowRecursion = true
}

func main() {
	// 1. Load configuration from ADSSH_* environment variables (provides defaults)
	cfg := config.LoadFromEnv()

	// 2. Parse CLI flags — flags override env vars
	cfg.IsLoginShell = strings.HasPrefix(os.Args[0], "-")

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case arg == "-r" || arg == "--restricted":
			cfg.Restricted = true
		case arg == "-l" || arg == "--login":
			cfg.IsLoginShell = true
		case (arg == "--serve") && i+1 < len(os.Args):
			cfg.ServeAddr = os.Args[i+1]
			i++
		case (arg == "--entitlements") && i+1 < len(os.Args):
			cfg.EntitlementsPath = os.Args[i+1]
			i++
		case (arg == "--policy") && i+1 < len(os.Args):
			cfg.PolicyPath = os.Args[i+1]
			i++
		case !strings.HasPrefix(arg, "-") && cfg.ScriptPath == "":
			cfg.ScriptPath = arg
		}
	}

	// 3. Initialize audit logging
	security.InitAuditLog(cfg.AuditLogPath, cfg.AuditURL, cfg.AuditToken)

	// 4. Load RBAC entitlements (if a path was configured)
	if cfg.EntitlementsPath != "" {
		if err := security.LoadEntitlements(cfg.EntitlementsPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load entitlements from %s: %v\n", cfg.EntitlementsPath, err)
		} else {
			security.LogEvent(fmt.Sprintf("Entitlements loaded from %s", cfg.EntitlementsPath))
		}
	}

	// 4b. Load Rego policy engine
	if err := security.LoadPolicy(cfg.PolicyPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load policy from %s: %v\n", cfg.PolicyPath, err)
	} else {
		security.LogEvent(fmt.Sprintf("Policy loaded from %s", cfg.PolicyPath))
	}

	// 5. Setup signal handling and terminal
	sys.SetupSignals()
	if err := sys.InitTerminal(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to initialize terminal: %v\n", err)
	}

	// 6. Build Starlark environment and load profiles
	thread := &starlark.Thread{Name: "main"}
	globals := starlark.StringDict{}
	starlarkext.SetupExtensions(globals, cfg.Restricted)

	env, err := config.LoadProfiles(thread, globals, cfg.IsLoginShell, cfg.ProfilePath, cfg.RCPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading profiles: %v\n", err)
	}

	// 6b. Inject SSH management builtins into `sys` dict
	if sysVal, ok := env["sys"]; ok {
		if sysDict, ok := sysVal.(*starlark.Dict); ok {
			enableSSH := starlark.NewBuiltin("enable_ssh", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var addr string
				if err := starlark.UnpackArgs(b.Name(), args, kwargs, "address", &addr); err != nil {
					return nil, err
				}
				if err := sys.EnableSSH(addr, cfg.HostKeyPath, cfg.AuthorizedKeysPath, env, cfg.Restricted, smartReplWrapper); err != nil {
					return nil, err
				}
				return starlark.None, nil
			})
			disableSSH := starlark.NewBuiltin("disable_ssh", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				if err := sys.DisableSSH(); err != nil {
					return nil, err
				}
				return starlark.None, nil
			})
			sysDict.SetKey(starlark.String("enable_ssh"), enableSSH)
			sysDict.SetKey(starlark.String("disable_ssh"), disableSSH)
		}
	}

	// 7. Dispatch to the appropriate execution mode
	if cfg.ServeAddr != "" {
		if err := sys.EnableSSH(cfg.ServeAddr, cfg.HostKeyPath, cfg.AuthorizedKeysPath, env, cfg.Restricted, smartReplWrapper); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start SSH server: %v\n", err)
			os.Exit(1)
		}
	}

	if cfg.ScriptPath != "" {
		if _, err := starlark.ExecFile(thread, cfg.ScriptPath, nil, env); err != nil {
			fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
			os.Exit(1)
		}
	} else {
		smartReplWrapper(env, cfg.Restricted, cfg.HistoryFile, os.Stdin, os.Stdout, os.Stderr)
	}
}

func smartReplWrapper(globals starlark.StringDict, restricted bool, historyFile string, in io.ReadCloser, out io.Writer, errOut io.Writer) {
	var sessionID string
	if val, ok := globals["SESSION_ID"]; ok {
		if strVal, ok := val.(starlark.String); ok {
			sessionID = string(strVal)
		}
	}

	if sessionID != "" {
		if session := sys.GetSession(sessionID); session != nil {
			menuPath := security.GetMenuForUser(session.User, session.Principals)
			if menuPath != "" {
				repl.StartMenu(menuPath, globals, restricted, in, out, errOut)
				return
			}
		}
	}

	repl.Start(globals, restricted, historyFile, in, out, errOut)
}

