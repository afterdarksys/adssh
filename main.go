package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.starlark.net/resolve"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"

	"adssh/config"
	"adssh/parser"
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
	// 0. Set SHELL env var for POSIX compliance — child processes need this
	if binaryPath, err := os.Executable(); err == nil {
		os.Setenv("SHELL", binaryPath)
	}

	// 1. Load configuration from ADSSH_* environment variables (provides defaults)
	cfg := config.LoadFromEnv()

	// 2. Parse CLI flags — flags override env vars
	cfg.IsLoginShell = strings.HasPrefix(os.Args[0], "-")

	var cmdFlag string // -c "expression"

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case arg == "-h" || arg == "--help":
			printHelp()
			return
		case arg == "--init":
			if err := runInit(); err != nil {
				fmt.Fprintf(os.Stderr, "init error: %v\n", err)
				os.Exit(1)
			}
			return
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
		case (arg == "-c") && i+1 < len(os.Args):
			cmdFlag = os.Args[i+1]
			i++
		case !strings.HasPrefix(arg, "-") && cfg.ScriptPath == "":
			cfg.ScriptPath = arg
		}
	}

	// 3. Initialize audit logging
	security.InitAuditLog(cfg.AuditLogPath, cfg.AuditURL, cfg.AuditToken)

	// 3b. Initialize HMAC chain ledger (next to the flat audit log)
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	xdgDataHome := config.XDGDataHome()
	security.InitChain(
		cfg.AuditLogPath+".chain",
		filepath.Join(xdgDataHome, "audit.key"),
		sessionID,
	)

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

	// 7a. -c flag: evaluate a single expression/command and exit
	if cmdFlag != "" {
		if err := evalOnce(thread, cmdFlag, env, cfg.Restricted); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		return
	}

	if cfg.ServeAddr != "" {
		if err := sys.EnableSSH(cfg.ServeAddr, cfg.HostKeyPath, cfg.AuthorizedKeysPath, env, cfg.Restricted, smartReplWrapper); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start SSH server: %v\n", err)
			os.Exit(1)
		}
	}

	if cfg.ScriptPath != "" {
		// Shebang / script file support: read content and evaluate
		src, err := os.ReadFile(cfg.ScriptPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read script %s: %v\n", cfg.ScriptPath, err)
			os.Exit(1)
		}
		// Strip shebang line if present
		content := string(src)
		if strings.HasPrefix(content, "#!") {
			if idx := strings.IndexByte(content, '\n'); idx >= 0 {
				content = content[idx+1:]
			} else {
				content = ""
			}
		}
		if _, err := starlark.ExecFile(thread, cfg.ScriptPath, []byte(content), env); err != nil {
			fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
			os.Exit(1)
		}
	} else {
		smartReplWrapper(env, cfg.Restricted, cfg.HistoryFile, os.Stdin, os.Stdout, os.Stderr)
	}
}

// evalOnce evaluates a single expression or command (for -c flag).
// It goes through the same security/audit machinery as the REPL.
func evalOnce(thread *starlark.Thread, src string, globals starlark.StringDict, restricted bool) error {
	security.LogCommand(src, "")

	mode := parser.DetermineMode(src)

	if mode == parser.ModeStarlark {
		// Try expression first
		val, err := starlark.Eval(thread, "<-c>", src, globals)
		if err == nil {
			if val != nil && val != starlark.None {
				fmt.Println(val.String())
			}
			return nil
		}
		// Fall back to statement (def, assignment, etc.)
		if _, err2 := starlark.ExecFile(thread, "<-c>", src, globals); err2 != nil {
			return fmt.Errorf("starlark error: %v", err2)
		}
		return nil
	}

	// Shell mode
	f, parseErr := syntax.NewParser().Parse(strings.NewReader(src), "")
	if parseErr != nil {
		return fmt.Errorf("parse error: %v", parseErr)
	}
	runner, runErr := interp.New(
		interp.StdIO(os.Stdin, os.Stdout, os.Stderr),
		interp.ExecHandlers(security.BashInterceptor(restricted, globals)),
		interp.OpenHandler(security.VirtualOpenHandler()),
	)
	if runErr != nil {
		return fmt.Errorf("runner error: %v", runErr)
	}
	if err := runner.Run(context.Background(), f); err != nil {
		return fmt.Errorf("command error: %v", err)
	}
	return nil
}

func printHelp() {
	fmt.Print(`adssh — programmable DevOps shell

USAGE
  adssh [options] [script.star]

OPTIONS
  -h, --help                  Show this help
      --init                  Create ~/.adssh/ with starter config and exit
  -r, --restricted            Restricted mode (no path traversal, no cd/export)
  -l, --login                 Login shell (load ~/.adsshprofile)
      --serve <addr>          Start built-in SSH server (e.g. --serve :2222)
      --policy <path>         Load OPA/Rego policy file
      --entitlements <path>   Load RBAC entitlements YAML

REPL MODES
  Starlark   aws.ec2.list_instances(region="us-east-1")
             def greet(name): return "hello " + name
             x = data.json_parse('{"k":"v"}')
  Shell      ls -la | jq '.name'
             git status && git diff
  Force      !<cmd>   or   $ <cmd>   to force shell mode

VIRTUAL BINARIES (type 'vbins' for full list)
  jq          JSON processor             jq '.name' < file.json
  yq          YAML processor             cat k8s.yaml | yq '.spec'
  http        HTTP client                http https://api.example.com/v1/status
  mirror      Session viewer             mirror list
  cmdgen      Cloud CLI generator        cmdgen aws ec2 create instance_type=t3.micro
  package     Package manager            package install ripgrep
  darkscan    Malware scanner            darkscan /tmp/suspect
  grant       Role escalation            grant request admin

ENVIRONMENT VARIABLES
  ADSSH_RESTRICTED        Enable restricted mode (true/false)
  ADSSH_SERVE             SSH server address (:2222)
  ADSSH_POLICY            Path to Rego policy file
  ADSSH_ENTITLEMENTS      Path to entitlements YAML
  ADSSH_AUDIT_LOG         Audit log path (default: ~/.adssh/audit.log)
  ADSSH_PROFILE           Login profile script (default: ~/.adsshprofile)
  ADSSH_RC                RC script (default: ~/.adsshrc)

Run 'adssh --init' to create a starter config in ~/.adssh/
`)
}

func runInit() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %v", err)
	}

	dir := filepath.Join(home, ".adssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create %s: %v", dir, err)
	}

	files := map[string]string{
		"authorized_keys": "# Add SSH public keys here (one per line) to allow remote access via adssh --serve\n",

		"default.rego": `package adssh

# Default policy: allow everything.
# Replace with your own rules to restrict what users can run.
# See policy/examples/ for more patterns.

default allow = true
`,

		".adsshrc": `# ~/.adssh/.adsshrc — loaded on every interactive session
# This is Starlark (https://bazel.build/rules/language), a safe Python dialect.

# Custom prompt
PROMPT = "adssh> "

# Example: define a Starlark helper available in the REPL
def k8s_pods(namespace="default"):
    result = sys.exec_cmd("kubectl get pods -n " + namespace + " -o json")
    pods = data.json_parse(result)
    for item in pods["items"]:
        print(item["metadata"]["name"])

# Example: register a shell alias as a custom command
# sys.register_command("ll", lambda args: None)  # see docs for full pattern

# Example: load a plugin
# sys.load_plugin("/path/to/myplugin.so")
`,
	}

	created := []string{}
	skipped := []string{}

	for name, content := range files {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			skipped = append(skipped, path)
			continue
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			return fmt.Errorf("cannot write %s: %v", path, err)
		}
		created = append(created, path)
	}

	fmt.Printf("adssh init — %s\n\n", dir)
	for _, f := range created {
		fmt.Printf("  created  %s\n", f)
	}
	for _, f := range skipped {
		fmt.Printf("  exists   %s (not overwritten)\n", f)
	}

	fmt.Printf(`
Next steps:
  1. Edit ~/.adssh/.adsshrc to customize your session
  2. Set ADSSH_RC=~/.adssh/.adsshrc  (or it auto-loads ~/.adsshrc)
  3. Run: adssh
  4. Try: aws.ec2.list_instances(region="us-east-1")
     Or:  ls -la | jq '.'
     Or:  vbins
`)
	return nil
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

