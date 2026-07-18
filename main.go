package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.starlark.net/resolve"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/syntax"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/internal/config"
	"github.com/afterdarksys/adssh/internal/repl"
	"github.com/afterdarksys/adssh/internal/starlarkext"
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/parser"
	"github.com/afterdarksys/adssh/security"
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
	doctorFlag := false

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case arg == "-h" || arg == "--help":
			printHelp()
			return
		case arg == "--doctor":
			doctorFlag = true
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

	if doctorFlag {
		if code := runDoctor(cfg); code != 0 {
			os.Exit(code)
		}
		return
	}

	// 3. Build the security engine from configuration. Construction is
	// FAIL-CLOSED: a malformed policy or an unreadable entitlements file aborts
	// startup rather than silently running unprotected. A missing policy file
	// still falls back to allow-by-default (RequirePolicy is left unset).
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	xdgDataHome := config.XDGDataHome()
	eng, err := engine.New(engine.Config{
		EngineConfig: security.EngineConfig{
			PolicyPath:       cfg.PolicyPath,
			AuditLogPath:     cfg.AuditLogPath,
			AuditLogURL:      cfg.AuditURL,
			AuditLogToken:    cfg.AuditToken,
			ChainPath:        cfg.AuditLogPath + ".chain",
			ChainKeyPath:     filepath.Join(xdgDataHome, "audit.key"),
			SessionID:        sessionID,
			EntitlementsPath: cfg.EntitlementsPath,
			Restricted:       cfg.Restricted,
		},
		ProfilePath:  cfg.ProfilePath,
		RCPath:       cfg.RCPath,
		HistoryFile:  cfg.HistoryFile,
		IsLoginShell: cfg.IsLoginShell,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "adssh: %v\n", err)
		os.Exit(1)
	}

	// TODO(engine-facade): the SSH server (sshStarter/repl.Start), the Starlark
	// exec builtins (starlarkext/exec.go, job.go) and the REPL completer still
	// resolve the process-global default engine. Point the default at the engine
	// we just built so those paths authorize through the same policy, audit log
	// and hash chain as the sessions opened below — until repl/ and starlarkext/
	// accept an *engine.Engine directly.
	security.SetDefaultEngine(eng.Security())

	if cfg.EntitlementsPath != "" {
		eng.Security().LogEvent(fmt.Sprintf("Entitlements loaded from %s", cfg.EntitlementsPath))
	}
	if _, statErr := os.Stat(cfg.PolicyPath); statErr == nil {
		eng.Security().LogEvent(fmt.Sprintf("Policy loaded from %s", cfg.PolicyPath))
	}

	// 4. Setup signal handling and terminal
	sys.SetupSignals()
	if err := sys.InitTerminal(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to initialize terminal: %v\n", err)
	}

	// 5. Open the single-user session for the interactive / -c / script paths.
	// The engine builds its globals fresh; the login/RC profiles are then layered
	// on top so ~/.adsshprofile and ~/.adsshrc customisations still apply.
	sess, err := eng.NewSession(engine.SessionOptions{
		SessionID:   sessionID,
		Restricted:  cfg.Restricted,
		In:          os.Stdin,
		Out:         os.Stdout,
		Err:         os.Stderr,
		HistoryFile: cfg.HistoryFile,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "adssh: failed to open session: %v\n", err)
		os.Exit(1)
	}
	thread := sess.Thread
	env := sess.Globals
	if _, perr := config.LoadProfiles(thread, env, cfg.IsLoginShell, cfg.ProfilePath, cfg.RCPath); perr != nil {
		fmt.Fprintf(os.Stderr, "Error loading profiles: %v\n", perr)
	}

	// sshStarter builds each SSH session's OWN isolated globals (fresh
	// SetupExtensions, its own aliases/custom-commands/shopts/plugins dicts and
	// directory stack) rather than sharing/shallow-copying the base env. The RC
	// profile is re-loaded per session so ~/.adsshrc customisations still apply.
	// TODO(session): SSH sessions intentionally do not receive the
	// enable_ssh/disable_ssh builtins injected into the single-user env below.
	sshStarter := func(sessionID, user string, principals []string, in io.ReadCloser, out, errOut io.Writer) {
		sessGlobals := starlark.StringDict{}
		starlarkext.SetupExtensions(starlarkext.ExtensionOptions{
			Env:        sessGlobals,
			Restricted: cfg.Restricted,
			SessionID:  sessionID,
			In:         in,
			Out:        out,
			Err:        errOut,
		})
		sessThread := &starlark.Thread{Name: "ssh-" + sessionID}
		if _, perr := config.LoadProfiles(sessThread, sessGlobals, false, cfg.ProfilePath, cfg.RCPath); perr != nil {
			fmt.Fprintf(errOut, "Error loading profiles: %v\n", perr)
		}
		if menuPath := eng.Security().GetMenuForUser(user, principals); menuPath != "" {
			repl.StartMenu(menuPath, sessGlobals, cfg.Restricted, in, out, errOut)
			return
		}
		repl.Start(sessGlobals, cfg.Restricted, cfg.HistoryFile, in, out, errOut)
	}

	// 6b. Inject SSH management builtins into `sys` dict
	if sysVal, ok := env["sys"]; ok {
		if sysDict, ok := sysVal.(*starlark.Dict); ok {
			enableSSH := starlark.NewBuiltin("enable_ssh", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var addr string
				if err := starlark.UnpackArgs(b.Name(), args, kwargs, "address", &addr); err != nil {
					return nil, err
				}
				if err := sys.EnableSSH(addr, cfg.HostKeyPath, cfg.AuthorizedKeysPath, sshStarter); err != nil {
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
			_ = sysDict.SetKey(starlark.String("enable_ssh"), enableSSH)
			_ = sysDict.SetKey(starlark.String("disable_ssh"), disableSSH)
		}
	}

	// 7. Dispatch to the appropriate execution mode

	// 7a. -c flag: evaluate a single expression/command and exit
	if cmdFlag != "" {
		if err := evalOnce(sess, cmdFlag); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		return
	}

	if cfg.ServeAddr != "" {
		if err := sys.EnableSSH(cfg.ServeAddr, cfg.HostKeyPath, cfg.AuthorizedKeysPath, sshStarter); err != nil {
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
		smartReplWrapper(eng, env, cfg.Restricted, cfg.HistoryFile, os.Stdin, os.Stdout, os.Stderr)
	}
}

// evalOnce evaluates a single expression or command (for -c flag) against the
// engine-bound session, so it passes through the same policy/audit/chain
// machinery as the REPL: Starlark runs on the session thread/globals, shell runs
// on the session's engine-authorized runner.
func evalOnce(sess *engine.Session, src string) error {
	security.LogCommand(src, "")

	mode := parser.DetermineMode(src)

	if mode == parser.ModeStarlark {
		// Try expression first
		val, err := starlark.Eval(sess.Thread, "<-c>", src, sess.Globals)
		if err == nil {
			if val != nil && val != starlark.None {
				fmt.Println(val.String())
			}
			return nil
		}
		// Fall back to statement (def, assignment, etc.)
		if _, err2 := starlark.ExecFile(sess.Thread, "<-c>", src, sess.Globals); err2 != nil {
			return fmt.Errorf("starlark error: %v", err2)
		}
		return nil
	}

	// Shell mode — run through this session's engine-authorized runner.
	f, parseErr := syntax.NewParser().Parse(strings.NewReader(src), "")
	if parseErr != nil {
		return fmt.Errorf("parse error: %v", parseErr)
	}
	if err := sess.GateProgram(f); err != nil {
		return fmt.Errorf("command error: %v", err)
	}
	if err := sess.Runner.Run(context.Background(), f); err != nil {
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
      --doctor                Check local configuration and readiness
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

type doctorCheck struct {
	Status  string
	Name    string
	Details string
}

func runDoctor(cfg config.AppConfig) int {
	checks := []doctorCheck{}
	failures := 0

	add := func(status, name, details string) {
		checks = append(checks, doctorCheck{Status: status, Name: name, Details: details})
		if status == "FAIL" {
			failures++
		}
	}

	addPathCheck := func(name, path string, required bool) {
		if path == "" {
			if required {
				add("FAIL", name, "path is empty")
			} else {
				add("WARN", name, "not configured")
			}
			return
		}
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) && !required {
				add("WARN", name, fmt.Sprintf("%s does not exist", path))
				return
			}
			add("FAIL", name, fmt.Sprintf("%s: %v", path, err))
			return
		}
		if info.IsDir() {
			add("FAIL", name, fmt.Sprintf("%s is a directory", path))
			return
		}
		add("OK", name, path)
	}

	addWritableDirCheck := func(name, path string) {
		if path == "" {
			add("FAIL", name, "path is empty")
			return
		}
		dir := filepath.Dir(path)
		info, err := os.Stat(dir)
		if err != nil {
			add("FAIL", name, fmt.Sprintf("%s: %v", dir, err))
			return
		}
		if !info.IsDir() {
			add("FAIL", name, fmt.Sprintf("%s is not a directory", dir))
			return
		}
		f, err := os.CreateTemp(dir, ".adssh-doctor-*")
		if err != nil {
			add("FAIL", name, fmt.Sprintf("%s is not writable: %v", dir, err))
			return
		}
		tmp := f.Name()
		_ = f.Close()
		_ = os.Remove(tmp)
		add("OK", name, fmt.Sprintf("%s is writable", dir))
	}

	fmt.Println("adssh doctor")
	fmt.Println()

	if exe, err := os.Executable(); err == nil {
		add("OK", "binary", exe)
	} else {
		add("WARN", "binary", fmt.Sprintf("cannot resolve executable: %v", err))
	}

	cfgDir := config.XDGConfigHome()
	if info, err := os.Stat(cfgDir); err == nil && info.IsDir() {
		add("OK", "config directory", cfgDir)
	} else if err == nil {
		add("FAIL", "config directory", fmt.Sprintf("%s is not a directory", cfgDir))
	} else if os.IsNotExist(err) {
		add("WARN", "config directory", fmt.Sprintf("%s does not exist; run adssh --init", cfgDir))
	} else {
		add("FAIL", "config directory", fmt.Sprintf("%s: %v", cfgDir, err))
	}

	addWritableDirCheck("audit log directory", cfg.AuditLogPath)
	addWritableDirCheck("history directory", cfg.HistoryFile)
	addPathCheck("rc script", cfg.RCPath, false)
	addPathCheck("login profile", cfg.ProfilePath, false)

	if _, err := os.Stat(cfg.PolicyPath); err != nil {
		if os.IsNotExist(err) {
			add("WARN", "policy", fmt.Sprintf("%s does not exist; running with allow-all fallback", cfg.PolicyPath))
		} else {
			add("FAIL", "policy", fmt.Sprintf("%s: %v", cfg.PolicyPath, err))
		}
	} else if err := security.LoadPolicy(cfg.PolicyPath); err != nil {
		add("FAIL", "policy", fmt.Sprintf("%s: %v", cfg.PolicyPath, err))
	} else {
		pctx := security.BuildPolicyContext("true", []string{}, "")
		if allowed, reason, err := security.EvaluatePolicy(pctx); err != nil {
			add("FAIL", "policy", fmt.Sprintf("evaluation failed: %v", err))
		} else if !allowed {
			if reason == "" {
				reason = "sample command denied"
			}
			add("WARN", "policy", fmt.Sprintf("%s compiled, but denies a sample command: %s", cfg.PolicyPath, reason))
		} else {
			add("OK", "policy", fmt.Sprintf("%s compiles", cfg.PolicyPath))
		}
	}

	if cfg.ServeAddr != "" {
		if os.Geteuid() != 0 {
			add("FAIL", "ssh server", "adssh --serve currently requires root")
		} else {
			add("OK", "ssh server", "running as root")
		}
		addPathCheck("authorized_keys", cfg.AuthorizedKeysPath, true)
	} else {
		addPathCheck("authorized_keys", cfg.AuthorizedKeysPath, false)
	}

	for _, tool := range []string{"ssh", "git", "docker", "kubectl"} {
		if path, err := exec.LookPath(tool); err == nil {
			add("OK", "host tool: "+tool, path)
		} else {
			add("WARN", "host tool: "+tool, "not found in PATH")
		}
	}

	for _, check := range checks {
		fmt.Printf("%-4s  %-22s %s\n", check.Status, check.Name, check.Details)
	}
	fmt.Println()

	if failures > 0 {
		fmt.Printf("%d readiness check(s) failed.\n", failures)
		return 1
	}
	fmt.Println("No failing readiness checks.")
	return 0
}

func runInit() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %v", err)
	}

	dir := config.XDGConfigHome()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create %s: %v", dir, err)
	}

	files := map[string]string{
		"authorized_keys": "# Add SSH public keys here (one per line) to allow remote access via adssh --serve\n",

		"policy.rego": `package adssh.authz

# Default policy: allow everything.
# Replace with your own rules to restrict what users can run.
# See policy/examples/ for more patterns.

default allow = true
default deny_reason = ""
`,
	}

	rcPath := filepath.Join(home, ".adsshrc")
	rcContent := `# ~/.adsshrc — loaded on every interactive session
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
`

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

	if _, err := os.Stat(rcPath); err == nil {
		skipped = append(skipped, rcPath)
	} else {
		if err := os.WriteFile(rcPath, []byte(rcContent), 0600); err != nil {
			return fmt.Errorf("cannot write %s: %v", rcPath, err)
		}
		created = append(created, rcPath)
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
  1. Edit ~/.adsshrc to customize your session
  2. Run: adssh --doctor
  3. Run: adssh
  4. Try: aws.ec2.list_instances(region="us-east-1")
     Or:  ls -la | jq '.'
     Or:  vbins
`)
	return nil
}

func smartReplWrapper(eng *engine.Engine, globals starlark.StringDict, restricted bool, historyFile string, in io.ReadCloser, out io.Writer, errOut io.Writer) {
	var sessionID string
	if val, ok := globals["SESSION_ID"]; ok {
		if strVal, ok := val.(starlark.String); ok {
			sessionID = string(strVal)
		}
	}

	if sessionID != "" {
		if session := sys.GetSession(sessionID); session != nil {
			menuPath := eng.Security().GetMenuForUser(session.User, session.Principals)
			if menuPath != "" {
				repl.StartMenu(menuPath, globals, restricted, in, out, errOut)
				return
			}
		}
	}

	repl.Start(globals, restricted, historyFile, in, out, errOut)
}
