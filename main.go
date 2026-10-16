package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strings"
	"time"

	"go.starlark.net/resolve"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/internal/agent"
	"github.com/afterdarksys/adssh/internal/config"

	// grid registers the grid, flight, agent, worktree, and repo vbins.
	_ "github.com/afterdarksys/adssh/internal/grid"
	"github.com/afterdarksys/adssh/internal/guard"
	"github.com/afterdarksys/adssh/internal/repl"
	"github.com/afterdarksys/adssh/internal/sah"
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
	sys.MaybeRunSessionChild()
	if err := sys.ConfigureHostFromEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "adssh: %v\n", err)
		os.Exit(1)
	}
	if isSSHSessionArgv(os.Args) {
		os.Exit(runSSHSession(os.Args))
	}

	// 0. Set SHELL env var for POSIX compliance — child processes need this
	if binaryPath, err := os.Executable(); err == nil {
		os.Setenv("SHELL", binaryPath)
	}

	// 1. Load configuration from ADSSH_* environment variables (provides defaults)
	cfg := config.LoadFromEnv()
	logSettings, err := config.ParseLogSettings(os.Getenv("ADSSH_LOG_LEVEL"), os.Getenv("ADSSH_LOG_FORMAT"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "adssh: %v\n", err)
		os.Exit(2)
	}
	// The standard log package routes through this logger too.
	slog.SetDefault(config.NewLogger(os.Stderr, logSettings))

	// 2. Parse CLI flags — flags override env vars
	cfg.IsLoginShell = strings.HasPrefix(os.Args[0], "-")

	var cmdFlag string // -c "expression"
	doctorFlag := false
	sahMode := false

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
		case (arg == "--serve-agent") && i+1 < len(os.Args):
			cfg.AgentServeAddr = os.Args[i+1]
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
		case arg == "sah" && cfg.ScriptPath == "" && cmdFlag == "":
			sahMode = true
		case !strings.HasPrefix(arg, "-") && cfg.ScriptPath == "" && !sahMode:
			cfg.ScriptPath = arg
		}
	}

	// Disabled sah/1 exits before the engine starts and before the frame is read.
	if sahMode && !cfg.SAHEnabled {
		os.Exit(sah.Handle(false, nil, os.Stdout, nil))
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

	// TODO(engine-facade): the Starlark exec builtins (starlarkext/exec.go,
	// job.go) and the REPL completer still resolve the process-global default
	// engine. Point the default at the engine we just built so those paths
	// authorize through the same policy, audit log and hash chain as the
	// sessions opened below — until repl/ and starlarkext/ accept an
	// *engine.Engine directly.
	security.SetDefaultEngine(eng.Security())
	// sessionID here is the SSH login the listener bound. It is not the local REPL id.
	sys.SetSSHMonitorServer(sshMonitorServer(eng.Security()))
	guard.SetRecorder(func(ev guard.Event) {
		// The guard has already applied the ban; it stands even when the
		// record fails, so the failure is reported rather than dropped.
		if err := eng.Security().LogEvent(fmt.Sprintf("GUARD action=%s addr=%s reason=%s", ev.Action, ev.Addr, ev.Reason)); err != nil {
			fmt.Fprintf(os.Stderr, "adssh: guard audit write failed: %v\n", err)
		}
	})
	if err := guard.Configure(guard.Options{
		ConfigPath: cfg.GuardConfigPath,
		StatePath:  cfg.GuardStatePath,
		Switch:     cfg.GuardSwitch,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "adssh: guard: %v\n", err)
		if cfg.ServeAddr != "" {
			os.Exit(1)
		}
	}

	// The local process identity is the OS account this binary runs as, taken
	// from the kernel, not from $USER, which the caller can set to anything.
	localUser, localGroups, err := localIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "adssh: %v\n", err)
		os.Exit(1)
	}

	if sahMode {
		// sah never registers a session, so the identity is bound on the
		// engine directly; an unbound session id is denied as unknown. The
		// REPL below registers its session instead, so elevation and agent
		// claims from the registry stay visible to policy.
		if err := eng.Security().BindSessionIdentity(sessionID, localUser, localGroups); err != nil {
			fmt.Fprintf(os.Stderr, "adssh: %v\n", err)
			os.Exit(1)
		}
		os.Exit(runSAH(eng.Security(), sessionID))
	}

	// An audit log that cannot record startup cannot record commands either.
	if cfg.EntitlementsPath != "" {
		if err := eng.Security().LogEvent(fmt.Sprintf("Entitlements loaded from %s", cfg.EntitlementsPath)); err != nil {
			fmt.Fprintf(os.Stderr, "adssh: audit: %v\n", err)
			os.Exit(1)
		}
	}
	if _, statErr := os.Stat(cfg.PolicyPath); statErr == nil {
		if err := eng.Security().LogEvent(fmt.Sprintf("Policy loaded from %s", cfg.PolicyPath)); err != nil {
			fmt.Fprintf(os.Stderr, "adssh: audit: %v\n", err)
			os.Exit(1)
		}
	}

	// 4. Setup signal handling and terminal
	sys.SetupSignals()
	if err := sys.InitTerminal(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to initialize terminal: %v\n", err)
	}

	outCast := sys.NewOutputBroadcaster(os.Stdout)
	localSession := &sys.Session{
		ID:   sessionID,
		User: localUser,
		Out:  outCast,
	}
	if err := sys.RegisterSession(localSession); err != nil {
		fmt.Fprintf(os.Stderr, "adssh: %v\n", err)
		os.Exit(1)
	}
	defer sys.UnregisterSession(sessionID)

	// 5. Open the single-user session for the interactive / -c / script paths.
	// The engine builds its globals fresh; the login/RC profiles are then layered
	// on top so ~/.adsshprofile and ~/.adsshrc customisations still apply.
	sess, err := eng.NewSession(engine.SessionOptions{
		SessionID:   sessionID,
		Restricted:  cfg.Restricted,
		In:          os.Stdin,
		Out:         outCast,
		Err:         os.Stderr,
		HistoryFile: cfg.HistoryFile,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "adssh: failed to open session: %v\n", err)
		os.Exit(1)
	}
	thread := sess.Thread
	env := sess.Globals
	starlarkext.GovernStarlarkGlobalsInPlace(eng.Security(), env)
	if _, perr := config.LoadProfiles(thread, env, cfg.IsLoginShell, cfg.ProfilePath, cfg.RCPath); perr != nil {
		fmt.Fprintf(os.Stderr, "Error loading profiles: %v\n", perr)
	}

	// sshStarter execs one session process per SSH login. The listener keeps
	// the socket, host key, session table, and audit files. The child is the
	// REPL. SSH sessions do not receive enable_ssh or disable_ssh.
	sshStarter := func(sessionID, user string, principals []string, in io.ReadCloser, out, errOut io.Writer) error {
		slave, ok := in.(*os.File)
		if !ok {
			fmt.Fprintf(errOut, "adssh: ssh session: pty is not a file\n")
			return errors.New("ssh session: pty is not a file")
		}
		// The certificate principals are the session's groups for its
		// life; grant cannot add to them. Elevation still merges in.
		if err := eng.Security().BindSessionIdentity(sessionID, user, principals); err != nil {
			fmt.Fprintf(errOut, "adssh: %v\n", err)
			return err
		}
		defer eng.Security().UnbindSessionIdentity(sessionID)
		// History, profile, and rc paths come from the target user's home,
		// not from this listener's config.
		err := sys.SpawnSSHSession(sys.SSHSessionSpec{
			SessionID:  sessionID,
			User:       user,
			Principals: principals,
			Restricted: cfg.Restricted,
			MenuPath:   eng.Security().GetMenuForUser(user, principals),
			PluginDir:  security.ConfiguredPluginDir(),
			PTY:        slave,
		})
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				fmt.Fprintf(errOut, "adssh: %v\n", err)
			}
		}
		return err
	}
	gatewayAuthorizer := func(req sys.GatewayAuthRequest) error {
		return eng.Security().AuthorizeGateway(directTCPIPPolicyRequest(req))
	}

	// 6b. Inject SSH management builtins into `sys` dict
	if sysVal, ok := env["sys"]; ok {
		enableSSH := starlark.NewBuiltin("enable_ssh", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var addr string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "address", &addr); err != nil {
				return nil, err
			}
			if err := enableSSHWithHangup(func() error {
				return sys.EnableSSHWithOptions(addr, cfg.HostKeyPath, cfg.AuthorizedKeysPath, sys.SSHServerOptions{PermitRoot: cfg.SSHPermitRoot, Audit: eng.Security().LogEvent}, sshStarter, gatewayAuthorizer)
			}); err != nil {
				return nil, err
			}
			return starlark.None, nil
		})
		disableSSH := starlark.NewBuiltin("disable_ssh", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := disableSSHClearHangup(sys.DisableSSH); err != nil {
				return nil, err
			}
			return starlark.None, nil
		})
		enableSSHVal := starlarkext.GovernStarlarkValue(eng.Security(), "starlark.sys.enable_ssh", enableSSH)
		disableSSHVal := starlarkext.GovernStarlarkValue(eng.Security(), "starlark.sys.disable_ssh", disableSSH)
		switch sysDict := sysVal.(type) {
		case *starlark.Dict:
			_ = sysDict.SetKey(starlark.String("enable_ssh"), enableSSHVal)
			_ = sysDict.SetKey(starlark.String("disable_ssh"), disableSSHVal)
		case *starlarkext.GovernedStarlarkDict:
			_ = sysDict.SetKey(starlark.String("enable_ssh"), enableSSHVal)
			_ = sysDict.SetKey(starlark.String("disable_ssh"), disableSSHVal)
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
		if err := sys.EnableSSHWithOptions(cfg.ServeAddr, cfg.HostKeyPath, cfg.AuthorizedKeysPath, sys.SSHServerOptions{PermitRoot: cfg.SSHPermitRoot, Audit: eng.Security().LogEvent}, sshStarter, gatewayAuthorizer); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start SSH server: %v\n", err)
			os.Exit(1)
		}
		// SIGHUP on the listener stops new logins and leaves running SSH
		// sessions alone instead of exiting.
		onHangup(listenerHangup)
	}

	// Instrumentation agent: a hardened HTTP listener that runs only NAMED,
	// pre-approved, read-only tasks from the allowlist, each through the same
	// policy + audit chokepoint. It fails closed — no token configured, a
	// malformed tasks file, or a bind failure aborts startup. Bind should be
	// localhost or behind TLS (see docs/INSTRUMENT-AGENT.md).
	if cfg.AgentServeAddr != "" {
		if _, err := agent.Start(cfg.AgentServeAddr, cfg.AgentToken, cfg.AgentTasksPath); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start instrumentation agent: %v\n", err)
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
		if strings.HasSuffix(cfg.ScriptPath, ".adssh") {
			if err := evalLineScript(sess, content); err != nil {
				fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
				os.Exit(1)
			}
		} else {
			if _, err := starlark.ExecFile(thread, cfg.ScriptPath, []byte(content), env); err != nil {
				fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
				os.Exit(1)
			}
		}
	} else {
		smartReplWrapper(eng, env, cfg.Restricted, cfg.HistoryFile, os.Stdin, outCast, os.Stderr)
	}
}

// evalOnce evaluates a single expression or command (for -c flag) against the
// engine-bound session, so it passes through the same policy/audit/chain
// machinery as the REPL: Starlark runs on the session thread/globals, shell runs
// on the session's engine-authorized runner.
func evalOnce(sess *engine.Session, src string) error {
	if err := security.LogCommand(src, ""); err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	flow := parser.ClassifyFlow(src)
	switch flow.Kind {
	case parser.FlowReady:
		err := repl.RunFlow(src, repl.FlowExec{
			Gate:   sess.GateProgram,
			Runner: sess.Runner,
			Ctx:    context.Background(),
		})
		status := 0
		if err != nil {
			if es, ok := err.(interp.ExitStatus); ok {
				status = int(es)
				sess.Globals["?"] = starlark.MakeInt(status)
				return es
			}
			sess.Globals["?"] = starlark.MakeInt(1)
			return err
		}
		sess.Globals["?"] = starlark.MakeInt(status)
		return nil
	case parser.FlowIncomplete, parser.FlowSyntax:
		if flow.Err != nil {
			return flow.Err
		}
		return errors.New("flow: not a block")
	}

	mode := parser.DetermineMode(src)

	if mode == parser.ModeStarlark {
		// Parse decides expression or statements, so src runs exactly once.
		val, isExpr, newBindings, err := repl.EvalStarlarkOnce(sess.Thread, "<-c>", src, sess.Globals)
		if err != nil {
			return fmt.Errorf("starlark error: %v", err)
		}
		if isExpr && val != nil && val != starlark.None {
			fmt.Println(val.String())
		}
		// A def or assignment in one script chunk is visible to the next.
		// Reserved session names are not merged.
		repl.MergeStarlarkBindings(sess.Globals, newBindings, sess.Err)
		return nil
	}

	// Shell mode — run through this session's engine-authorized runner.
	if strings.HasPrefix(src, "!") {
		src = strings.TrimSpace(src[1:])
	} else if strings.HasPrefix(src, "$ ") {
		src = strings.TrimSpace(src[2:])
	}
	if parser.ShellIncomplete(src) {
		return parser.ErrIncompleteShell
	}
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

func evalLineScript(sess *engine.Session, src string) error {
	return repl.AccumulateScript(src, func(chunk string, line int, ignore bool) error {
		if err := evalOnce(sess, chunk); err != nil {
			if ignore {
				fmt.Fprintln(sess.Err, err)
				return nil
			}
			return fmt.Errorf("line %d: %w", line, err)
		}
		return nil
	})
}

func runSAH(sec *security.Engine, sessionID string) int {
	return sah.Handle(true, os.Stdin, os.Stdout, func(command []string) (string, string, int, error) {
		return sahExecute(sec, sessionID, command)
	})
}

func sahExecute(sec *security.Engine, sessionID string, command []string) (string, string, int, error) {
	if sec == nil || !sec.PolicyLoaded() {
		return "", "", 0, errors.New("policy_required")
	}
	argv0 := command[0]
	base := argv0
	if strings.Contains(argv0, "/") {
		base = filepath.Base(argv0)
	}
	switch base {
	case "adssh", "sah", "adssh-mcp":
		return "", "", 0, errors.New("command_rejected")
	}
	if _, ok := sec.Lookup(argv0); ok {
		return "", "", 0, errors.New("command_rejected")
	}
	if err := sec.AuthorizeCommand(command, sessionID); err != nil {
		return "", "", 0, errors.New("policy_denied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	// The child sees an allowlisted environment, never the listener's
	// ADSSH_* settings or tokens, and its output is capped while it runs so a
	// policy-allowed `yes` cannot grow memory for the 30 seconds.
	cmd.Env = sahChildEnv()
	cmd.WaitDelay = 2 * time.Second
	stdout := &sahCappedBuffer{limit: sahOutputCap}
	stderr := &sahCappedBuffer{limit: sahOutputCap}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	runErr := cmd.Run()
	out := security.RedactSensitiveText(stdout.String())
	errOut := security.RedactSensitiveText(stderr.String())
	if runErr == nil {
		return out, errOut, 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return out, errOut, exitErr.ExitCode(), nil
	}
	return "", "", 0, errors.New("execute_failed")
}

// localIdentity resolves the account this process runs as and its group
// names. A resolution failure is an error, not a fallback to $USER.
func localIdentity() (string, []string, error) {
	u, err := osuser.Current()
	if err != nil {
		return "", nil, fmt.Errorf("resolve local user: %v", err)
	}
	if u.Username == "" {
		return "", nil, errors.New("resolve local user: empty username")
	}
	var groups []string
	if gids, err := u.GroupIds(); err == nil {
		for _, gid := range gids {
			if g, err := osuser.LookupGroupId(gid); err == nil {
				groups = append(groups, g.Name)
			}
		}
	}
	return u.Username, groups, nil
}

// sahOutputCap bounds each of stdout and stderr captured from a sah child.
// The frame response caps again at 4 KiB; this cap exists so the buffer
// stops growing while the child is still running.
const sahOutputCap = 64 * 1024

// sahChildEnv is the environment a sah child receives: locale and path only,
// plus the caller's HOME, USER and LOGNAME. Nothing named ADSSH_* and no
// token-looking variable crosses into the child.
func sahChildEnv() []string {
	env := make([]string, 0, 8)
	for _, name := range []string{"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "TERM"} {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// sahCappedBuffer keeps the first limit bytes written and reports every write
// as complete so the child is not killed with EPIPE.
type sahCappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *sahCappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.buf.Write(p)
	}
	return n, nil
}

func (b *sahCappedBuffer) String() string { return b.buf.String() }

func printHelp() {
	fmt.Print(`adssh — programmable DevOps shell

USAGE
  adssh [options] [script.star|script.adssh]

OPTIONS
  -h, --help                  Show this help
      --init                  Create ~/.adssh/ with starter config and exit
      --doctor                Check local configuration and readiness
  -r, --restricted            Restricted mode (no path traversal, no cd/export)
  -l, --login                 Login shell (load ~/.adsshprofile)
      --serve <addr>          Start built-in SSH server (e.g. --serve :2222)
      --serve-agent <addr>    Start instrumentation-agent HTTP listener
                              (e.g. --serve-agent 127.0.0.1:7777; needs
                              ADSSH_AGENT_TOKEN, runs only allowlisted tasks)
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
  mirror      Session supervisor         mirror list
  admin       Local admin API            admin sessions --json
  identity    OIDC / SSH CA identity     identity status
  sah         sah/1 stdio (ADSSH_SAH)    ADSSH_SAH=1 adssh sah
  gateway     Policy TCP gateway         gateway start --target host:22
  lease       Command secret lease       lease --from vault:path?field=token --as TOKEN -- cmd
  guard       SSH listener jail          guard status
  elevate     Break-glass elevation      elevate request prod-admin --for 10m --reason INC
  grid        sah-grid membership        grid status
  flight      Witnessed change           flight place --id F --agent A --worktree W --for 10m
  agent       Supervised cloud agent     agent status
  worktree    Pinned checkout            worktree checkout --id W --from PATH --rev SHA
  ??          Last denial explainer      ??
  cmdgen      Cloud CLI generator        cmdgen aws ec2 create instance_type=t3.micro
  package     Package manager            package install ripgrep
  darkscan    Malware scanner            darkscan /tmp/suspect
  grant       Role escalation            grant request admin

ENVIRONMENT VARIABLES
  ADSSH_SAH               sah/1 stdio switch (1/true/yes; default off)
  ADSSH_GIT_PROMPT        Git branch in the \g prompt escape (1/true/yes/on; default off)
  ADSSH_RESTRICTED        Enable restricted mode (true/false)
  ADSSH_SERVE             SSH server address (:2222)
  ADSSH_SSH_PERMIT_ROOT   Allow SSH login as root or any uid-0 name (1/true/yes; default off)
  ADSSH_GUARD             SSH listener jail switch (off/on; unset follows guard.yaml)
  ADSSH_GUARD_CONFIG      Jail config (default: ~/.adssh/guard.yaml)
  ADSSH_GUARD_STATE       Ban file (default: ~/.adssh/guard-state.json)
  ADSSH_POLICY            Path to Rego policy file
  ADSSH_ENTITLEMENTS      Path to entitlements YAML
  ADSSH_AUDIT_LOG         Audit log path (default: ~/.adssh/audit.log)
  ADSSH_AUDIT_URL         SIEM webhook (https; host checked at send time, private needs ADSSH_CALLBACK_ALLOW_PRIVATE)
  ADSSH_CONTROLPLANE_URL  Device-login control plane origin (https; unset fails closed)
  ADSSH_OIDC_ISSUER       OIDC issuer for identity oidc import (unset fails closed)
  ADSSH_OIDC_JWKS_URL     https JWKS URL for that issuer
  ADSSH_OIDC_ADMIN_ISSUER Issuer for identity oidc import --provider admin
  ADSSH_OIDC_ADMIN_JWKS_URL https JWKS URL for the admin issuer
  ADSSH_OIDC_LOGIN_AUDIENCE Required aud for identity oidc import (unset fails closed)
  ADSSH_OIDC_ADMIN_AUDIENCE Required aud for --provider admin (unset fails closed)
  ADSSH_CALLBACK_ALLOW_PRIVATE Allow private-range callback hosts (1/true/yes; default off)
  ADSSH_AGENT_SERVE       Instrumentation-agent HTTP address (127.0.0.1:7777)
  ADSSH_AGENT_TOKEN       Bearer token for the instrumentation agent (required)
  ADSSH_AGENT_TASKS       Task allowlist (default: ~/.adssh/instrument-tasks.yaml)
  ADSSH_RECORD_DIR        Session recording directory (default: ~/.adssh/recordings)
  ADSSH_PROFILE           Login profile script (default: ~/.adsshprofile)
  ADSSH_RC                RC script (default: ~/.adsshrc)
  ADSSH_ADMIN_KEYS        admin serve named-key file, enterprise build (0600 name=key; approve/deny/unban)
  ADSSH_LOG_LEVEL         Listener log level: error|warn|info|debug (default info; stderr)
  ADSSH_LOG_FORMAT        Listener log format: text|json (default text)
  ADSSH_SNOOP_NOTIFY      Snoop attach notice default for support (on|off; default on)
  ADSSH_SNOOP_NOTIFY_LOCK Force the snoop notice over policy (on; default off)

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

	if off, on, err := guard.ParseSwitch(cfg.GuardSwitch); err != nil {
		add("FAIL", "guard switch", err.Error())
	} else if off {
		add("OK", "guard switch", "forced off")
	} else if on {
		add("OK", "guard switch", "forced on")
	} else {
		add("OK", "guard switch", "follows guard.yaml")
	}
	if info, err := os.Lstat(cfg.GuardConfigPath); err != nil && os.IsNotExist(err) {
		add("WARN", "guard config", fmt.Sprintf("%s does not exist; defaults apply", cfg.GuardConfigPath))
	} else if err != nil {
		add("FAIL", "guard config", fmt.Sprintf("%s: %v", cfg.GuardConfigPath, err))
	} else if err := guard.CheckConfig(cfg.GuardConfigPath); err != nil {
		add("FAIL", "guard config", err.Error())
	} else if info.Mode()&os.ModeSymlink != 0 {
		add("FAIL", "guard config", fmt.Sprintf("%s is a symlink", cfg.GuardConfigPath))
	} else {
		add("OK", "guard config", cfg.GuardConfigPath)
	}
	if err := guard.CheckState(cfg.GuardStatePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			add("OK", "guard state", "no ban file yet")
		} else {
			add("FAIL", "guard state", err.Error())
		}
	} else {
		add("OK", "guard state", cfg.GuardStatePath)
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

// defaultInstrumentTasks is the starter instrumentation-agent allowlist written
// by --init. It ships FAIL-CLOSED: the active allowlist is empty (every task is
// 404) until an operator deliberately adds entries. The commented examples show
// the grammar. Only add NAMED, read-only virtual binaries here — the network
// names only the task; the vbin + args below are fixed and never client-supplied.
const defaultInstrumentTasks = `# adssh instrumentation-agent task allowlist
#
# The control-plane API names ONLY a task; the virtual binary and its arguments
# come from this file and are NEVER taken from the request. Allowlist only
# genuinely read-only tasks. This is not a remote shell.
#
# Grammar:
#   tasks:
#     <task-name>:
#       vbin: <virtual-binary-name>   # must be a registered adssh vbin
#       args: [<fixed>, <args>]       # fixed args passed to the vbin
#       description: <text>           # shown by GET /v1/tasks
#       risk: <label>                 # advisory; threaded into the policy AgentClaim
#
# Ships empty (deny-everything) on purpose. Uncomment / add entries you trust.
# Example (Linux; 'proc get' is read-only — never allowlist 'proc set'):
#
#   loadavg:
#     vbin: proc
#     args: ["get", "/proc/loadavg"]
#     description: "System load average (1/5/15 min)"
#     risk: low
#   meminfo:
#     vbin: proc
#     args: ["get", "/proc/meminfo"]
#     description: "Kernel memory statistics"
#     risk: low

tasks: {}
`

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
		"authorized_keys": "# SSH public keys for adssh --serve, one per line.\n" +
			"# Each key must name the logins it may use:\n" +
			"#   user=\"alice\" ssh-ed25519 AAAA... alice@laptop\n" +
			"#   user=\"alice,deploy\" ssh-ed25519 AAAA... shared\n" +
			"# A line without user= is refused. Root needs ADSSH_SSH_PERMIT_ROOT=1.\n" +
			"# CA keys: cert-authority ssh-ed25519 AAAA... (certs bind by principal)\n",

		"policy.rego": `package adssh.authz

# Default policy: allow everything.
# Replace with your own rules to restrict what users can run.
# See policy/examples/ for more patterns.

default allow = true
default deny_reason = ""
`,

		"instrument-tasks.yaml": defaultInstrumentTasks,

		"guard.yaml": `# SSH listener jail. See docs/guard.md.
# Manage with the guard command (status, config, list, unban, reload)
# or the local admin API (GET /v1/guard, POST /v1/guard/unban).
# This file is not a firewall rule.
enabled: true
find_time: 10m
max_retry: 5
ban_time: 1h
rate_limit: 30
rate_window: 1m
max_entries: 10000
ignore:
  - 127.0.0.0/8
  - ::1/128
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
			menuPath := eng.Security().GetMenuForUser(session.User, session.PrincipalList())
			if menuPath != "" {
				repl.StartMenu(menuPath, globals, restricted, in, out, errOut)
				return
			}
		}
	}

	repl.Start(globals, restricted, historyFile, in, out, errOut)
}

// directTCPIPPolicyRequest maps a listener direct-tcpip check to one gateway
// policy decision: the requested name and the address it resolved to are
// both in the input.
func directTCPIPPolicyRequest(req sys.GatewayAuthRequest) security.GatewayPolicyRequest {
	return security.GatewayPolicyRequest{
		SessionID:  req.SessionID,
		User:       req.User,
		Groups:     req.Principals,
		Action:     "direct-tcpip",
		TargetHost: req.TargetHost,
		TargetIP:   req.TargetIP,
		TargetPort: req.TargetPort,
	}
}

// onHangup is sys.OnHangup; tests replace it.
var onHangup = sys.OnHangup

// enableSSHWithHangup starts the SSH listener and, once it is running, makes
// SIGHUP stop accepting connections instead of exiting the process.
func enableSSHWithHangup(enable func() error) error {
	if err := enable(); err != nil {
		return err
	}
	onHangup(listenerHangup)
	return nil
}

// disableSSHClearHangup stops the SSH listener and restores the default
// SIGHUP action (propagate to jobs, exit).
func disableSSHClearHangup(disable func() error) error {
	if err := disable(); err != nil {
		return err
	}
	onHangup(nil)
	return nil
}

// listenerHangup is the --serve SIGHUP action: stop accepting SSH
// connections, keep the running sessions and this process.
func listenerHangup() {
	if err := sys.StopAcceptingSSH(); err != nil {
		fmt.Fprintf(os.Stderr, "adssh: SIGHUP: %v\n", err)
		return
	}
	fmt.Fprintln(os.Stderr, "adssh: SIGHUP: no longer accepting SSH connections; running sessions continue")
}

// sshMonitorServer serves one SSH login's monitor socket against sec. Authorize
// and Run are gated by the same AuthorizeCommandContext; Run executes the
// virtual binary here, in the listener, under the session the socket is bound
// to. A Cancel frame ends the gate's four-eyes wait.
func sshMonitorServer(sec *security.Engine) func(conn net.Conn, sessionID string) {
	return func(conn net.Conn, sessionID string) {
		gate := func(ctx context.Context, args []string) error {
			if sys.GetSession(sessionID) == nil {
				return errors.New("adssh: ssh monitor: session is gone")
			}
			return sec.AuthorizeCommandContext(ctx, args, sessionID)
		}
		run := func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
			return sec.RunVBinForSession(ctx, sessionID, args, stdin, stdout, stderr)
		}
		security.ServeSSHMonitorRun(conn, sessionID, gate, run)
	}
}
