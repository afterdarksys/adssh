package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"go.starlark.net/starlark"

	"github.com/afterdarksys/adssh/internal/config"
	"github.com/afterdarksys/adssh/internal/repl"
	"github.com/afterdarksys/adssh/internal/starlarkext"
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"
)

// Threats: an SSH login is a separate process. The child does not open the
// audit log and does not choose its session id. A missing monitor, a failed
// ping, or a missing gate exits before the REPL. The listener evaluates
// policy. File, network, and cloud builtins that do not pass the gate stay
// in this process: they run as the dropped uid and under the session rlimits,
// and they are policy-bypassable. A native exploit can still execve. Argument
// errors do not include the value. This process must not construct an engine
// or replace the default engine. The listener's gate is the monitor client.
// SIGINT and SIGQUIT are caught here, not ignored, so the commands this
// process runs get the default disposition; the PTY's ISIG delivers Ctrl-C
// to the foreground process group. SIGTSTP, SIGTTIN, and SIGTTOU stay
// ignored in this process for job control; the --session-child wrapper
// resets them for wrapped commands, and a command run with every session
// limit at zero keeps them ignored. The environment and working directory
// are the listener's allowlist for the target user. After the gate is
// installed the process is marked: every local policy evaluation denies.
// Vbins that change engine or session state or explain policy (elevate, cm,
// grant, 4eyes, why, ??, ...) are sent to the listener as monitor Run frames;
// the listener gates and runs them under the session it bound, so this
// process cannot pick the identity they run as. lease, repo, plugin load,
// mirror view and console, and path-taking subcommands stay refused and are
// recorded by the listener as denied (see security/ssh_monitor.go). SIGINT
// during an Authorize or Run sends Cancel, which ends a pending four-eyes
// wait in the listener. --plugin-dir is the listener's configured plugin
// directory, so plugin list shows it; plugins are not loaded here.

type sshSessionOpts struct {
	sessionID  string
	user       string
	menu       string
	history    string
	profile    string
	rc         string
	pluginDir  string
	principals []string
	restricted bool
}

func isSSHSessionArgv(args []string) bool {
	return len(args) >= 2 && args[1] == "--ssh-session"
}

func runSSHSession(args []string) int {
	opts, err := parseSSHSessionArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	// Non-dumpable before anything else runs: another process with this
	// uid cannot read this process's environment or ptrace it to reach the
	// monitor socket, which carries this session's policy identity. Not
	// covered: the moment between exec and this call.
	if err := sys.SetNonDumpable(); err != nil {
		fmt.Fprintf(os.Stderr, "adssh: ssh session: %v\n", err)
		return 1
	}
	file, err := sys.OpenMonitorFD(3)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	client := sys.NewMonitorClient(sys.NewMonitorConn(file))
	if err := client.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "adssh: ssh session: monitor did not answer\n")
		return 1
	}
	security.SetRemoteGate(func(_ bool, argv []string, _ string) error {
		return client.Authorize(argv)
	})
	security.SetRemoteRun(client.Run)
	if !security.RemoteGateEnabled() {
		fmt.Fprintf(os.Stderr, "adssh: ssh session: monitor gate is not installed\n")
		return 1
	}
	// Local policy evaluation and state-changing vbins are refused from here on.
	security.MarkRemoteGateProcess()
	overlay := newSSHOverlaySession(opts)
	if err := sys.RegisterSession(overlay); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	defer sys.UnregisterSession(opts.sessionID)
	if opts.pluginDir != "" {
		_ = os.Setenv("ADSSH_PLUGIN_DIR", opts.pluginDir)
	}
	if binaryPath, err := os.Executable(); err == nil {
		_ = os.Setenv("SHELL", binaryPath)
	}
	sys.SetupSignals()
	// SIGINT also cancels the running command's context and the in-flight
	// monitor request.
	installSessionSignals(overlay, client.Cancel)
	globals := starlark.StringDict{}
	starlarkext.SetupExtensions(starlarkext.ExtensionOptions{
		Env:        globals,
		Restricted: opts.restricted,
		SessionID:  opts.sessionID,
		In:         os.Stdin,
		Out:        os.Stdout,
		Err:        os.Stderr,
	})
	starlarkext.GovernStarlarkGlobalsInPlace(security.DefaultEngine(), globals)
	thread := &starlark.Thread{Name: "ssh-" + opts.sessionID}
	if _, err := config.LoadProfiles(thread, globals, false, opts.profile, opts.rc); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading profiles: %v\n", err)
	}
	if opts.menu != "" {
		repl.StartMenu(opts.menu, globals, opts.restricted, opts.history, os.Stdin, os.Stdout, os.Stderr)
	} else {
		repl.Start(globals, opts.restricted, opts.history, os.Stdin, os.Stdout, os.Stderr)
	}
	return 0
}

// newSSHOverlaySession is the child's view of the listener's session. The
// principals are the listener's --principal values.
func newSSHOverlaySession(opts sshSessionOpts) *sys.Session {
	return &sys.Session{
		ID:         opts.sessionID,
		User:       opts.user,
		Principals: append([]string(nil), opts.principals...),
	}
}

func parseSSHSessionArgs(args []string) (sshSessionOpts, error) {
	if !isSSHSessionArgv(args) {
		return sshSessionOpts{}, errors.New("adssh: ssh session: invalid value")
	}
	var opts sshSessionOpts
	var gotID, gotUser, gotFD, gotHistory, gotProfile, gotRC bool
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--restricted":
			opts.restricted = true
		case "--monitor-fd":
			if i+1 >= len(args) || args[i+1] != "3" {
				return sshSessionOpts{}, errors.New("adssh: ssh session: monitor fd must be 3")
			}
			gotFD = true
			i++
		case "--session-id":
			v, err := nextSessionValue(args, &i)
			if err != nil {
				return sshSessionOpts{}, err
			}
			opts.sessionID = v
			gotID = true
		case "--ssh-user":
			v, err := nextSessionValue(args, &i)
			if err != nil {
				return sshSessionOpts{}, err
			}
			opts.user = v
			gotUser = true
		case "--menu":
			v, err := nextSessionValue(args, &i)
			if err != nil {
				return sshSessionOpts{}, err
			}
			opts.menu = v
		case "--history":
			v, err := nextSessionValue(args, &i)
			if err != nil {
				return sshSessionOpts{}, err
			}
			opts.history = v
			gotHistory = true
		case "--profile":
			v, err := nextSessionValue(args, &i)
			if err != nil {
				return sshSessionOpts{}, err
			}
			opts.profile = v
			gotProfile = true
		case "--rc":
			v, err := nextSessionValue(args, &i)
			if err != nil {
				return sshSessionOpts{}, err
			}
			opts.rc = v
			gotRC = true
		case "--plugin-dir":
			v, err := nextSessionValue(args, &i)
			if err != nil {
				return sshSessionOpts{}, err
			}
			if !filepath.IsAbs(v) {
				return sshSessionOpts{}, errors.New("adssh: ssh session: invalid value")
			}
			opts.pluginDir = filepath.Clean(v)
		case "--principal":
			v, err := nextSessionValue(args, &i)
			if err != nil {
				return sshSessionOpts{}, err
			}
			opts.principals = append(opts.principals, v)
		default:
			return sshSessionOpts{}, errors.New("adssh: ssh session: invalid value")
		}
	}
	if !gotID || !gotUser || !gotFD || !gotHistory || !gotProfile || !gotRC {
		return sshSessionOpts{}, errors.New("adssh: ssh session: invalid value")
	}
	return opts, nil
}

func nextSessionValue(args []string, i *int) (string, error) {
	if *i+1 >= len(args) {
		return "", errors.New("adssh: ssh session: invalid value")
	}
	*i++
	v := args[*i]
	if v == "" || strings.IndexByte(v, 0) >= 0 || strings.HasPrefix(v, "-") {
		return "", errors.New("adssh: ssh session: invalid value")
	}
	return v, nil
}

// installSessionSignals catches SIGINT and SIGQUIT in the session process.
// A caught signal is reset to the default by execve and an ignored one is
// not, so commands this process runs die on Ctrl-C and Ctrl-\ while this
// process survives (SetupSignals catches them too). SIGINT also cancels the
// running command's context and calls cancelMonitor, when set.
func installSessionSignals(overlay *sys.Session, cancelMonitor func()) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		for sig := range ch {
			if sig == syscall.SIGINT {
				overlay.CancelCommand()
				if cancelMonitor != nil {
					cancelMonitor()
				}
			}
		}
	}()
}
