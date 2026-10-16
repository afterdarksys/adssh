package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

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

type sshSessionOpts struct {
	sessionID  string
	user       string
	menu       string
	history    string
	profile    string
	rc         string
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
	if !security.RemoteGateEnabled() {
		fmt.Fprintf(os.Stderr, "adssh: ssh session: monitor gate is not installed\n")
		return 1
	}
	overlay := &sys.Session{ID: opts.sessionID, User: opts.user}
	if err := sys.RegisterSession(overlay); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	defer sys.UnregisterSession(opts.sessionID)
	if binaryPath, err := os.Executable(); err == nil {
		_ = os.Setenv("SHELL", binaryPath)
	}
	sys.SetupSignals()
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
		repl.StartMenu(opts.menu, globals, opts.restricted, os.Stdin, os.Stdout, os.Stderr)
	} else {
		repl.Start(globals, opts.restricted, opts.history, os.Stdin, os.Stdout, os.Stderr)
	}
	return 0
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
