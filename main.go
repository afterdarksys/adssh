package main

import (
	"fmt"
	"os"
	"strings"

	"go.starlark.net/resolve"
	"go.starlark.net/starlark"

	"adssh/config"
	"adssh/repl"
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
	var restricted bool
	var serveAddr string
	var scriptPath string

	// Check if invoked as a login shell
	isLoginShell := strings.HasPrefix(os.Args[0], "-")

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "-r" || arg == "--restricted" {
			restricted = true
		} else if arg == "-l" || arg == "--login" {
			// explicitly set as login shell via flag
			isLoginShell = true
		} else if arg == "--serve" && i+1 < len(os.Args) {
			serveAddr = os.Args[i+1]
			i++
		} else if !strings.HasPrefix(arg, "-") && scriptPath == "" {
			scriptPath = arg
		}
	}

	// 1. Setup Signal Handling
	sys.SetupSignals()

	// 2. Setup Terminal and Ioctl
	err := sys.InitTerminal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to initialize terminal: %v\n", err)
	}

	// 3. Load configuration (~/.adshprofile and ~/.adshrc)
	thread := &starlark.Thread{Name: "main"}
	globals := starlark.StringDict{}
	// Inject standard library extensions
	starlarkext.SetupExtensions(globals, restricted)

	env, err := config.LoadProfiles(thread, globals, isLoginShell)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading profiles: %v\n", err)
	}

	// 4. Handle Execution Mode
	if serveAddr != "" {
		sys.StartSSHServer(serveAddr, env, restricted, repl.Start)
	} else if scriptPath != "" {
		_, err := starlark.ExecFile(thread, scriptPath, nil, env)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
			os.Exit(1)
		}
	} else {
		repl.Start(env, restricted, os.Stdin, os.Stdout, os.Stderr)
	}
}
