package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
)

// LoadProfiles executes system-wide and user profiles in order.
// profilePath and rcPath come from AppConfig (env vars or defaults).
func LoadProfiles(thread *starlark.Thread, env starlark.StringDict, isLoginShell bool, profilePath, rcPath string) (starlark.StringDict, error) {
	var paths []string

	// Login shell: source POSIX /etc/profile and ~/.profile first,
	// then adssh-specific system profile.
	if isLoginShell {
		sourceShellProfiles()
		paths = append(paths, "/etc/adssh_profile")
	}

	paths = append(paths, profilePath, rcPath)

	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Auto-create the RC file with a starter template
			if strings.HasSuffix(path, ".adsshrc") || path == rcPath {
				_ = os.WriteFile(path, []byte(defaultRC), 0600)
			} else {
				continue
			}
		}

		globals, err := starlark.ExecFile(thread, path, nil, env)
		if err == nil {
			for k, v := range globals {
				env[k] = v
			}
		}
	}
	return env, nil
}

// sourceShellProfiles sources /etc/profile and ~/.profile by running them
// through the system sh and exporting resulting env vars into the current
// process. This is the standard POSIX login-shell behavior.
func sourceShellProfiles() {
	home, _ := os.UserHomeDir()

	candidates := []string{
		"/etc/profile",
		filepath.Join(home, ".profile"),
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}
		// Source the file in a subshell and print the resulting environment.
		// We use 'env' after sourcing so we can parse the exported variables.
		cmd := exec.Command("sh", "-c", ". "+p+" && env")
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		// Parse the output and apply new/changed variables to the current process.
		for _, line := range strings.Split(string(out), "\n") {
			if idx := strings.IndexByte(line, '='); idx > 0 {
				key := line[:idx]
				val := line[idx+1:]
				// Only propagate if not already set (profiles shouldn't override
				// explicit ADSSH_* vars or existing user settings).
				if os.Getenv(key) == "" {
					os.Setenv(key, val)
				}
			}
		}
	}
}

const defaultRC = `# Welcome to Adssh!
# This file is evaluated as Starlark (a Python dialect) on every interactive session.

# 1. Terminal prompt (ANSI colors supported)
PROMPT = "\x1b[32madssh>\x1b[0m "

# 2. Key bindings: "vi" or "emacs"
set_keymap("vi")

# 3. Namespaces available: sys, net, crypto, data, re, sec, i18n, cloud
# Examples:
#   sys.setenv("EDITOR", "vim")
#   sys.load_plugin("~/.adssh/plugins/systemapi.so")
`
