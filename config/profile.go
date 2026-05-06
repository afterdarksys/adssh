package config

import (
	"os"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
)

// LoadProfiles executes system-wide and user profiles.
func LoadProfiles(thread *starlark.Thread, env starlark.StringDict, isLoginShell bool) (starlark.StringDict, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return env, err
	}

	var profilePaths []string

	// If invoked as a login shell (e.g. via sshd or getty with `-adssh`), load global profiles first.
	if isLoginShell {
		profilePaths = append(profilePaths, "/etc/profile")
		profilePaths = append(profilePaths, "/etc/adssh_profile")
	}

	// Always load user profiles
	profilePaths = append(profilePaths, filepath.Join(home, ".adsshprofile"))
	profilePaths = append(profilePaths, filepath.Join(home, ".adsshrc"))

	for _, path := range profilePaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if strings.HasSuffix(path, ".adsshrc") {
				defaultRc := `
# Welcome to Adssh! 
# This file is parsed as pure Starlark (a Python dialect).

# 1. Set your terminal prompt (Supports ANSI colors)
PROMPT = "\x1b[32madssh>\x1b[0m "

# 2. Configure your Terminal bindings (vi or emacs)
set_keymap("vi")

# 3. Use the sys, net, sec, and data namespaces
# sys.setenv("EDITOR", "vim")
`
				os.WriteFile(path, []byte(defaultRc), 0600)
			} else {
				continue
			}
		}

		if _, err := os.Stat(path); err == nil {
			globals, err := starlark.ExecFile(thread, path, nil, env)
			if err == nil {
				for k, v := range globals {
					env[k] = v
				}
			}
		}
	}
	return env, nil
}
