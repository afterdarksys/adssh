package config

import (
	"os"
	"strings"

	"go.starlark.net/starlark"
)

// LoadProfiles executes system-wide and user profiles in order.
// profilePath and rcPath come from AppConfig (env vars or defaults).
func LoadProfiles(thread *starlark.Thread, env starlark.StringDict, isLoginShell bool, profilePath, rcPath string) (starlark.StringDict, error) {
	var paths []string

	// Login shell: load system-wide profiles first
	if isLoginShell {
		paths = append(paths, "/etc/profile", "/etc/adssh_profile")
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
