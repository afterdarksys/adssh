package config

import (
	"fmt"
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

	// Profiles run before the REPL exists, so the REPL's set_keymap is not
	// defined yet. This stand-in validates the mode and records it as KEYMAP,
	// which the REPL applies when it starts (the PROMPT convention).
	if _, ok := env["set_keymap"]; !ok {
		env["set_keymap"] = starlark.NewBuiltin("set_keymap", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var mode string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "mode", &mode); err != nil {
				return nil, err
			}
			if mode != "vi" && mode != "emacs" {
				return nil, fmt.Errorf("set_keymap: unknown mode '%s'. Use 'vi' or 'emacs'", mode)
			}
			env["KEYMAP"] = starlark.String(mode)
			return starlark.None, nil
		})
	}

	for _, path := range paths {
		if path == "" {
			continue
		}

		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Auto-create the RC file with a starter template
			if strings.HasSuffix(path, ".adsshrc") || path == rcPath {
				if err := os.WriteFile(path, []byte(defaultRC), 0600); err != nil {
					return env, fmt.Errorf("create profile %s: %w", path, err)
				}
			} else {
				continue
			}
		} else if err != nil {
			return env, fmt.Errorf("stat profile %s: %w", path, err)
		}

		globals, err := starlark.ExecFile(thread, path, nil, env)
		if err != nil {
			return env, fmt.Errorf("load profile %s: %w", path, err)
		}
		for k, v := range globals {
			env[k] = v
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

const defaultRC = `# Welcome to adssh. This file is Starlark (a small Python dialect) and runs at
# the start of every interactive session. examples/adsshrc in the adssh repo
# documents everything it can set. Type "help" at the prompt for more.

# Prompt (ANSI colors work).
PROMPT = "\x1b[32madssh>\x1b[0m "

# Line editing keys: "emacs" (the bash/zsh default) or "vi".
set_keymap("emacs")
`
