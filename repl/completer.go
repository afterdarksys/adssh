package repl

import (
	"os"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
)

// adsshCompleter implements readline.AutoCompleter.
// It completes:
//   - First word: virtual binaries, shell builtins, Starlark namespace names,
//     and dynamically registered custom commands / plugin names.
//   - Starlark namespace.method (e.g. "sys.ge" → "sys.getenv")
//   - mirror / cmdgen subcommands
//   - File paths for all other arguments
type adsshCompleter struct {
	globals starlark.StringDict
}

var virtualBinaries = []string{"jq", "yq", "http", "mirror", "cmdgen"}

var shellBuiltins = []string{
	"cd", "export", "exit", "quit", "echo", "ls", "cat", "grep",
	"find", "which", "env", "pwd", "mkdir", "rm", "cp", "mv",
	"chmod", "chown", "ps", "kill", "jobs", "bg", "fg",
}

var starlarkNamespaces = []string{
	"sys", "net", "crypto", "data", "re", "sec", "i18n", "cloud", "plugins",
}

// starlarkNamespaceKeys maps namespace → list of method names.
var starlarkNamespaceKeys = map[string][]string{
	"sys":    {"getenv", "setenv", "load_plugin", "read_file", "write_file", "exec_cmd", "exec_async", "exec_json", "register_command"},
	"net":    {"tcp_send", "http_get"},
	"crypto": {"md5", "sha256"},
	"data":   {"json_parse", "json_dump", "yaml_parse", "yaml_dump"},
	"re":     {"match", "pcre_match"},
	"sec":    {"audit", "is_restricted", "file_hash"},
	"i18n":   {"load", "set_lang", "T"},
	"cloud":  {"gen"},
}

var mirrorSubcmds = []string{"list", "view", "console"}
var cmdgenProviders = []string{"docker", "kubectl", "aws"}

// Do implements readline.AutoCompleter.
// length is the number of runes before pos that form the current token.
// Each element of newLine is the suffix to append (full candidate minus the already-typed prefix).
func (c *adsshCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	lineStr := string(line[:pos])

	// ── Starlark namespace.method completion ────────────────────────────────
	// Matches patterns like "sys.ge" or "x = sys.ge" anywhere in the line.
	if dotIdx := strings.LastIndex(lineStr, "."); dotIdx >= 0 {
		afterDot := lineStr[dotIdx+1:]
		beforeDot := lineStr[:dotIdx]

		// The namespace is the last whitespace-delimited token before the dot.
		parts := strings.Fields(beforeDot)
		var ns string
		if len(parts) > 0 {
			ns = parts[len(parts)-1]
		} else {
			ns = beforeDot
		}

		if keys, ok := starlarkNamespaceKeys[ns]; ok {
			var completions [][]rune
			for _, k := range keys {
				if strings.HasPrefix(k, afterDot) {
					completions = append(completions, []rune(k[len(afterDot):]))
				}
			}
			return completions, len(afterDot)
		}
	}

	words := strings.Fields(lineStr)
	endsWithSpace := len(lineStr) > 0 && lineStr[len(lineStr)-1] == ' '

	// ── First word: command completion ──────────────────────────────────────
	if len(words) == 0 || (len(words) == 1 && !endsWithSpace) {
		prefix := ""
		if len(words) == 1 {
			prefix = words[0]
		}
		return c.completeCommand(prefix)
	}

	cmd := words[0]
	argPrefix := ""
	completingArg := !endsWithSpace && len(words) >= 2
	if completingArg {
		argPrefix = words[len(words)-1]
	}

	// ── mirror subcommands ───────────────────────────────────────────────────
	if cmd == "mirror" && len(words) <= 2 {
		var completions [][]rune
		for _, s := range mirrorSubcmds {
			if strings.HasPrefix(s, argPrefix) {
				completions = append(completions, []rune(s[len(argPrefix):]))
			}
		}
		return completions, len(argPrefix)
	}

	// ── cmdgen providers ─────────────────────────────────────────────────────
	if cmd == "cmdgen" && len(words) <= 2 {
		var completions [][]rune
		for _, s := range cmdgenProviders {
			if strings.HasPrefix(s, argPrefix) {
				completions = append(completions, []rune(s[len(argPrefix):]))
			}
		}
		return completions, len(argPrefix)
	}

	// ── Default: file path completion ────────────────────────────────────────
	return c.completeFile(argPrefix)
}

// completeCommand returns suffix completions for the first word on the line.
func (c *adsshCompleter) completeCommand(prefix string) ([][]rune, int) {
	seen := make(map[string]bool)
	var candidates []string

	for _, name := range virtualBinaries {
		if !seen[name] {
			seen[name] = true
			candidates = append(candidates, name)
		}
	}
	for _, name := range shellBuiltins {
		if !seen[name] {
			seen[name] = true
			candidates = append(candidates, name)
		}
	}
	for _, name := range starlarkNamespaces {
		if !seen[name] {
			seen[name] = true
			candidates = append(candidates, name)
		}
	}

	// Dynamically registered custom commands
	if c.globals != nil {
		if dictVal, ok := c.globals["__custom_commands__"]; ok {
			if dict, ok := dictVal.(*starlark.Dict); ok {
				for _, kv := range dict.Items() {
					if name, ok := kv[0].(starlark.String); ok {
						s := string(name)
						if !seen[s] {
							seen[s] = true
							candidates = append(candidates, s)
						}
					}
				}
			}
		}
		// Plugin namespace names (so "plugins[" completes to plugin names)
		if pluginsVal, ok := c.globals["plugins"]; ok {
			if dict, ok := pluginsVal.(*starlark.Dict); ok {
				for _, kv := range dict.Items() {
					if name, ok := kv[0].(starlark.String); ok {
						s := "plugins[\"" + string(name) + "\"]"
						if !seen[s] {
							seen[s] = true
							candidates = append(candidates, s)
						}
					}
				}
			}
		}
	}

	var completions [][]rune
	for _, name := range candidates {
		if strings.HasPrefix(name, prefix) {
			completions = append(completions, []rune(name[len(prefix):]))
		}
	}
	return completions, len(prefix)
}

// completeFile returns suffix completions for a partial file path.
func (c *adsshCompleter) completeFile(prefix string) ([][]rune, int) {
	var dir, base string

	if prefix == "" || strings.HasSuffix(prefix, "/") {
		dir = prefix
		if dir == "" {
			dir = "."
		}
		base = ""
	} else {
		dir = filepath.Dir(prefix)
		base = filepath.Base(prefix)
	}

	// Expand leading ~
	expandedDir := dir
	if strings.HasPrefix(dir, "~") {
		if homeDir, err := os.UserHomeDir(); err == nil {
			expandedDir = homeDir + dir[1:]
		}
	}

	entries, err := os.ReadDir(expandedDir)
	if err != nil {
		return nil, 0
	}

	var completions [][]rune
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, base) {
			continue
		}
		suffix := name[len(base):]
		if entry.IsDir() {
			suffix += "/"
		}
		completions = append(completions, []rune(suffix))
	}
	return completions, len(base)
}
