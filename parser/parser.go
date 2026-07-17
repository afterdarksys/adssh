package parser

import (
	"regexp"
	"strings"
)

// EvalMode indicates whether to run via Starlark or standard OS shell
type EvalMode int

const (
	ModeStarlark EvalMode = iota
	ModeShell
)

// envPrefixCmdRe matches a shell env-prefix command invocation, e.g.
// "FOO=bar cmd" or "DEBUG=1 make test": an identifier, '=', a value with no
// whitespace, then whitespace and at least one more token (the command).
var envPrefixCmdRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=[^ \t]*[ \t]+\S`)

func DetermineMode(line string) EvalMode {
	trimmed := strings.TrimSpace(line)

	// If it starts with ! or $, force shell
	if strings.HasPrefix(trimmed, "!") || strings.HasPrefix(trimmed, "$ ") {
		return ModeShell
	}

	// Heuristics for Starlark
	if strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "for ") || strings.HasPrefix(trimmed, "if ") || strings.HasPrefix(trimmed, "print(") {
		return ModeStarlark
	}

	// Shell shapes that would otherwise be misrouted by the '=' heuristic below.
	// POSIX test brackets, e.g. "[ $x == 5 ]".
	if strings.HasPrefix(trimmed, "[") {
		return ModeShell
	}
	// Shell export statement, e.g. "export FOO=bar".
	if strings.HasPrefix(trimmed, "export ") {
		return ModeShell
	}
	// Env-prefix command invocation, e.g. "FOO=bar cmd" / "DEBUG=1 make test".
	// A bare "x=5" (no trailing command) does not match and still routes to
	// Starlark via the assignment heuristic below.
	if envPrefixCmdRe.MatchString(trimmed) {
		return ModeShell
	}

	if strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "==") {
		// likely assignment e.g. x = 5
		return ModeStarlark
	}

	// Default to shell for commands like "ls -la"
	return ModeShell
}
