package parser

import (
	"strings"
)

// EvalMode indicates whether to run via Starlark or standard OS shell
type EvalMode int

const (
	ModeStarlark EvalMode = iota
	ModeShell
)

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

	if strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "==") {
		// likely assignment e.g. x = 5
		return ModeStarlark
	}

	// Default to shell for commands like "ls -la"
	return ModeShell
}
