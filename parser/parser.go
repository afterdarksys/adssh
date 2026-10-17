package parser

import (
	"regexp"
	"strings"

	"go.starlark.net/syntax"
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

	// `if expr:` stays Starlark. POSIX if/then and brace if stay on the shell
	// parser. A bare `if` or `if(` misses this keyword and falls through.
	if ifKeyword(trimmed) {
		if posixIfBeforeBrace(trimmed) {
			return ModeShell
		}
		if starlarkIf(trimmed) {
			return ModeStarlark
		}
		return ModeShell
	}

	// Heuristics for Starlark
	if strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "for ") || strings.HasPrefix(trimmed, "print(") {
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
		// An = alone does not make Starlark: ls --color=auto, echo a=b,
		// dd if=x of=y and docker run -e A=b are shell. The line is Starlark
		// when it parses as Starlark with assignable targets (x = 5,
		// d["k"] = 1, a, b = 1, 2) or is the unfinished start of a block
		// (x = {).
		if starlarkLine(trimmed) {
			return ModeStarlark
		}
		return ModeShell
	}

	// Default to shell for commands like "ls -la"
	return ModeShell
}

var starlarkLineOptions = &syntax.FileOptions{Set: true, While: true, TopLevelControl: true, GlobalReassign: true, Recursion: true}

// starlarkLine reports whether line is Starlark: it parses and every
// assignment target is assignable, or it is cut off at end of input (the
// first line of a multi-line value or block).
func starlarkLine(line string) bool {
	f, err := starlarkLineOptions.Parse("<line>", line, 0)
	if err != nil {
		msg := err.Error()
		return strings.Contains(msg, "got end of file") || strings.Contains(msg, "unexpected EOF")
	}
	for _, stmt := range f.Stmts {
		if a, ok := stmt.(*syntax.AssignStmt); ok && !assignable(a.LHS) {
			return false
		}
	}
	return true
}

// assignable reports whether e can be assigned to: a name, x.attr, x[k], or
// a tuple or list of those. The parser accepts ls --color=auto as an
// assignment to ls - -color; the resolver would reject it later.
func assignable(e syntax.Expr) bool {
	switch e := e.(type) {
	case *syntax.Ident, *syntax.DotExpr, *syntax.IndexExpr:
		return true
	case *syntax.ParenExpr:
		return assignable(e.X)
	case *syntax.TupleExpr:
		for _, x := range e.List {
			if !assignable(x) {
				return false
			}
		}
		return len(e.List) > 0
	case *syntax.ListExpr:
		for _, x := range e.List {
			if !assignable(x) {
				return false
			}
		}
		return len(e.List) > 0
	}
	return false
}
