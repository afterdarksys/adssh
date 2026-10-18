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

// spacedAssignRe matches the start of a spaced Starlark assignment, x = ...,
// cfg.port = ... or d["k"] = ...: a target, whitespace, one '=', whitespace.
// No shell command is written that way, so a line of this shape that does not
// parse is a Starlark mistake (s = {1, 2}), not a program named s.
var spacedAssignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]*\])*[ \t]+=[ \t]`)

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
	// load( is Starlark too: adssh has no load(), and Starlark says so,
	// where the shell would look for a program named load.
	if strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "for ") || strings.HasPrefix(trimmed, "print(") || strings.HasPrefix(trimmed, "load(") {
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
		if starlarkLine(trimmed) || spacedAssignRe.MatchString(trimmed) {
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
		return (strings.Contains(msg, "got end of file") || strings.Contains(msg, "unexpected EOF")) && OpensBlock(line)
	}
	for _, stmt := range f.Stmts {
		if a, ok := stmt.(*syntax.AssignStmt); ok && !assignable(a.LHS) {
			return false
		}
	}
	return true
}

// OpensBlock reports whether src was cut off by what it left open: a
// bracket, a string, or a trailing : or \ on its last non-blank line. The
// first line of a multi-line value or block does (x = {, a, b = (,
// doc = """start); ls --color=auto / ends early on a trailing operator and
// does not. Brackets and quotes in a # comment do not count. The mode router
// and the multi-line collectors share it, so a line routed to Starlark as
// unfinished is also read as unfinished.
// Threats: a block's first line routed to the shell, or a block cut short by
// its collector, makes each later line its own chunk, so a body line such as
// "reboot" would run as a command.
func OpensBlock(src string) bool {
	depth := 0
	var quote string
	for i := 0; i < len(src); i++ {
		c := src[i]
		if quote != "" {
			switch {
			case c == '\\':
				i++
			case c == '\n' && len(quote) == 1:
				quote = "" // a one-quote string cannot span lines
			case strings.HasPrefix(src[i:], quote):
				i += len(quote) - 1
				quote = ""
			}
			continue
		}
		switch c {
		case '#':
			for i+1 < len(src) && src[i+1] != '\n' {
				i++
			}
		case '"', '\'':
			quote = string(c)
			if strings.HasPrefix(src[i:], strings.Repeat(quote, 3)) {
				quote = strings.Repeat(quote, 3)
				i += 2
			}
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		}
	}
	if depth > 0 || quote != "" {
		return true
	}
	last := strings.TrimRight(src, " \t\r\n")
	return strings.HasSuffix(last, ":") || strings.HasSuffix(last, "\\")
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
