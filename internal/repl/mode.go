package repl

import (
	"os/exec"
	"regexp"
	"strings"

	"github.com/afterdarksys/adssh/parser"
	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
	starsyntax "go.starlark.net/syntax"
	"mvdan.cc/sh/v3/interp"
	shsyntax "mvdan.cc/sh/v3/syntax"
)

// leadingName is the first identifier of a line.
var leadingName = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\b`)

// RefineMode sends to Starlark a line that parser.DetermineMode gave to the
// shell when it is plainly a Starlark expression: its first name is a
// Starlark global or builtin (x, len(...), sys.exec_cmd(...),
// aws.ec2.list_instances()) and the line parses as a Starlark expression.
// The shell keeps it when it is valid shell and its first name is something
// the shell would run: an alias, a registered command, a vbin, a shell
// builtin, or a program on PATH. ! and "$ " still force the shell. Anything
// else keeps the mode it was given.
func RefineMode(line string, mode parser.EvalMode, globals starlark.StringDict) parser.EvalMode {
	if mode != parser.ModeShell {
		return mode
	}
	m := leadingName.FindStringSubmatch(line)
	if m == nil {
		return mode
	}
	name := m[1]
	if _, ok := globals[name]; !ok {
		if _, ok := starlark.Universe[name]; !ok {
			return mode
		}
	}
	if _, err := starsyntax.ParseExpr("<line>", line, 0); err != nil {
		return mode
	}
	// A line the shell cannot parse, such as dir(sys), is Starlark even when
	// the name is also a program (/usr/bin/dir).
	if _, err := shsyntax.NewParser().Parse(strings.NewReader(line), ""); err != nil {
		return parser.ModeStarlark
	}
	if shellRunsName(name, globals) {
		return mode
	}
	return parser.ModeStarlark
}

// shellRunsName reports whether the shell would run name as a command.
func shellRunsName(name string, globals starlark.StringDict) bool {
	for _, bag := range []string{"__aliases__", "__custom_commands__"} {
		if d, ok := globals[bag].(*starlark.Dict); ok {
			if _, found, _ := d.Get(starlark.String(name)); found {
				return true
			}
		}
	}
	if _, ok := security.Lookup(name); ok {
		return true
	}
	if interp.IsBuiltin(name) {
		return true
	}
	_, err := exec.LookPath(name)
	return err == nil
}
