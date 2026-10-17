package repl

import (
	"testing"

	"github.com/afterdarksys/adssh/parser"
	"go.starlark.net/starlark"
)

func TestRefineModeRoutesStarlarkExpressions(t *testing.T) {
	aliases := starlark.NewDict(1)
	_ = aliases.SetKey(starlark.String("ll"), starlark.String("ls -l"))
	globals := starlark.StringDict{
		"x":           starlark.MakeInt(5),
		"sys":         starlark.NewDict(0),
		"aws":         starlark.NewDict(0),
		"ll":          starlark.MakeInt(1), // also an alias: the shell keeps it
		"__aliases__": aliases,
	}
	for _, tc := range []struct {
		line string
		want parser.EvalMode
	}{
		{"x", parser.ModeStarlark},
		{"len([1, 2, 3])", parser.ModeStarlark},
		{"dir(sys)", parser.ModeStarlark},
		{"sys.exec_cmd('echo hi')", parser.ModeStarlark},
		{"aws.ec2.list_instances()", parser.ModeStarlark},
		{"x[0]", parser.ModeStarlark},
		{"x * 21", parser.ModeStarlark},
		{"x > 3", parser.ModeStarlark},
		{"ls > out.txt", parser.ModeShell},
		{"ls -la", parser.ModeShell},            // not a Starlark name
		{"echo hello", parser.ModeShell},        // shell builtin, not a Starlark name
		{"ll", parser.ModeShell},                // an alias wins over the global
		{"type ls", parser.ModeShell},           // Starlark's type, but valid shell for a builtin
		{"help", parser.ModeShell},              // a vbin
		{"! x", parser.ModeShell},               // forced shell
		{"x y", parser.ModeShell},               // not a Starlark expression
		{"undefined_name(1)", parser.ModeShell}, // not bound: left to the shell
	} {
		mode := parser.DetermineMode(tc.line)
		if got := RefineMode(tc.line, mode, globals); got != tc.want {
			t.Errorf("RefineMode(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
