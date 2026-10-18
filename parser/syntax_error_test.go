package parser

import "testing"

func TestSyntaxError(t *testing.T) {
	for _, tc := range []struct {
		line string
		bad  bool
	}{
		{"ls -la", false},
		{"ls --color=auto | grep x", false},
		{`echo "unfinished`, false}, // open quote: still typing
		{"ls |", false},             // trailing pipe: still typing
		{"if true; then", false},    // unfinished compound
		{"x = {", false},            // unfinished Starlark value
		{"def f(x):", false},        // unfinished Starlark block
		{"len([1, 2])", false},      // Starlark, though bad shell
		{"x = 5", false},
		{"echo )", true},     // bad in both
		{"ls ;; ls", true},   // bad in both
		{"x = 5 )", true},    // bad in both
		{"! echo )", true},   // forced shell
		{"$ len([1])", true}, // forced shell: Starlark does not rescue it
		{"", false},
	} {
		if got := SyntaxError(tc.line); got != tc.bad {
			t.Errorf("SyntaxError(%q) = %v, want %v", tc.line, got, tc.bad)
		}
	}
}
