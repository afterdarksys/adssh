package parser

import "testing"

// TestDetermineMode is a characterization test: it pins down the ACTUAL,
// current behavior of DetermineMode's line-level heuristic (see
// parser.go), including known quirks. Cases marked quirk=true document
// heuristic misclassifications that are intentionally NOT "fixed" here —
// see docs/plans/2026-07-16-wave1-security-core-tests.md.
func TestDetermineMode(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  EvalMode
		quirk string // non-empty => documents a known heuristic quirk
	}{
		// --- forced shell prefixes: "!" and "$ " ---
		{name: "bang prefix", input: "!ls -la", want: ModeShell},
		{name: "bang alone", input: "!", want: ModeShell},
		{name: "bang with leading whitespace", input: "   !ls", want: ModeShell},
		{name: "dollar-space prefix", input: "$ ls", want: ModeShell},
		{name: "dollar-space with extra space", input: "$  ls", want: ModeShell},
		{
			name: "dollar without space", input: "$ls", want: ModeShell,
			quirk: "no space after $ so the forced-shell prefix check doesn't match; still ends up ModeShell via the default fallthrough since it contains no '='",
		},
		{
			name: "dollar alone", input: "$", want: ModeShell,
			quirk: "too short to match the 2-char '$ ' prefix; falls through to default shell",
		},

		// --- Starlark keyword prefixes: def/for/if/print( ---
		{name: "def keyword", input: "def foo():", want: ModeStarlark},
		{name: "def with args", input: "def foo(x, y):", want: ModeStarlark},
		{name: "for keyword", input: "for x in range(10):", want: ModeStarlark},
		{name: "for over items", input: "for i in items:", want: ModeStarlark},
		{name: "if keyword", input: "if x > 5:", want: ModeStarlark},
		{name: "if true", input: "if True:", want: ModeStarlark},
		{name: "print call", input: "print(x)", want: ModeStarlark},
		{name: "print call with string", input: "print('hello')", want: ModeStarlark},
		{
			name: "print with space before paren", input: "print (x)", want: ModeShell,
			quirk: "HasPrefix requires the literal 'print(' with no space; 'print (x)' misses the keyword check and, containing no '=', falls through to default shell",
		},
		{
			name: "bare if no trailing space", input: "if", want: ModeShell,
			quirk: "HasPrefix requires 'if ' (with trailing space); a bare 'if' with no space misses the keyword check and falls through to default shell",
		},
		{
			name: "if with parens no space", input: "if(x):", want: ModeShell,
			quirk: "HasPrefix requires 'if ' (with trailing space); 'if(x):' misses the keyword check and, containing no '=', falls through to default shell",
		},
		{
			name: "identifier starting with def but not keyword", input: "definitely_a_var = 10", want: ModeStarlark,
			quirk: "does not match 'def ' prefix (5th char is 'i' not space), but still routes to Starlark via the assignment-contains-'=' check",
		},

		// --- assignment heuristic: contains "=" and does not start with "==" ---
		{name: "assignment with spaces", input: "x = 5", want: ModeStarlark},
		{name: "assignment no spaces", input: "x=5", want: ModeStarlark},
		{name: "assignment expression", input: "y = x + 1", want: ModeStarlark},
		{name: "assignment with surrounding whitespace", input: "  x = 5  ", want: ModeStarlark},
		{
			name: "env-prefix assignment before command", input: "FOO=bar cmd", want: ModeStarlark,
			quirk: "CHARACTERIZATION: this looks like a shell env-prefixed command invocation, but the heuristic only checks for '=' and misroutes it to Starlark",
		},
		{
			name: "env-prefix assignment before shell pipeline", input: "FOO=bar ls -la", want: ModeStarlark,
			quirk: "CHARACTERIZATION: same env-prefix quirk as above — routes to Starlark instead of shell",
		},
		{
			name: "export assignment", input: "export FOO=bar", want: ModeStarlark,
			quirk: "CHARACTERIZATION: 'export FOO=bar' is valid shell syntax but contains '=' so it is misrouted to Starlark",
		},

		// --- "==" comparisons: ACTUAL behavior, not the naively-expected one ---
		{
			name: "bare equality comparison", input: "x == 5", want: ModeStarlark,
			quirk: "CHARACTERIZATION: the '==' exclusion only checks whether the TRIMMED LINE ITSELF starts with '==', not whether the '=' occurrence is part of '=='. 'x == 5' contains '=' and does not start with '==', so it is routed to ModeStarlark, not shell as one might naively expect",
		},
		{
			name: "line literally starting with ==", input: "==5", want: ModeShell,
			quirk: "this is the only shape the '==' exclusion actually catches: HasPrefix(trimmed, \"==\") is true here, so the assignment branch is skipped and it falls through to default shell",
		},
		{
			name: "not-equal comparison", input: "x != 5", want: ModeStarlark,
			quirk: "CHARACTERIZATION: '!=' contains the '=' rune and doesn't start with '==', so it is also misrouted to ModeStarlark",
		},
		{
			name: "bracket-test equality", input: "[ $x == 5 ]", want: ModeStarlark,
			quirk: "CHARACTERIZATION: POSIX test-bracket syntax with '==' is misrouted to ModeStarlark for the same reason as the bare comparison case",
		},
		{name: "if-guard with equality (keyword wins)", input: "if x == 5:", want: ModeStarlark},

		// --- plain commands / pipelines / empty / whitespace -> shell ---
		{name: "simple command", input: "ls -la", want: ModeShell},
		{name: "git status", input: "git status", want: ModeShell},
		{name: "pipeline with jq", input: "ls -la | jq '.name'", want: ModeShell},
		{name: "grep command", input: "grep -r 'pattern' file.txt", want: ModeShell},
		{name: "echo with var", input: "echo $HOME", want: ModeShell},
		{name: "chained commands", input: "cd /tmp && ls", want: ModeShell},
		{name: "kubectl command", input: "kubectl get pods", want: ModeShell},
		{name: "aws cli command", input: "aws s3 ls", want: ModeShell},
		{name: "redirect to file", input: "ls -la > output.txt", want: ModeShell},
		{name: "curl piped to jq", input: "curl -s https://example.com | jq '.'", want: ModeShell},
		{name: "git log piped to head", input: "git log --oneline | head -5", want: ModeShell},
		{name: "empty string", input: "", want: ModeShell},
		{name: "whitespace only spaces", input: "   ", want: ModeShell},
		{name: "whitespace only tabs", input: "\t\t", want: ModeShell},
		{name: "command with trailing newline-like whitespace", input: "  ls -la  ", want: ModeShell},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetermineMode(tc.input)
			if got != tc.want {
				t.Errorf("DetermineMode(%q) = %v, want %v%s", tc.input, got, tc.want, quirkSuffix(tc.quirk))
			}
			if tc.quirk != "" {
				t.Logf("quirk: %s", tc.quirk)
			}
		})
	}
}

func quirkSuffix(quirk string) string {
	if quirk == "" {
		return ""
	}
	return " (quirk: " + quirk + ")"
}
