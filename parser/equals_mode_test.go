package parser

import "testing"

// A shell line with = in an argument is shell; a Starlark assignment, or the
// unfinished first line of a Starlark value, is Starlark.
func TestEqualsInShellArgumentsStaysShell(t *testing.T) {
	for _, tc := range []struct {
		line string
		want EvalMode
	}{
		{"ls --color=auto /tmp", ModeShell},
		{"echo a=b", ModeShell},
		{"echo pipefail=$?", ModeShell},
		{"env A=b printenv A", ModeShell},
		{"grep -c x= /dev/null", ModeShell},
		{"dd if=/dev/zero of=z bs=1 count=1", ModeShell},
		{"docker run -e A=b img", ModeShell},
		{"cmd --opt=1 && other", ModeShell},
		{"git config user.name=ryan", ModeShell},
		{"x = 5", ModeStarlark},
		{"x=5", ModeStarlark},
		{"x += 1", ModeStarlark},
		{"a, b = 1, 2", ModeStarlark},
		{"d['k'] = 1", ModeStarlark},
		{"s.attr = 3", ModeStarlark},
		{"y = sys.exec_cmd('ls')", ModeStarlark},
		{"nums = [n * n for n in range(4)]", ModeStarlark},
		{"x = {", ModeStarlark},
		{"cfg = dict(", ModeStarlark},
		{"items = [1,", ModeStarlark},
		{`doc = """start`, ModeStarlark},
	} {
		if got := DetermineMode(tc.line); got != tc.want {
			t.Errorf("DetermineMode(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// A spaced assignment that does not parse is a Starlark mistake, not a
// program named after its target: s = {1, 2} reports the Starlark error.
func TestSpacedAssignmentThatFailsToParseIsStarlark(t *testing.T) {
	for _, tc := range []struct {
		line string
		want EvalMode
	}{
		{"s = {1, 2}", ModeStarlark},
		{"s = {1}", ModeStarlark},
		{"cfg.port = {8080, 8443}", ModeStarlark},
		{`d["k"] = {1, 2}`, ModeStarlark},
		{"test $x = 5", ModeShell},
		{"find . -name a=b", ModeShell},
		{"ls --color=auto /", ModeShell},
		{"grep -c x= /dev/null /", ModeShell},
		{"x={", ModeStarlark},
		{"x += [1,", ModeStarlark},
		{`aws.ec2.list_instances(region="us-east-1",`, ModeStarlark},
		{"a, b = (", ModeStarlark},
		{"a, b = [1,", ModeStarlark},
		{"(a, b) = (1,", ModeStarlark},
		{"d[x[0]] = {", ModeStarlark},
		{`d["a]"] = {`, ModeStarlark},
		{"while x == 1:", ModeStarlark},
		{"f (a=1,", ModeStarlark},
		{`"s".format(a=`, ModeStarlark},
		{`doc = """start`, ModeStarlark},
		{"cp a=b /", ModeShell},
		{"ls --color=auto / # (", ModeShell},
	} {
		if got := DetermineMode(tc.line); got != tc.want {
			t.Errorf("DetermineMode(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
