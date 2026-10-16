package repl

import (
	"bytes"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// countingGlobals returns globals holding a count() builtin and a pointer to
// the number of times it has been called.
func countingGlobals() (starlark.StringDict, *int) {
	calls := 0
	count := starlark.NewBuiltin("count", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		calls++
		return starlark.MakeInt(calls), nil
	})
	return starlark.StringDict{"count": count}, &calls
}

// TestEvalStarlarkRuntimeErrorRunsSideEffectOnce: an expression that fails at
// runtime after a side effect must not be re-run as a statement.
func TestEvalStarlarkRuntimeErrorRunsSideEffectOnce(t *testing.T) {
	globals, calls := countingGlobals()
	errOut := &bytes.Buffer{}
	code := evalStarlark(&starlark.Thread{Name: "test"}, "count() / 0", globals, errOut)
	if *calls != 1 {
		t.Fatalf("count() called %d times, want 1", *calls)
	}
	if code == 0 || !strings.Contains(errOut.String(), "Starlark error") {
		t.Fatalf("want a reported error, got code=%d errOut=%q", code, errOut.String())
	}
}

func TestEvalStarlarkExpressionRunsOnce(t *testing.T) {
	globals, calls := countingGlobals()
	errOut := &bytes.Buffer{}
	if code := evalStarlark(&starlark.Thread{Name: "test"}, "count()", globals, errOut); code != 0 {
		t.Fatalf("code=%d errOut=%q", code, errOut.String())
	}
	if *calls != 1 {
		t.Fatalf("count() called %d times, want 1", *calls)
	}
}

func TestEvalStarlarkAssignmentRunsOnceAndBinds(t *testing.T) {
	globals, calls := countingGlobals()
	errOut := &bytes.Buffer{}
	if code := evalStarlark(&starlark.Thread{Name: "test"}, "x = count()", globals, errOut); code != 0 {
		t.Fatalf("code=%d errOut=%q", code, errOut.String())
	}
	if *calls != 1 {
		t.Fatalf("count() called %d times, want 1", *calls)
	}
	if got, ok := globals["x"].(starlark.Int); !ok || got.String() != "1" {
		t.Fatalf("x = %v, want 1", globals["x"])
	}
}

func TestEvalStarlarkDefStillDefines(t *testing.T) {
	globals, _ := countingGlobals()
	errOut := &bytes.Buffer{}
	if code := evalStarlark(&starlark.Thread{Name: "test"}, "def f():\n    return 7\n", globals, errOut); code != 0 {
		t.Fatalf("code=%d errOut=%q", code, errOut.String())
	}
	if _, ok := globals["f"].(*starlark.Function); !ok {
		t.Fatalf("f not defined: %v", globals["f"])
	}
}
