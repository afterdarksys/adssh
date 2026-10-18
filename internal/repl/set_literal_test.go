package repl

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// A set literal fails to parse; the error names set([...]) as the fix.
func TestSetLiteralErrorNamesSet(t *testing.T) {
	for _, src := range []string{"s = {1, 2}", "s = {1}", "{1, 2}"} {
		_, _, _, err := EvalStarlarkOnce(&starlark.Thread{Name: "test"}, "<test>", src, starlark.StringDict{})
		if err == nil || !strings.Contains(err.Error(), "set([1, 2])") {
			t.Errorf("%s: got %v, want the set() hint", src, err)
		}
	}
	_, _, _, err := EvalStarlarkOnce(&starlark.Thread{Name: "test"}, "<test>", `d = {"a" 1}`, starlark.StringDict{})
	if err == nil || strings.Contains(err.Error(), "set(") {
		t.Errorf("dict syntax error: got %v, want no set() hint", err)
	}
}
