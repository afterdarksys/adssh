package security

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// mvdan cannot redirect fd 3 and up and fails such a command with no message.
// The gate refuses the program first, with an error the user sees.
func TestUnsupportedRedirectFDIsReported(t *testing.T) {
	for _, src := range []string{"exec 3> /dev/null", "echo x 3> /dev/null", "cat 4< /dev/null", "true && { echo a 9>&1; }"} {
		_, _, err, rec := runShell(t, false, starlark.StringDict{}, src)
		if err == nil || !strings.Contains(err.Error(), "unsupported redirect fd") {
			t.Fatalf("%q: err = %v, want unsupported redirect fd", src, err)
		}
		if len(rec.calls) != 0 {
			t.Fatalf("%q ran %v before the error", src, rec.calls)
		}
	}
	for _, src := range []string{"echo x 2>&1", "echo x 1>/dev/null", "cat 0</dev/null", "echo x >/dev/null 2>/dev/null"} {
		// Only the fd check is under test; other package tests may leave
		// policy state on the default engine.
		if _, _, err, _ := runShell(t, false, starlark.StringDict{}, src); err != nil && strings.Contains(err.Error(), "unsupported redirect fd") {
			t.Fatalf("%q: %v", src, err)
		}
	}
}
