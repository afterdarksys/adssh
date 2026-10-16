package repl

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// TestBackgroundSyntaxRemainsInAuthorizedShellProgram: a trailing '&' is left
// to the runner, so a background command still reaches the configured exec
// handler chain (where the session interceptor sits) instead of a side launcher.
func TestBackgroundSyntaxRemainsInAuthorizedShellProgram(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	record := func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			mu.Lock()
			seen = append(seen, strings.Join(args, " "))
			mu.Unlock()
			return nil
		}
	}
	r, err := interp.New(
		interp.Env(expand.ListEnviron()),
		interp.StdIO(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}),
		interp.ExecHandlers(record),
	)
	if err != nil {
		t.Fatalf("interp.New: %v", err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("dangerous --arg &\nwait\n"), "bg.sh")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := r.Run(context.Background(), file); err != nil {
		t.Fatalf("run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "dangerous --arg" {
		t.Fatalf("background command did not pass through the exec handler chain: %q", seen)
	}
}
