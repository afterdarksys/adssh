package security

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func TestPickSelectsFuzzyMatchFromStdinNonInteractively(t *testing.T) {
	var out bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(strings.NewReader("alpha\nbeta\ngamma\n"), &out, &out),
		interp.ExecHandler(func(ctx context.Context, args []string) error {
			return pickBinary{}.Run(ctx, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("pick --non-interactive --query bet"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "beta" {
		t.Fatalf("pick output = %q, want beta", got)
	}
}
