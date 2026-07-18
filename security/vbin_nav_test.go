package security

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func TestNavNonInteractiveDirectorySelectionChangesShellDirectory(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "production")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	runner, err := interp.New(
		interp.Dir(root),
		interp.StdIO(strings.NewReader(""), &out, &out),
		interp.ExecHandler(func(ctx context.Context, args []string) error {
			return navBinary{}.Run(ctx, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("nav --non-interactive --select prod ."), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	if runner.Dir != child {
		t.Fatalf("runner directory = %q, want %q", runner.Dir, child)
	}
}
