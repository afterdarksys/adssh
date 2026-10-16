package security

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/guard"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func runGuard(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &out),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return DispatchVBin(ctx, guardBinary{}, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("guard-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	err = runner.Run(context.Background(), file)
	return out.String(), err
}

func TestGuardStatusJSONAndUnknownUnban(t *testing.T) {
	guard.ResetForTest()
	t.Cleanup(guard.ResetForTest)
	dir := t.TempDir()
	if err := guard.Configure(guard.Options{
		ConfigPath: dir + "/guard.yaml",
		StatePath:  dir + "/guard-state.json",
	}); err != nil {
		t.Fatal(err)
	}
	out, err := runGuard(t, "guard", "status", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"enabled":true`) || !strings.Contains(out, "127.0.0.0/8") {
		t.Fatalf("status: %s", out)
	}
	if _, err := runGuard(t, "guard", "unban", "203.0.113.50"); err == nil {
		t.Fatal("unknown unban returned nil")
	}
}

// An SSH login child never calls guard.Configure. Its status must say so
// instead of printing defaults that look like a live jail.
func TestGuardStatusUnconfiguredProcess(t *testing.T) {
	guard.ResetForTest()
	t.Cleanup(guard.ResetForTest)
	out, err := runGuard(t, "guard", "status")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "note: not configured in this process") || !strings.Contains(out, "enabled: false") {
		t.Fatalf("status output:\n%s", out)
	}
	out, err = runGuard(t, "guard", "config", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"configured":false`) || !strings.Contains(out, `"note":"not configured in this process"`) {
		t.Fatalf("config json: %s", out)
	}
}
