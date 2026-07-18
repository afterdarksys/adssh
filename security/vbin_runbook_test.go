package security

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func runRunbookVBin(t *testing.T, eng *Engine, args []string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(ctx, runbookBinary{}, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, _ := syntax.NewParser().Parse(strings.NewReader("runbook-test"), "")
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &runbookTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

type runbookTestError struct{ message string }

func (e *runbookTestError) Error() string { return e.message }

func TestRunbookRequiresTypedParametersAndExecutesGovernedSteps(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ADSSH_RUNBOOK_DIR", dir)
	source := `
description = "print a target"
params = {
    "target": {"type": "string", "required": True},
}
steps = [
    {"name": "print", "command": ["/usr/bin/printf", "%s", "${target}"]},
]
`
	if err := os.WriteFile(filepath.Join(dir, "diagnose.star"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runRunbookVBin(t, eng, []string{"runbook", "run", "diagnose"}); err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("missing required parameter was accepted: %v", err)
	}
	output, err := runRunbookVBin(t, eng, []string{"runbook", "run", "diagnose", "--param", "target=production"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "production") {
		t.Fatalf("runbook output = %q", output)
	}
}

func TestRunbookDryRunExplainsWithoutExecuting(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ADSSH_RUNBOOK_DIR", dir)
	marker := filepath.Join(dir, "executed")
	source := fmt.Sprintf(`description = "dry"
params = {}
steps = [{"name": "never", "command": ["/usr/bin/touch", %q]}]
`, marker)
	if err := os.WriteFile(filepath.Join(dir, "dry.star"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, _ := NewEngine(EngineConfig{})
	output, err := runRunbookVBin(t, eng, []string{"runbook", "run", "dry", "--dry-run"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "allowed") {
		t.Fatalf("dry-run output = %q", output)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("dry-run executed its step: %v", err)
	}
}

func TestRunbookRejectsSymlinkedDefinition(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ADSSH_RUNBOOK_DIR", dir)
	target := filepath.Join(t.TempDir(), "outside.star")
	if err := os.WriteFile(target, []byte(`steps = [{"command": ["/usr/bin/true"]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "linked.star")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRunbook("linked"); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked runbook was accepted: %v", err)
	}
}

func TestRunbookBoundsStarlarkEvaluation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ADSSH_RUNBOOK_DIR", dir)
	source := `
work = [i for i in range(2000000)]
steps = [{"command": ["/usr/bin/true"]}]
`
	if err := os.WriteFile(filepath.Join(dir, "expensive.star"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRunbook("expensive"); err == nil || !strings.Contains(err.Error(), "too many steps") {
		t.Fatalf("expensive runbook was accepted: %v", err)
	}
}
