package security

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func runParVBin(t *testing.T, eng *Engine, args []string, input string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(strings.NewReader(input), &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(ctx, parBinary{}, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, _ := syntax.NewParser().Parse(strings.NewReader("par-test"), "")
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &runbookTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

func TestParRunsItemsConcurrentlyButRendersInInputOrder(t *testing.T) {
	eng, _ := NewEngine(EngineConfig{})
	output, err := runParVBin(t, eng, []string{
		"par", "--jobs", "3", "beta", "alpha", "gamma", "--", "/usr/bin/printf", "%s\\n", "{}",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output); got != "beta\nalpha\ngamma" {
		t.Fatalf("ordered output = %q", got)
	}
}

func TestParAppliesPolicyToEveryChild(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh
authz := {"allow": input.command != "/usr/bin/printf", "deny_reason": "printf blocked"}
`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = runParVBin(t, eng, []string{"par", "item", "--", "/usr/bin/printf", "{}"}, "")
	if err == nil || !strings.Contains(err.Error(), "printf blocked") {
		t.Fatalf("child policy denial was not surfaced: %v", err)
	}
}

func TestParRejectsUnsafeJobCount(t *testing.T) {
	eng, _ := NewEngine(EngineConfig{})
	_, err := runParVBin(t, eng, []string{"par", "--jobs", "0", "item", "--", "/usr/bin/true"}, "")
	if err == nil || !strings.Contains(err.Error(), "jobs") {
		t.Fatalf("unsafe job count accepted: %v", err)
	}
}
