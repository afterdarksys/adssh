package security

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func runDenialVBin(t *testing.T, eng *Engine, sessionID string, args []string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(WithSessionID(ctx, sessionID), denialBinary{}, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("denial-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &runbookTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

func TestQuestionQuestionExplainsLastPolicyDenial(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh.authz
default allow = false
default deny_reason = "blocked by test policy"
`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.gateCommand(false, []string{"deploy", "prod"}, "deny-session"); err == nil {
		t.Fatal("expected policy denial")
	}
	output, err := runDenialVBin(t, eng, "deny-session", []string{"??"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DENIED deploy prod", "policy", "blocked by test policy"} {
		if !strings.Contains(output, want) {
			t.Fatalf("?? output missing %q: %q", want, output)
		}
	}
}

func TestQuestionQuestionReportsNoDenial(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := runDenialVBin(t, eng, "clean-session", []string{"??"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "No denied command recorded") {
		t.Fatalf("unexpected output: %q", output)
	}
}
