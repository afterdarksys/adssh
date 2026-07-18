package security

import (
	"context"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func TestGovernedCommandDenialNeverReachesExecutor(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`
package adssh
authz := {"allow": false, "deny_reason": "blocked by test"}
`)})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	executor := func(context.Context, governedCommand) (commandResult, error) {
		called = true
		return commandResult{}, nil
	}

	_, err = eng.runGovernedCommand(context.Background(), "", governedCommand{Args: []string{"dangerous"}}, executor)
	if err == nil || !strings.Contains(err.Error(), "blocked by test") {
		t.Fatalf("expected policy denial, got %v", err)
	}
	if called {
		t.Fatal("denied child command reached executor")
	}
}

type runtimeTestBinary struct{ ran *bool }

func (runtimeTestBinary) Name() string        { return "runtime-child-vbin" }
func (runtimeTestBinary) Description() string { return "test child" }
func (runtimeTestBinary) Usage() string       { return "runtime-child-vbin" }
func (v runtimeTestBinary) Run(context.Context, []string) error {
	*v.ran = true
	return nil
}

func TestGovernedCommandCanDispatchRegisteredVBin(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	eng.Register(runtimeTestBinary{ran: &ran})
	runner, err := interp.New(interp.ExecHandler(func(ctx context.Context, _ []string) error {
		_, err := eng.runGovernedCommand(ctx, "", governedCommand{Args: []string{"runtime-child-vbin"}}, nil)
		return err
	}))
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("parent"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Fatal("registered child VBIN was not dispatched")
	}
}

func TestGovernedCommandBoundsCapturedOutput(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := eng.runGovernedCommand(context.Background(), "", governedCommand{
		Args:      []string{"/usr/bin/printf", "abcdef"},
		MaxOutput: 3,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Stdout) != "abc" {
		t.Fatalf("bounded stdout = %q, want abc", result.Stdout)
	}
}
