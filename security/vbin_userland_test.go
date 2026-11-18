package security

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func TestUserlandAuthorizesChildBeforeDial(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`package adssh
authz := {"allow": input.command != "cat", "deny_reason": "cat blocked"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	runner, err := interp.New(interp.StdIO(strings.NewReader(""), &out, &out), interp.ExecHandler(func(ctx context.Context, _ []string) error {
		return eng.DispatchVBin(ctx, userlandBinary{}, []string{"userland", "--socket", "/nonexistent/s", "exec", "cat", "/etc/hosts"})
	}))
	if err != nil {
		t.Fatal(err)
	}
	node, err := syntax.NewParser().Parse(strings.NewReader("invoke"), "")
	if err != nil {
		t.Fatal(err)
	}
	err = runner.Run(context.Background(), node)
	if err == nil || !strings.Contains(err.Error(), "cat blocked") {
		t.Fatalf("child escaped gate: %v", err)
	}
}
