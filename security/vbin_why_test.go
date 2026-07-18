package security

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func TestWhyJSONReturnsOrderedGovernanceExplanation(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &out),
		interp.ExecHandler(func(ctx context.Context, args []string) error {
			return eng.DispatchVBin(ctx, whyBinary{}, []string{"why", "--json", "--", "echo", "hello"})
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, _ := syntax.NewParser().Parse(strings.NewReader("why-test"), "")
	if err := runner.Run(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	var explanation CommandExplanation
	if err := json.Unmarshal(out.Bytes(), &explanation); err != nil {
		t.Fatalf("decode why output %q: %v", out.String(), err)
	}
	if explanation.Command != "echo" || explanation.Outcome != "allowed" {
		t.Fatalf("unexpected why output: %#v", explanation)
	}
}
