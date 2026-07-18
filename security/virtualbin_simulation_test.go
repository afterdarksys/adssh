package security

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func TestSimulatedSecurityToolsDoNotClaimVerdicts(t *testing.T) {
	for _, command := range []string{"darkscan sample.bin", "memforensics 123"} {
		t.Run(strings.Fields(command)[0], func(t *testing.T) {
			var out bytes.Buffer
			runner, err := interp.New(
				interp.StdIO(nil, &out, &out),
				interp.ExecHandlers(BashInterceptor(false, nil)),
			)
			if err != nil {
				t.Fatal(err)
			}
			file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
			if err != nil {
				t.Fatal(err)
			}
			if err := runner.Run(context.Background(), file); err != nil {
				t.Fatal(err)
			}
			text := out.String()
			if !strings.Contains(text, "SIMULATED — NO SECURITY VERDICT") {
				t.Fatalf("missing unambiguous simulation label: %q", text)
			}
			if strings.Contains(text, "CLEAN") || strings.Contains(text, "No threats detected") {
				t.Fatalf("simulated tool claimed a security verdict: %q", text)
			}
		})
	}
}
