package security

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

const allowAllPolicy = "package adssh.authz\ndefault allow = true\n"

func testID(t *testing.T, suffix string) string {
	t.Helper()
	id := strings.ReplaceAll(t.Name(), "/", "_") + "_" + suffix
	if !roleNamePattern.MatchString(id) {
		t.Fatalf("test id is invalid (%d chars)", len(id))
	}
	return id
}

func policyEngine(t *testing.T, source string) *Engine {
	t.Helper()
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(source)})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func runVBin(t *testing.T, eng *Engine, sessionID string, args []string) (string, error) {
	t.Helper()
	if eng == nil {
		var err error
		eng, err = NewEngine(EngineConfig{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(args) == 0 {
		t.Fatal("missing vbin args")
	}
	vb, ok := eng.Lookup(args[0])
	if !ok {
		t.Fatalf("vbin %s is not registered", args[0])
	}
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(WithSessionID(ctx, sessionID), vb, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("vbin-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &runbookTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

func equalErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s", want)
	}
	got := err.Error()
	if got != want {
		if strings.Contains(got, "eyJ") {
			t.Fatal("error mismatched and contained a jwt")
		}
		t.Fatalf("got %q want %q", got, want)
	}
}
