package repl

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/afterdarksys/adssh/security"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// gateCounter is a stand-in for the session CallHandler: it counts every
// command name it authorizes.
type gateCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (g *gateCounter) handler(ctx context.Context, args []string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.counts == nil {
		g.counts = map[string]int{}
	}
	if len(args) > 0 {
		g.counts[args[0]]++
	}
	return args, nil
}

func (g *gateCounter) count(name string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.counts[name]
}

func allowedExplanation(args []string) (security.CommandExplanation, error) {
	return security.CommandExplanation{
		Outcome: "allowed",
		Command: args[0],
		Stages:  []security.ExplanationStage{{Name: "policy", Status: "allowed"}},
	}, nil
}

// newConfirmRunner builds a runner with the gate counter as its CallHandler
// and the confirm handler wired to run through a subshell of that runner.
func newConfirmRunner(t *testing.T, stdin io.Reader, tty bool, explain func([]string) (security.CommandExplanation, error)) (*interp.Runner, *gateCounter, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	gate := &gateCounter{}
	var out, errOut bytes.Buffer
	var runner *interp.Runner
	deps := confirmDeps{
		explain: explain,
		isTTY:   func(io.Reader) bool { return tty },
		run:     subshellRun(func() *interp.Runner { return runner }),
	}
	var err error
	runner, err = interp.New(
		interp.StdIO(stdin, &out, &errOut),
		interp.CallHandler(gate.handler),
		interp.ExecHandlers(confirmHandler(deps)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return runner, gate, &out, &errOut
}

func runLine(t *testing.T, r *interp.Runner, line string) error {
	t.Helper()
	f, err := syntax.NewParser().Parse(strings.NewReader(line), "")
	if err != nil {
		t.Fatal(err)
	}
	return r.Run(context.Background(), f)
}

func TestConfirmDryRunPrintsWithoutRunning(t *testing.T) {
	explain := func(args []string) (security.CommandExplanation, error) {
		return security.CommandExplanation{
			Outcome:      "denied",
			Command:      args[0],
			RequiredRole: "sre-admin",
			Stages: []security.ExplanationStage{
				{Name: "policy", Status: "denied", Reason: "rm needs sre-admin"},
				{Name: "four_eyes", Status: "not_required"},
			},
		}, nil
	}
	r, gate, out, _ := newConfirmRunner(t, strings.NewReader(""), false, explain)
	if err := runLine(t, r, "confirm --dry-run rm -rf '/tmp/a b'"); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"command: rm -rf '/tmp/a b'",
		"risk:    destructive",
		"policy:  denied",
		"policy denied: rm needs sre-admin",
		"rule:    required role sre-admin",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("dry-run output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "[y/N]") {
		t.Error("dry-run asked for confirmation")
	}
	if gate.count("confirm") != 1 || gate.count("rm") != 0 {
		t.Fatalf("gate counts confirm=%d rm=%d", gate.count("confirm"), gate.count("rm"))
	}
}

func TestConfirmRefusesWithoutTTY(t *testing.T) {
	r, gate, out, errOut := newConfirmRunner(t, strings.NewReader("y\n"), false, allowedExplanation)
	err := runLine(t, r, "confirm echo ran")
	var status interp.ExitStatus
	if !errors.As(err, &status) || status == 0 {
		t.Fatalf("want a non-zero exit, got %v", err)
	}
	if strings.Contains(out.String(), "ran") || gate.count("echo") != 0 {
		t.Fatalf("command ran without a terminal: out=%q", out.String())
	}
	if !strings.Contains(errOut.String(), "not a terminal") {
		t.Fatalf("refusal not reported: %q", errOut.String())
	}
}

func TestConfirmRunReachesGateOnce(t *testing.T) {
	r, gate, out, errOut := newConfirmRunner(t, strings.NewReader("y\n"), true, allowedExplanation)
	if err := runLine(t, r, "confirm echo 'hello world'"); err != nil {
		t.Fatalf("run: %v (stderr %q)", err, errOut.String())
	}
	if !strings.Contains(out.String(), "[y/N]") || !strings.Contains(out.String(), "hello world\n") {
		t.Fatalf("output = %q", out.String())
	}
	if gate.count("confirm") != 1 || gate.count("echo") != 1 {
		t.Fatalf("gate counts confirm=%d echo=%d, want 1 and 1", gate.count("confirm"), gate.count("echo"))
	}
}

func TestConfirmDeclinedDoesNotRun(t *testing.T) {
	for _, answer := range []string{"n\n", "\n", "", "yes please\n"} {
		r, gate, out, _ := newConfirmRunner(t, strings.NewReader(answer), true, allowedExplanation)
		err := runLine(t, r, "confirm echo ran")
		if err == nil || gate.count("echo") != 0 || strings.Contains(out.String(), "\nran\n") {
			t.Fatalf("answer %q: err=%v echo gated %d times, out=%q", answer, err, gate.count("echo"), out.String())
		}
	}
}

func TestConfirmPolicyDenyDoesNotAsk(t *testing.T) {
	explain := func(args []string) (security.CommandExplanation, error) {
		return security.CommandExplanation{Outcome: "denied", Command: args[0],
			Stages: []security.ExplanationStage{{Name: "policy", Status: "denied", Reason: "no"}}}, nil
	}
	r, gate, out, _ := newConfirmRunner(t, strings.NewReader("y\n"), true, explain)
	if err := runLine(t, r, "confirm echo ran"); err == nil {
		t.Fatal("a denied command was confirmed")
	}
	if strings.Contains(out.String(), "[y/N]") || gate.count("echo") != 0 {
		t.Fatalf("asked or ran a denied command: %q", out.String())
	}
}

func TestConfirmExplainErrorFailsClosed(t *testing.T) {
	explain := func([]string) (security.CommandExplanation, error) {
		return security.CommandExplanation{}, errors.New("engine down")
	}
	r, gate, _, errOut := newConfirmRunner(t, strings.NewReader("y\n"), true, explain)
	if err := runLine(t, r, "confirm echo ran"); err == nil || gate.count("echo") != 0 {
		t.Fatalf("ran after an explain error: err=%v", err)
	}
	if !strings.Contains(errOut.String(), "engine down") {
		t.Fatalf("errOut = %q", errOut.String())
	}
}

func TestConfirmUsage(t *testing.T) {
	r, _, _, errOut := newConfirmRunner(t, strings.NewReader(""), true, allowedExplanation)
	if err := runLine(t, r, "confirm --dry-run"); err == nil || !strings.Contains(errOut.String(), "usage") {
		t.Fatalf("err=%v errOut=%q", err, errOut.String())
	}
}

func TestCompleterHasNoJobBuiltins(t *testing.T) {
	for _, b := range shellBuiltins {
		switch b {
		case "jobs", "fg", "bg":
			t.Errorf("completer still offers %q", b)
		}
	}
	found := false
	for _, b := range shellBuiltins {
		if b == "confirm" {
			found = true
		}
	}
	if !found {
		t.Error("completer does not offer confirm")
	}
}
