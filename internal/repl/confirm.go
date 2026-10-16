package repl

// Threats: `confirm` must never turn into a way around the gate or into an
// unattended yes. The `confirm ...` line itself passes the session gate like
// any command (policy can demand it with input.command == "confirm"). The
// command it wraps is then run on a subshell of the session runner, so it
// reaches the same call-handler gate exactly once, under its own name. The
// preview is ExplainCommand, which runs nothing and writes no audit entry; it
// is advice, and the gate decides. Confirmation fails closed: a policy denial,
// an explain error, a stdin that is not a terminal (a pipe, a script, a
// here-doc), EOF, or any answer other than y/yes means the command does not
// run. The answer is read a byte at a time, so input meant for the command is
// not consumed.

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/afterdarksys/adssh/internal/risk"
	"github.com/afterdarksys/adssh/security"

	"golang.org/x/term"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

const confirmUsage = "confirm: usage: confirm [--dry-run] command [args...]"

type confirmDeps struct {
	// explain is the policy preview (security ExplainCommand).
	explain func(args []string) (security.CommandExplanation, error)
	// remote is true in an SSH session child: its policy lives in the
	// listener and is decided by the gate when the command runs.
	remote bool
	isTTY  func(io.Reader) bool
	// run executes args through the session's gate.
	run func(ctx context.Context, hc interp.HandlerContext, args []string) error
}

// newConfirmDeps wires confirm to the default engine and to a subshell of
// the session runner.
func newConfirmDeps(sessionID string, runner func() *interp.Runner) confirmDeps {
	return confirmDeps{
		explain: func(args []string) (security.CommandExplanation, error) {
			return security.DefaultEngine().ExplainCommand(sessionID, args)
		},
		remote: security.RemoteGateProcess(),
		isTTY:  readerIsTerminal,
		run:    subshellRun(runner),
	}
}

func readerIsTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// subshellRun runs args, quoted, on a subshell of the runner with the
// handler's stdio and directory. The subshell keeps the runner's call
// handler, so the command is gated and audited once like a typed command.
func subshellRun(runner func() *interp.Runner) func(context.Context, interp.HandlerContext, []string) error {
	return func(ctx context.Context, hc interp.HandlerContext, args []string) error {
		f, err := syntax.NewParser().Parse(strings.NewReader(quoteArgs(args)), "confirm")
		if err != nil {
			return err
		}
		sub := runner().Subshell()
		if err := interp.StdIO(hc.Stdin, hc.Stdout, hc.Stderr)(sub); err != nil {
			return err
		}
		sub.Dir = hc.Dir
		return sub.Run(ctx, f)
	}
}

func quoteArgs(args []string) string {
	words := make([]string, len(args))
	for i, a := range args {
		q, err := syntax.Quote(a, syntax.LangBash)
		if err != nil {
			// Quote fails only on a NUL byte, which no argv can hold.
			q = "''"
		}
		words[i] = q
	}
	return strings.Join(words, " ")
}

// confirmHandler is the exec handler for `confirm`.
func confirmHandler(d confirmDeps) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 || args[0] != "confirm" {
				return next(ctx, args)
			}
			return runConfirm(ctx, interp.HandlerCtx(ctx), args[1:], d)
		}
	}
}

func runConfirm(ctx context.Context, hc interp.HandlerContext, args []string, d confirmDeps) error {
	dryRun := false
	if len(args) > 0 && args[0] == "--dry-run" {
		dryRun, args = true, args[1:]
	}
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(hc.Stderr, confirmUsage)
		return interp.ExitStatus(2)
	}
	if !dryRun && !d.isTTY(hc.Stdin) {
		fmt.Fprintln(hc.Stderr, "confirm: stdin is not a terminal; refusing to run without an answer")
		return interp.ExitStatus(1)
	}

	line := quoteArgs(args)
	fmt.Fprintf(hc.Stdout, "command: %s\n", line)
	fmt.Fprintf(hc.Stdout, "risk:    %s\n", risk.ShellCommandClass(line))
	denied, err := writeConfirmPolicy(hc.Stdout, args, d)
	if err != nil {
		fmt.Fprintf(hc.Stderr, "confirm: policy preview failed: %v\n", err)
		return interp.ExitStatus(1)
	}
	if dryRun {
		return nil
	}
	if denied {
		fmt.Fprintln(hc.Stderr, "confirm: policy would deny this command; not running")
		return interp.ExitStatus(1)
	}

	fmt.Fprint(hc.Stdout, "run it? [y/N] ")
	switch strings.ToLower(readAnswer(hc.Stdin)) {
	case "y", "yes":
		return d.run(ctx, hc, args)
	}
	fmt.Fprintln(hc.Stdout, "not run")
	return interp.ExitStatus(1)
}

// writeConfirmPolicy prints the policy decision and reports a denial.
func writeConfirmPolicy(w io.Writer, args []string, d confirmDeps) (denied bool, err error) {
	if d.remote {
		fmt.Fprintln(w, "policy:  decided by the SSH listener when the command runs")
		return false, nil
	}
	exp, err := d.explain(args)
	if err != nil {
		return false, err
	}
	fmt.Fprintf(w, "policy:  %s\n", exp.Outcome)
	for _, st := range exp.Stages {
		if st.Status != "denied" && st.Status != "approval_required" && st.Status != "warning" {
			continue
		}
		if st.Reason != "" {
			fmt.Fprintf(w, "  %s %s: %s\n", st.Name, st.Status, st.Reason)
		} else {
			fmt.Fprintf(w, "  %s %s\n", st.Name, st.Status)
		}
	}
	if exp.Rule != "" {
		fmt.Fprintf(w, "rule:    %s\n", exp.Rule)
	}
	if exp.RequiredRole != "" {
		fmt.Fprintf(w, "rule:    required role %s\n", exp.RequiredRole)
	}
	if exp.RequiredEntitlement != "" {
		fmt.Fprintf(w, "rule:    required entitlement %s\n", exp.RequiredEntitlement)
	}
	return exp.Outcome == "denied", nil
}

// readAnswer reads one line, at most 64 bytes, a byte at a time.
func readAnswer(r io.Reader) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	buf := make([]byte, 1)
	for reads := 0; b.Len() < 64 && reads < 256; reads++ {
		n, err := r.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			break
		}
	}
	return strings.TrimSpace(b.String())
}
