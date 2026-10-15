package repl

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/parser"
	"github.com/afterdarksys/adssh/security"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func newFlowExec(t *testing.T, restricted bool) (FlowExec, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	run, out, errOut, _ := testPasteRunner(t, restricted)
	return FlowExec{
		Gate: func(node syntax.Node) error {
			return security.GateProgramSession(run.state, node)
		},
		Runner: run.runner,
		Ctx:    context.Background(),
	}, out, errOut
}

func TestRunFlowIfElse(t *testing.T) {
	ex, out, _ := newFlowExec(t, false)
	err := RunFlow("if false { echo yes } else { echo no }", ex)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "no\n" {
		t.Fatalf("stdout %q", out.String())
	}

	ex, out, _ = newFlowExec(t, false)
	err = RunFlow("if false { echo yes }", ex)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "" {
		t.Fatalf("stdout %q", out.String())
	}

	ex, out, _ = newFlowExec(t, false)
	err = RunFlow("if true { echo yes } else { echo no }", ex)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "yes\n" {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestRunFlowTryCatch(t *testing.T) {
	ex, out, _ := newFlowExec(t, false)
	err := RunFlow("try { echo before; false; echo after } catch { echo recovered }", ex)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "before\nrecovered\n" {
		t.Fatalf("stdout %q", out.String())
	}

	ex, out, _ = newFlowExec(t, false)
	err = RunFlow("try { echo ok } catch { echo no }", ex)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "ok\n" {
		t.Fatalf("stdout %q", out.String())
	}

	ex, out, _ = newFlowExec(t, false)
	err = RunFlow("try { false } catch { false }", ex)
	status, ok := err.(interp.ExitStatus)
	if !ok || status != 1 {
		t.Fatalf("err %v", err)
	}
	if out.String() != "" {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestRunFlowRejectsPOSIXAndEmpty(t *testing.T) {
	ex, out, _ := newFlowExec(t, false)
	err := RunFlow("if true; then echo yes; else echo no; fi", ex)
	if err == nil || err.Error() != "flow: not a block" {
		t.Fatalf("err %v", err)
	}
	if out.String() != "" {
		t.Fatalf("posix ran: %q", out.String())
	}

	ex, out, _ = newFlowExec(t, false)
	err = RunFlow("try { echo hi }", ex)
	if err == nil || err.Error() != parser.ErrTryNeedsCatch.Error() {
		t.Fatalf("err %v", err)
	}
	if out.String() != "" {
		t.Fatalf("incomplete ran: %q", out.String())
	}

	ex, out, _ = newFlowExec(t, false)
	err = RunFlow("try { } catch { echo caught }", ex)
	if err == nil || err.Error() != parser.ErrEmptyTry.Error() {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(out.String(), "caught") {
		t.Fatalf("empty body ran catch: %q", out.String())
	}

	ex, out, _ = newFlowExec(t, false)
	err = RunFlow("try { echo hi } echo", ex)
	if err == nil || err.Error() != parser.ErrExpectedCatch.Error() {
		t.Fatalf("err %v", err)
	}
	if out.String() != "" {
		t.Fatalf("syntax ran: %q", out.String())
	}
}

func TestRunFlowRestrictedDoesNotCatch(t *testing.T) {
	ex, out, _ := newFlowExec(t, true)
	err := RunFlow("try { /bin/echo secret } catch { echo caught }", ex)
	if err == nil {
		t.Fatal("expected a denial")
	}
	if _, ok := err.(interp.ExitStatus); ok {
		t.Fatalf("denial became exit status: %v", err)
	}
	if !strings.Contains(err.Error(), "restricted") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(out.String(), "secret") || strings.Contains(out.String(), "caught") {
		t.Fatalf("stdout %q", out.String())
	}

	ex, out, _ = newFlowExec(t, true)
	err = RunFlow("try { echo hi; export FOO=1 } catch { echo caught }", ex)
	if err == nil {
		t.Fatal("expected a gate error")
	}
	if _, ok := err.(interp.ExitStatus); ok {
		t.Fatalf("gate error became exit status: %v", err)
	}
	if strings.Contains(out.String(), "hi") || strings.Contains(out.String(), "caught") {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestAccumulateScriptChunks(t *testing.T) {
	var got []string
	var ignores []bool
	err := AccumulateScript("echo one\ntry { false } catch { echo caught }\necho two\n", func(chunk string, line int, ignore bool) error {
		got = append(got, chunk)
		ignores = append(ignores, ignore)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("chunks %q", got)
	}
	if got[0] != "echo one" || !strings.HasPrefix(got[1], "try {") || got[2] != "echo two" {
		t.Fatalf("chunks %q", got)
	}
	if ignores[0] || ignores[1] || ignores[2] {
		t.Fatalf("ignores %v", ignores)
	}

	got = nil
	err = AccumulateScript("if true; then\necho yes\nfi\n", func(chunk string, line int, ignore bool) error {
		got = append(got, chunk)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(got[0], "then") || !strings.Contains(got[0], "fi") {
		t.Fatalf("posix chunks %q", got)
	}

	got = nil
	err = AccumulateScript("try {\nexit\n} catch { echo no }\necho after\n", func(chunk string, line int, ignore bool) error {
		got = append(got, chunk)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !strings.Contains(got[0], "exit") || got[1] != "echo after" {
		t.Fatalf("exit inside try: %q", got)
	}

	got = nil
	err = AccumulateScript("echo one\nexit\necho two\n", func(chunk string, line int, ignore bool) error {
		got = append(got, chunk)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "echo one" {
		t.Fatalf("exit stopped late: %q", got)
	}

	got = nil
	ignores = nil
	err = AccumulateScript("- false\necho ok\n", func(chunk string, line int, ignore bool) error {
		got = append(got, chunk)
		ignores = append(ignores, ignore)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "false" || !ignores[0] || got[1] != "echo ok" || ignores[1] {
		t.Fatalf("ignore chunks %q flags %v", got, ignores)
	}

	got = nil
	err = AccumulateScript("echo first\ntry {\n", func(chunk string, line int, ignore bool) error {
		got = append(got, chunk)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), parser.ErrUnclosed.Error()) {
		t.Fatalf("err %v", err)
	}
	if len(got) != 1 || got[0] != "echo first" {
		t.Fatalf("partial executed: %q", got)
	}
}
