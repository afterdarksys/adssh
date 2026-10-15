package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/parser"
	"github.com/afterdarksys/adssh/security"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
)

func flowSession(t *testing.T, policy []byte) (*engine.Session, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	cfg := engine.Config{}
	if policy != nil {
		cfg.EngineConfig = security.EngineConfig{PolicySource: policy}
	}
	eng, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	sess, err := eng.NewSession(engine.SessionOptions{Out: &out, Err: &errOut})
	if err != nil {
		t.Fatal(err)
	}
	return sess, &out, &errOut
}

func TestEvalOncePolicyDenyDoesNotCatch(t *testing.T) {
	sess, out, _ := flowSession(t, []byte("package adssh.authz\ndefault allow = false\n"))
	err := evalOnce(sess, "try { echo secret } catch { echo caught }")
	if err == nil {
		t.Fatal("expected a denial")
	}
	if _, ok := err.(interp.ExitStatus); ok {
		t.Fatalf("denial became exit status: %v", err)
	}
	if strings.Contains(out.String(), "secret") || strings.Contains(out.String(), "caught") {
		t.Fatalf("stdout %q", out.String())
	}
	if status, ok := sess.Globals["?"].(starlark.Int); !ok || status.String() != "1" {
		t.Fatalf("status %v", sess.Globals["?"])
	}
}

func TestEvalOnceStarlarkIfStaysStarlark(t *testing.T) {
	sess, _, _ := flowSession(t, nil)
	// evalOnce keeps the existing Starlark path, which does not copy new
	// bindings back into globals. The else branch is observed through print.
	var printed bytes.Buffer
	sess.Thread.Print = func(_ *starlark.Thread, msg string) {
		printed.WriteString(msg)
	}
	src := "x = 0\nif x > 5:\n  print('then')\nelse:\n  print('else')\n"
	if err := evalOnce(sess, src); err != nil {
		t.Fatal(err)
	}
	if printed.String() != "else" {
		t.Fatalf("printed %q", printed.String())
	}
}

func TestEvalOncePOSIXIfRuns(t *testing.T) {
	sess, out, _ := flowSession(t, nil)
	err := evalOnce(sess, "if true; then echo yes; else echo no; fi")
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "yes\n" {
		t.Fatalf("stdout %q", out.String())
	}

	sess, out, _ = flowSession(t, nil)
	err = evalOnce(sess, "if true; then")
	if err == nil || err.Error() != parser.ErrIncompleteShell.Error() {
		t.Fatalf("err %v stdout %q", err, out.String())
	}
	if out.String() != "" {
		t.Fatalf("incomplete ran: %q", out.String())
	}
}

func TestEvalOnceTrySetsStatus(t *testing.T) {
	sess, out, _ := flowSession(t, nil)
	err := evalOnce(sess, "try { false } catch { false }")
	status, ok := err.(interp.ExitStatus)
	if !ok || status != 1 {
		t.Fatalf("err %v", err)
	}
	if sess.Globals["?"].String() != "1" {
		t.Fatalf("status %v", sess.Globals["?"])
	}
	if out.String() != "" {
		t.Fatalf("stdout %q", out.String())
	}

	sess, out, _ = flowSession(t, nil)
	err = evalOnce(sess, "try { false } catch { echo recovered }")
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "recovered\n" {
		t.Fatalf("stdout %q", out.String())
	}
	if sess.Globals["?"].String() != "0" {
		t.Fatalf("status %v", sess.Globals["?"])
	}
}

func TestEvalLineScriptRunsFlowBetweenCommands(t *testing.T) {
	sess, out, _ := flowSession(t, nil)
	src := "echo one\ntry { false } catch { echo caught }\necho two\n"
	if err := evalLineScript(sess, src); err != nil {
		t.Fatal(err)
	}
	if out.String() != "one\ncaught\ntwo\n" {
		t.Fatalf("stdout %q", out.String())
	}
}
