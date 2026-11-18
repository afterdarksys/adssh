//go:build userland_integration

package userland_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/engine"
	"github.com/afterdarksys/adssh/internal/userland"
	"github.com/afterdarksys/adssh/internal/userland/pb"
	"github.com/afterdarksys/adssh/security"
	"mvdan.cc/sh/v3/interp"
)

func TestBundledWorker(t *testing.T) {
	dir, err := os.MkdirTemp("", "ul-integration-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	worker, err := filepath.Abs("../../adssh-userland-worker")
	if err != nil {
		t.Fatal(err)
	}
	gate, err := security.NewEngine(security.EngineConfig{RequirePolicy: true, PolicySource: []byte(`package adssh
authz := {"allow": input.command in {"cat", "find", "grep", "head", "ls"}}`), AuditLogPath: filepath.Join(dir, "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.BindSessionIdentity("daemon", "local-user", nil); err != nil {
		t.Fatal(err)
	}
	defer gate.UnbindSessionIdentity("daemon")
	srv, err := userland.NewServer(userland.Config{Worker: worker,
		Authorize: func(ctx context.Context, args []string) error {
			return gate.AuthorizeCommandContext(ctx, args, "daemon")
		},
		Record: func(_ context.Context, _ []string, event string) error { return gate.LogEvent(event) },
	})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "s")
	listener, err := userland.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(listener)
	defer srv.Stop()
	conn, err := userland.Dial(context.Background(), socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := os.WriteFile(filepath.Join(dir, "sample.txt"), []byte("alpha\nbeta\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args            []string
		input, contains string
		code            int
	}{
		{args: []string{"cat", "sample.txt"}, contains: "alpha\nbeta\n"},
		{args: []string{"ls"}, contains: "sample.txt"},
		{args: []string{"head", "-n", "1"}, input: "alpha\nbeta\n", contains: "alpha\n"},
		{args: []string{"grep", "beta"}, input: "alpha\nbeta\n", contains: "beta\n"},
		{args: []string{"grep", "absent"}, input: "alpha\n", code: 1},
		{args: []string{"find", ".", "-name", "sample.txt"}, contains: "sample.txt"},
		{args: []string{"cat", "missing"}, code: 1},
		{args: []string{"head", "missing"}, code: 1},
		{args: []string{"grep", "x", "missing"}, code: 2},
		{args: []string{"find", "missing"}, code: 1},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			var out, stderr bytes.Buffer
			code, err := userland.Execute(context.Background(), conn, &pb.Start{Argv: tc.args, Directory: dir}, strings.NewReader(tc.input), &out, &stderr)
			if err != nil || code != tc.code || !strings.Contains(out.String(), tc.contains) {
				t.Fatalf("code=%d err=%v stdout=%q stderr=%q", code, err, &out, &stderr)
			}
		})
	}
	t.Run("shell_pipeline_and_redirection", func(t *testing.T) {
		var out, stderr bytes.Buffer
		session, err := engine.NewSession(engine.SessionOptions{In: strings.NewReader(""), Out: &out, Err: &stderr, Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		src := "printf 'alpha\\nbeta\\n' | userland --socket '" + socket + "' exec grep beta > result.txt"
		if err := session.RunShell(context.Background(), src); err != nil {
			t.Fatalf("pipeline: %v stderr=%q", err, &stderr)
		}
		data, err := os.ReadFile(filepath.Join(dir, "result.txt"))
		if err != nil || string(data) != "beta\n" {
			t.Fatalf("redirection=%q err=%v", data, err)
		}
		if err := session.RunShell(context.Background(), "userland --socket '"+socket+"' exec grep absent sample.txt"); err == nil {
			t.Fatal("grep no-match became shell success")
		}
	})

	t.Run("early_pipeline_exit", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(dir, "large.txt"), []byte(strings.Repeat("row\n", 300000)), 0600); err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		session, err := engine.NewSession(engine.SessionOptions{In: strings.NewReader(""), Out: &out, Err: &stderr, Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		prefix := "userland --socket '" + socket + "' exec "
		err = session.RunShell(context.Background(), prefix+"cat large.txt | "+prefix+"head -n 1")
		if err != nil || out.String() != "row\n" {
			t.Fatalf("early exit: %v stdout=%q stderr=%q", err, &out, &stderr)
		}
		err = session.RunShell(context.Background(), "set -o pipefail; "+prefix+"cat large.txt | "+prefix+"head -n 1")
		if code, ok := interp.IsExitStatus(err); !ok || code != 141 {
			t.Fatalf("pipefail lost SIGPIPE status: %v", err)
		}
	})
	t.Run("client_policy_denial", func(t *testing.T) {
		eng, err := security.NewEngine(security.EngineConfig{PolicySource: []byte(`package adssh
authz := {"allow": input.command != "cat"}`)})
		if err != nil {
			t.Fatal(err)
		}
		session, err := engine.NewSession(engine.SessionOptions{Engine: eng, In: strings.NewReader(""), Out: io.Discard, Err: io.Discard, Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if err := session.RunShell(context.Background(), "userland --socket '"+socket+"' exec cat sample.txt"); err == nil {
			t.Fatal("client deny bypassed")
		}
	})
}
