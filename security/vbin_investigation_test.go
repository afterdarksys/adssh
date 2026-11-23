package security

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func runInvestigation(t *testing.T, e *Engine, session, dir string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	runner, err := interp.New(interp.Dir(dir), interp.StdIO(nil, &out, &out), interp.ExecHandler(func(ctx context.Context, _ []string) error {
		vb, ok := e.Lookup(args[0])
		if !ok {
			t.Fatalf("unregistered %s", args[0])
		}
		return e.DispatchVBin(WithSessionID(ctx, session), vb, args)
	}))
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("invoke"), "")
	if err != nil {
		t.Fatal(err)
	}
	err = runner.Run(context.Background(), file)
	return out.String(), err
}
func TestFilterMatchingAndInvalidInputs(t *testing.T) {
	e, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "log"), []byte("alpha\nerror: one\nerror: two\nlast"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ mode, pattern, want string }{{"-s", "error:", "error: one\nerror: two\n"}, {"-r", "^error: (one|two)$", "error: one\nerror: two\n"}, {"-s", "absent", ""}, {"-r", "last$", "last\n"}} {
		got, err := runInvestigation(t, e, "", dir, "filter", tc.mode, tc.pattern, "log")
		if err != nil || got != tc.want {
			t.Fatalf("got %q, %v", got, err)
		}
	}
	for _, args := range [][]string{{"filter", "-r", "[", "log"}, {"filter", "-x", "a", "log"}, {"filter", "-s", "a", "missing"}, {"filter", "-s", "a", "."}} {
		if _, err := runInvestigation(t, e, "", dir, args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "long"), []byte(strings.Repeat("x", (1<<20)+2)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runInvestigation(t, e, "", dir, "filter", "-s", "x", "long"); err == nil {
		t.Fatal("accepted oversized line")
	}
}
func TestWatchTamperingIsolationAndBaselinePreserved(t *testing.T) {
	e, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("original")
	output, err := runInvestigation(t, e, "alice", dir, "watch", "set", "hash", "file")
	if err != nil {
		t.Fatal(err)
	}
	var baseline watchRecord
	if err := json.Unmarshal([]byte(output), &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.SHA256 == "" || baseline.SetAt.IsZero() || !baseline.Match {
		t.Fatalf("bad baseline %+v", baseline)
	}
	if _, err := runInvestigation(t, e, "bob", dir, "watch", "get", "hash", "file"); err == nil {
		t.Fatal("session leaked baseline")
	}
	other, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runInvestigation(t, other, "alice", dir, "watch", "get", "hash", "file"); err == nil {
		t.Fatal("engine leaked baseline")
	}
	write("tampered")
	output, err = runInvestigation(t, e, "alice", dir, "watch", "get", "hash", "file")
	if err == nil {
		t.Fatal("accepted changed content")
	}
	var changed watchRecord
	if err := json.Unmarshal([]byte(output), &changed); err != nil {
		t.Fatal(err)
	}
	if changed.Match || changed.ChangedAt == nil || changed.SHA256 != baseline.SHA256 {
		t.Fatalf("bad change record %+v", changed)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := runInvestigation(t, e, "alice", dir, "watch", "set", "hash", "file"); err == nil {
		t.Fatal("accepted missing file")
	}
	write("original")
	if _, err := runInvestigation(t, e, "alice", dir, "watch", "get", "hash", "file"); err != nil {
		t.Fatal(err)
	}
}
func TestInvestigationRejectsSymlinkOversizeAndCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(investigationMaxFile + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := investigationHash(context.Background(), path); err == nil {
		t.Fatal("accepted oversized file")
	}
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := investigationHash(context.Background(), link); err == nil {
		t.Fatal("accepted symlink")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := investigationHash(ctx, path); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestInvestigationFIFORefusedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := investigationHash(context.Background(), path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked opening FIFO")
	}
}

func TestInvestigationPolicyDenialPreventsBaseline(t *testing.T) {
	e, err := NewEngine(EngineConfig{PolicySource: []byte("package adssh\nauthz := {\"allow\": false}\n")})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	runner, err := interp.New(interp.StdIO(nil, &out, &out), interp.ExecHandlers(e.BashInterceptor(nil)))
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("watch set hash missing"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background(), file); err == nil {
		t.Fatal("policy denial did not reach caller")
	}
	if len(e.fileWatches().records) != 0 {
		t.Fatal("denied command changed baseline state")
	}
}
