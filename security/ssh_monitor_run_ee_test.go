//go:build ee

package security

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestSSHMonitorRunFourEyesApproveWritesListenerChain(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	id := "run-approver"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	seedPending(t, eng, "req-run", "alice", "bob")
	c := dialMonitorRun(t, id, func(ctx context.Context, args []string) error {
		return eng.AuthorizeCommandContext(ctx, args, id)
	}, func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return eng.RunVBinForSession(ctx, id, args, stdin, stdout, stderr)
	})
	sendRun(t, c, 3, []string{"4eyes", "approve", "req-run"}, nil)
	res := readRun(t, c, 3)
	if res.exit.Code != 0 || res.exit.Error != "" {
		t.Fatalf("exit=%+v stderr=%q", res.exit, res.stderr.String())
	}
	ledger, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ledger), "FOUREYES_DECISION request=req-run approver=bob decision=approve surface=shell") {
		t.Fatalf("listener chain missing decision:\n%s", ledger)
	}
}

func TestSSHMonitorCancelEndsFourEyesWait(t *testing.T) {
	t.Setenv("ADSSH_4EYES_WEBHOOK", "")
	eng, _, _ := chainEngine(t)
	if err := eng.AddFourEyesRule("elevate*", "", 60); err != nil {
		t.Fatal(err)
	}
	id := "run-cancel"
	sess := &sys.Session{ID: id, User: "bob"}
	registerTestSession(t, sess)
	sess.SetPromptWriter(io.Discard)
	var ran atomic.Bool
	c := dialMonitorRun(t, id, func(ctx context.Context, args []string) error {
		return eng.AuthorizeCommandContext(ctx, args, id)
	}, func(context.Context, []string, io.Reader, io.Writer, io.Writer) (int, error) {
		ran.Store(true)
		return 0, nil
	})
	sendRun(t, c, 40, []string{"elevate", "status"}, nil)
	// Wait for the pending request to exist.
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, _ := os.ReadDir(eng.fourEyesPendingDir())
		if len(entries) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no pending request")
		}
		time.Sleep(10 * time.Millisecond)
	}
	body, err := json.Marshal(sys.MonitorCancel{ID: 40})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := sys.WriteMonitorFrame(c, sys.MonitorFrameCancel, body); err != nil {
		t.Fatal(err)
	}
	res := readRun(t, c, 40)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("cancel took %v", elapsed)
	}
	if res.exit.Error == "" || !strings.Contains(res.exit.Error, "cancel") {
		t.Fatalf("exit = %+v", res.exit)
	}
	if ran.Load() {
		t.Fatal("canceled run executed")
	}
	// The connection stays usable.
	writeAuthFrame(t, c, 41, []string{"ls"})
	if resp := readAuth(t, c); !resp.OK {
		t.Fatalf("after cancel: %+v", resp)
	}
}

// Cancel also ends a four-eyes wait reached through Authorize.
func TestSSHMonitorCancelEndsAuthorizeFourEyesWait(t *testing.T) {
	t.Setenv("ADSSH_4EYES_WEBHOOK", "")
	eng, _, _ := chainEngine(t)
	if err := eng.AddFourEyesRule("rm *", "", 60); err != nil {
		t.Fatal(err)
	}
	id := "auth-cancel"
	sess := &sys.Session{ID: id, User: "bob"}
	registerTestSession(t, sess)
	sess.SetPromptWriter(io.Discard)
	c := dialMonitorRun(t, id, func(ctx context.Context, args []string) error {
		return eng.AuthorizeCommandContext(ctx, args, id)
	}, nil)
	writeAuthFrame(t, c, 7, []string{"rm", "-rf", "/srv"})
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, _ := os.ReadDir(eng.fourEyesPendingDir())
		if len(entries) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no pending request")
		}
		time.Sleep(10 * time.Millisecond)
	}
	body, _ := json.Marshal(sys.MonitorCancel{ID: 7})
	start := time.Now()
	if err := sys.WriteMonitorFrame(c, sys.MonitorFrameCancel, body); err != nil {
		t.Fatal(err)
	}
	resp := readAuth(t, c)
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("cancel took %v", time.Since(start))
	}
	if resp.OK || !strings.Contains(resp.Error, "cancel") || resp.ID != 7 {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestSSHMonitorRunElevateActivatesListenerSession(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`package adssh.authz
default allow = false
allow { input.command != "deploy" }
allow { input.command == "deploy"; input.elevation.role == "ops" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	id := "run-elevate"
	sess := &sys.Session{ID: id, User: "bob"}
	registerTestSession(t, sess)
	gate := func(ctx context.Context, args []string) error { return eng.AuthorizeCommandContext(ctx, args, id) }
	run := func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return eng.RunVBinForSession(ctx, id, args, stdin, stdout, stderr)
	}
	c := dialMonitorRun(t, id, gate, run)

	// Before: the listener denies deploy.
	writeAuthFrame(t, c, 10, []string{"deploy"})
	if resp := readAuth(t, c); resp.OK {
		t.Fatal("deploy allowed before elevation")
	}
	sendRun(t, c, 11, []string{"elevate", "request", "ops", "--reason", "x"}, nil)
	res := readRun(t, c, 11)
	if res.exit.Code != 0 || res.exit.Error != "" || !strings.Contains(res.stdout.String(), "elevate: role=ops") {
		t.Fatalf("exit=%+v stdout=%q stderr=%q", res.exit, res.stdout.String(), res.stderr.String())
	}
	if res.exit.Digest != sys.MonitorRunDigest([]string{"elevate", "request", "ops", "--reason", "x"}, sys.MonitorStdinNone, nil) {
		t.Fatal("exit digest")
	}
	if e := sess.ActiveElevation(); e == nil || e.Role != "ops" {
		t.Fatalf("listener session elevation = %+v", e)
	}
	writeAuthFrame(t, c, 12, []string{"deploy"})
	if resp := readAuth(t, c); !resp.OK {
		t.Fatalf("deploy after elevation: %+v", resp)
	}
}

// grant writes to the handler's stdout, so the message reaches an SSH user.
// Over Run only drop is accepted.
func TestSSHMonitorRunGrantOutputReachesClient(t *testing.T) {
	eng, _, _ := chainEngine(t)
	id := "run-grant"
	registerTestSession(t, &sys.Session{ID: id, User: "bob", Principals: []string{"ops"}})
	gate, run := listenerRun(eng, id)
	c := dialMonitorRun(t, id, gate, run)
	sendRun(t, c, 2, []string{"grant", "drop", "ops"}, nil)
	res := readRun(t, c, 2)
	if !strings.Contains(res.stdout.String(), "grant: successfully dropped role 'ops'") {
		t.Fatalf("drop stdout=%q", res.stdout.String())
	}
}

// mirror share over Run creates the grant on the listener-side session.
func TestSSHMonitorRunMirrorShareGrantsInListener(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	id := "run-mirror-share"
	registerTestSession(t, &sys.Session{ID: id, User: "alice"})
	t.Cleanup(func() { clearMirrorGrants(id) })
	gate, run := listenerRun(eng, id)
	c := dialMonitorRun(t, id, gate, run)
	sendRun(t, c, 1, []string{"mirror", "share", "--with", "bob", "--for", "5m"}, nil)
	res := readRun(t, c, 1)
	if res.exit.Code != 0 || res.exit.Error != "" {
		t.Fatalf("exit=%+v stderr=%q", res.exit, res.stderr.String())
	}
	mirrorGrantsMu.Lock()
	g := mirrorGrants[id]["bob"]
	mirrorGrantsMu.Unlock()
	if g == nil || g.owner != "alice" || g.console {
		t.Fatalf("listener grant = %+v", g)
	}
	ledger, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ledger), "MIRROR_SHARE: session="+id+" owner=alice with=bob mode=view") {
		t.Fatalf("chain missing share:\n%s", ledger)
	}
	sendRun(t, c, 2, []string{"mirror", "unshare", "--with", "bob"}, nil)
	if res := readRun(t, c, 2); res.exit.Error != "" {
		t.Fatalf("unshare exit=%+v", res.exit)
	}
	mirrorGrantsMu.Lock()
	g = mirrorGrants[id]["bob"]
	mirrorGrantsMu.Unlock()
	if g != nil {
		t.Fatal("unshare left the grant")
	}
	// whoami runs in the listener too.
	sendRun(t, c, 3, []string{"whoami"}, nil)
	if res := readRun(t, c, 3); res.exit.Error != "" || !strings.Contains(res.stdout.String(), "alice") {
		t.Fatalf("whoami exit=%+v stdout=%q", res.exit, res.stdout.String())
	}
}
