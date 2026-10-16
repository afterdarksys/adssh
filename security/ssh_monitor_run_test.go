package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func dialMonitorRun(t *testing.T, sessionID string, gate func(context.Context, []string) error, run SSHRunFunc) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		<-done
	})
	go func() {
		defer close(done)
		ServeSSHMonitorRun(server, sessionID, gate, run)
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	return client
}

func sendRun(t *testing.T, c net.Conn, id uint64, args []string, stdin []byte) {
	t.Helper()
	req := sys.MonitorRunRequest{ID: id, Args: args, StdinMode: sys.MonitorStdinNone}
	if stdin != nil {
		req.StdinMode = sys.MonitorStdinBytes
		req.Stdin = stdin
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.WriteMonitorFrame(c, sys.MonitorFrameRun, body); err != nil {
		t.Fatal(err)
	}
}

type runResult struct {
	stdout, stderr bytes.Buffer
	exit           sys.MonitorExit
}

// readRun reads Out frames until the Exit frame for id.
func readRun(t *testing.T, c net.Conn, id uint64) *runResult {
	t.Helper()
	res := &runResult{}
	var seq uint64
	for {
		typ, payload, err := sys.ReadMonitorFrame(c)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch typ {
		case sys.MonitorFrameOut:
			var out sys.MonitorOut
			if err := json.Unmarshal(payload, &out); err != nil {
				t.Fatal(err)
			}
			seq++
			if out.ID != id || out.Seq != seq {
				t.Fatalf("out id=%d seq=%d want id=%d seq=%d", out.ID, out.Seq, id, seq)
			}
			if len(out.Data) > sys.MaxMonitorOutChunk {
				t.Fatalf("chunk %d", len(out.Data))
			}
			if out.Stream == sys.MonitorStreamStdout {
				res.stdout.Write(out.Data)
			} else {
				res.stderr.Write(out.Data)
			}
		case sys.MonitorFrameExit:
			if err := json.Unmarshal(payload, &res.exit); err != nil {
				t.Fatal(err)
			}
			if res.exit.ID != id {
				t.Fatalf("exit id=%d want %d", res.exit.ID, id)
			}
			return res
		default:
			t.Fatalf("frame type %d", typ)
		}
	}
}

func allowGate(context.Context, []string) error { return nil }

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

func writeAuthFrame(t *testing.T, c net.Conn, id uint64, args []string) {
	t.Helper()
	body, err := json.Marshal(sys.MonitorAuthRequest{ID: id, Args: args})
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.WriteMonitorFrame(c, sys.MonitorFrameAuthorize, body); err != nil {
		t.Fatal(err)
	}
}

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

func TestSSHMonitorRunWhyReportsListenerPolicy(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(`package adssh.authz
default allow = false
allow { input.command != "rm" }
deny_reason = "listener-policy-says-no" { input.command == "rm" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	id := "run-why"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	c := dialMonitorRun(t, id, func(ctx context.Context, args []string) error {
		return eng.AuthorizeCommandContext(ctx, args, id)
	}, func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return eng.RunVBinForSession(ctx, id, args, stdin, stdout, stderr)
	})
	sendRun(t, c, 1, []string{"why", "--json", "--", "rm"}, nil)
	res := readRun(t, c, 1)
	if res.exit.Code != 0 || res.exit.Error != "" {
		t.Fatalf("exit=%+v stderr=%q", res.exit, res.stderr.String())
	}
	var exp CommandExplanation
	if err := json.Unmarshal(res.stdout.Bytes(), &exp); err != nil {
		t.Fatalf("why output %q: %v", res.stdout.String(), err)
	}
	if exp.Outcome != "denied" {
		t.Fatalf("outcome = %q", exp.Outcome)
	}
	if strings.Contains(res.stdout.String(), "evaluated by the listener") {
		t.Fatal("why ran against an empty engine")
	}
}

func TestSSHMonitorRunRefusals(t *testing.T) {
	id := "run-refuse"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	var gateCalls, runCalls atomic.Int32
	c := dialMonitorRun(t, id, func(context.Context, []string) error {
		gateCalls.Add(1)
		return nil
	}, func(context.Context, []string, io.Reader, io.Writer, io.Writer) (int, error) {
		runCalls.Add(1)
		return 0, nil
	})
	next := uint64(20)
	for _, args := range [][]string{
		{"mirror", "console", "other"},
		{"mirror", "view", "other"},
		{"plugin", "load", "x"},
		{"lease", "--from", "env:X", "--via", "env", "--", "id"},
		{"identity", "ssh-ca", "init", "--out", "/etc/x"},
		{"grid", "init", "--token-out", "/etc/x"},
		{"flight", "place", "--id", "f"},
		{"worktree", "checkout", "--id", "w", "--from", "/root", "--rev", "abc"},
		{"repo", "cat", "--id", "w", "--path", "x"},
		{"admin", "serve"},
		{"admin", "evidence", "--out", "/etc/x"},
		{"evidence", "--out", "/etc/x"},
		{"jq", "."},
		{"ls"},
	} {
		next++
		sendRun(t, c, next, args, nil)
		res := readRun(t, c, next)
		if res.exit.Error == "" || res.exit.Code == 0 || !strings.Contains(res.exit.Error, "not available in an SSH session") {
			t.Fatalf("%v: exit = %+v", args, res.exit)
		}
	}
	if gateCalls.Load() != 0 || runCalls.Load() != 0 {
		t.Fatalf("gate=%d run=%d for refused runs", gateCalls.Load(), runCalls.Load())
	}
}

func TestSSHMonitorRunWhileInFlightRejected(t *testing.T) {
	id := "run-busy"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	var runCalls atomic.Int32
	c := dialMonitorRun(t, id, allowGate, func(ctx context.Context, args []string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		runCalls.Add(1)
		started <- struct{}{}
		<-release
		_, _ = io.WriteString(stdout, "first")
		return 0, nil
	})
	sendRun(t, c, 5, []string{"elevate", "status"}, nil)
	<-started
	sendRun(t, c, 6, []string{"elevate", "status"}, nil)
	res := readRun(t, c, 6)
	if res.exit.Error == "" || !strings.Contains(res.exit.Error, "in flight") {
		t.Fatalf("second run exit = %+v", res.exit)
	}
	close(release)
	res = readRun(t, c, 5)
	if res.exit.Error != "" || res.stdout.String() != "first" {
		t.Fatalf("first run exit=%+v stdout=%q", res.exit, res.stdout.String())
	}
	if runCalls.Load() != 1 {
		t.Fatalf("run calls = %d", runCalls.Load())
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

func TestSSHMonitorRunTruncatesOutput(t *testing.T) {
	id := "run-trunc"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	c := dialMonitorRun(t, id, allowGate, func(_ context.Context, _ []string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		chunk := bytes.Repeat([]byte("z"), 100<<10)
		for i := 0; i < 12; i++ {
			if _, err := stdout.Write(chunk); err != nil {
				return 1, err
			}
		}
		return 7, nil
	})
	sendRun(t, c, 2, []string{"whoami"}, nil)
	res := readRun(t, c, 2)
	if res.stdout.Len() != sys.MaxMonitorRunOutput {
		t.Fatalf("stdout = %d bytes", res.stdout.Len())
	}
	if !strings.Contains(res.stderr.String(), "output truncated") {
		t.Fatalf("no truncation marker: %q", res.stderr.String())
	}
	if res.exit.Code != 7 || res.exit.Error != "" {
		t.Fatalf("exit = %+v", res.exit)
	}
}

func TestSSHMonitorRunStdinReachesVBin(t *testing.T) {
	id := "run-stdin"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	c := dialMonitorRun(t, id, allowGate, func(_ context.Context, _ []string, stdin io.Reader, stdout, _ io.Writer) (int, error) {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return 1, err
		}
		_, _ = stdout.Write(append([]byte("got:"), data...))
		return 0, nil
	})
	sendRun(t, c, 8, []string{"why", "--", "rm"}, []byte("piped input"))
	res := readRun(t, c, 8)
	if res.stdout.String() != "got:piped input" {
		t.Fatalf("stdout = %q", res.stdout.String())
	}
	if res.exit.Digest != sys.MonitorRunDigest([]string{"why", "--", "rm"}, sys.MonitorStdinBytes, []byte("piped input")) {
		t.Fatal("digest does not cover stdin")
	}
}

func TestSSHMonitorRunProtocolErrorsClose(t *testing.T) {
	cases := []struct {
		name string
		send func(t *testing.T, c net.Conn)
	}{
		{name: "session id field", send: func(t *testing.T, c net.Conn) {
			_ = sys.WriteMonitorFrame(c, sys.MonitorFrameRun, []byte(`{"id":1,"args":["why"],"stdin_mode":"none","session_id":"other"}`))
		}},
		{name: "malformed run", send: func(t *testing.T, c net.Conn) {
			_ = sys.WriteMonitorFrame(c, sys.MonitorFrameRun, []byte(`{`))
		}},
		{name: "malformed cancel", send: func(t *testing.T, c net.Conn) {
			_ = sys.WriteMonitorFrame(c, sys.MonitorFrameCancel, []byte(`{"id":0}`))
		}},
		{name: "skipped id", send: func(t *testing.T, c net.Conn) {
			sendRun(t, c, 1, []string{"why", "--", "rm"}, nil)
			_ = readRun(t, c, 1)
			sendRun(t, c, 3, []string{"why", "--", "rm"}, nil)
		}},
		{name: "out from child", send: func(t *testing.T, c net.Conn) {
			_ = sys.WriteMonitorFrame(c, sys.MonitorFrameOut, []byte(`{"id":1,"seq":1,"stream":1,"data":""}`))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := "run-proto-" + strings.ReplaceAll(tc.name, " ", "-")
			registerTestSession(t, &sys.Session{ID: id, User: "bob"})
			c := dialMonitorRun(t, id, allowGate, func(context.Context, []string, io.Reader, io.Writer, io.Writer) (int, error) {
				return 0, nil
			})
			tc.send(t, c)
			if _, _, err := sys.ReadMonitorFrame(c); err == nil {
				t.Fatal("connection stayed open")
			}
		})
	}
}

// The child routes listener-run vbins to the remote runner, with stdin, and
// the call gate does not authorize them locally.
func TestRemoteGateProcessRoutesRunToListener(t *testing.T) {
	rec := installRemoteGateProcess(t)
	type call struct {
		args  []string
		mode  string
		stdin string
	}
	var calls []call
	SetRemoteRun(func(args []string, mode string, stdin []byte, stdout, stderr io.Writer) (int, error) {
		calls = append(calls, call{append([]string(nil), args...), mode, string(stdin)})
		switch args[0] {
		case "why":
			_, _ = io.WriteString(stdout, "from-listener\n")
			return 0, nil
		case "guard":
			return 4, nil
		}
		return 1, errors.New("listener says no")
	})
	t.Cleanup(func() { SetRemoteRun(nil) })
	eng := DefaultEngine()
	run := func(src string) (string, error) {
		var out, errOut strings.Builder
		sess := &SessionState{Globals: starlark.StringDict{}, SessionID: "ssh-child"}
		runner, err := interp.New(
			interp.StdIO(nil, &out, &errOut),
			interp.CallHandler(eng.CallInterceptorSession(sess)),
			interp.ExecHandlers(eng.BashInterceptorSession(sess)),
		)
		if err != nil {
			t.Fatal(err)
		}
		prog, err := syntax.NewParser().Parse(strings.NewReader(src), "")
		if err != nil {
			t.Fatal(err)
		}
		err = runner.Run(context.Background(), prog)
		return out.String(), err
	}
	if out, err := run("why -- rm"); err != nil || out != "from-listener\n" {
		t.Fatalf("why: out=%q err=%v", out, err)
	}
	if _, err := run("command 4eyes approve abc"); err == nil || err.Error() != "listener says no" {
		t.Fatalf("command 4eyes: %v", err)
	}
	var status interp.ExitStatus
	if _, err := run("guard status"); !errors.As(err, &status) || status != 4 {
		t.Fatalf("guard exit: %v", err)
	}
	if _, err := run("echo piped | why -- rm"); err != nil {
		t.Fatal(err)
	}
	if rec.saw("why") || rec.saw("4eyes") || rec.saw("guard") {
		t.Fatal("a listener-run vbin was authorized locally")
	}
	if len(calls) != 4 || calls[0].mode != sys.MonitorStdinNone || calls[3].stdin != "piped\n" || calls[3].mode != sys.MonitorStdinBytes {
		t.Fatalf("calls = %+v", calls)
	}
	// Interactive and plugin-loading vbins stay refused in the child.
	if _, err := run("mirror console x"); err == nil || !strings.Contains(err.Error(), "mirror: "+sshRefusalText) {
		t.Fatalf("mirror console: %v", err)
	}
	if _, err := run("plugin load x"); err == nil || !strings.Contains(err.Error(), "plugin: "+sshRefusalText) {
		t.Fatalf("plugin load: %v", err)
	}
	if len(calls) != 4 {
		t.Fatal("a refused vbin reached the listener runner")
	}
}

func listenerRun(eng *Engine, id string) (func(context.Context, []string) error, SSHRunFunc) {
	return func(ctx context.Context, args []string) error {
			return eng.AuthorizeCommandContext(ctx, args, id)
		}, func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
			return eng.RunVBinForSession(ctx, id, args, stdin, stdout, stderr)
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

func TestSSHRunsInListenerMirrorShare(t *testing.T) {
	for _, args := range [][]string{{"mirror", "share", "--with", "bob", "--for", "5m"}, {"mirror", "unshare"}, {"mirror", "kill", "x"}, {"whoami"}} {
		if !sshRunsInListener(args) || sshListenerRunRefusal(args) != nil {
			t.Fatalf("%v does not run in the listener", args)
		}
	}
	for _, args := range [][]string{{"mirror", "list"}, {"mirror", "view", "x"}, {"mirror", "console", "x"}} {
		if sshRunsInListener(args) {
			t.Fatalf("%v routed to the listener", args)
		}
	}
}

// The gate's [POLICY] audit line carries the decision's rule and required
// entitlement, on deny and on allow.
func TestGatePolicyAuditCarriesRule(t *testing.T) {
	dir := t.TempDir()
	auditLog := dir + "/audit.log"
	eng, err := NewEngine(EngineConfig{AuditLogPath: auditLog, PolicySource: []byte(`package adssh.authz
default allow = false
default rule = "default_deny"
default required_entitlement = ""
allow { input.command == "ls" }
rule = "read_only" { input.command == "ls" }
required_entitlement = "k8s-ops" { input.command == "kubectl" }
`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.AuthorizeCommand([]string{"kubectl", "apply"}, ""); err == nil {
		t.Fatal("kubectl allowed")
	}
	if err := eng.AuthorizeCommand([]string{"ls"}, ""); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(auditLog)
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	if !strings.Contains(log, `allowed=false`) || !strings.Contains(log, `rule="default_deny" required_entitlement="k8s-ops"`) {
		t.Fatalf("deny line missing detail:\n%s", log)
	}
	if !strings.Contains(log, `allowed=true reason="" rule="read_only"`) {
		t.Fatalf("allow line missing rule:\n%s", log)
	}
}
