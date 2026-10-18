package security

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

const psqlNeedsDBA = `package adssh.authz
default allow = false
allow { input.command != "psql" }
allow { input.command == "psql"; input.groups[_] == "dba" }
`

// Elevation still reaches input.groups and input.elevation for a bound identity.
func TestBoundIdentityMergesElevation(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	id := "scope-elev"
	sess := &sys.Session{ID: id, User: "bob", Principals: []string{"dev"}}
	registerTestSession(t, sess)
	if err := eng.BindSessionIdentity(id, "bob", []string{"dev"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.UnbindSessionIdentity(id) })
	sess.ActivateElevation("ops", "fix", time.Now().Add(time.Hour))
	pctx := eng.buildPolicyContext("x", nil, id)
	if pctx.User != "bob" || len(pctx.Groups) != 2 || pctx.Groups[0] != "dev" || pctx.Groups[1] != "ops" {
		t.Fatalf("groups = %v user=%q", pctx.Groups, pctx.User)
	}
	if pctx.Elevation == nil || pctx.Elevation.Role != "ops" {
		t.Fatalf("elevation = %+v", pctx.Elevation)
	}
}

// Probe: 4eyes rm "rm *" over Run emptied the listener's rules.
func TestSSHRunFourEyesRuleChangesRefused(t *testing.T) {
	id := "scope-4eyes"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	var gateCalls, runCalls atomic.Int32
	c := dialMonitorRun(t, id, func(context.Context, []string) error {
		gateCalls.Add(1)
		return nil
	}, func(context.Context, []string, io.Reader, io.Writer, io.Writer) (int, error) {
		runCalls.Add(1)
		return 0, nil
	})
	next := uint64(0)
	for _, args := range [][]string{
		{"4eyes", "rm", "rm *"},
		{"4eyes", "remove", "rm *"},
		{"4eyes", "add", "*"},
	} {
		next++
		sendRun(t, c, next, args, nil)
		res := readRun(t, c, next)
		if res.exit.Code == 0 || !strings.Contains(res.exit.Error, "changes listener rules; use a local session or the admin API") {
			t.Fatalf("%v: exit=%+v", args, res.exit)
		}
	}
	if gateCalls.Load() != 0 || runCalls.Load() != 0 {
		t.Fatalf("gate=%d run=%d", gateCalls.Load(), runCalls.Load())
	}
	for _, args := range [][]string{{"4eyes", "approve", "x"}, {"4eyes", "deny", "x"}, {"4eyes", "pending"}, {"4eyes", "list"}} {
		if err := sshListenerRunRefusal(args); err != nil {
			t.Fatalf("%v refused: %v", args, err)
		}
	}
}

// Probe: gateway start --listen 0.0.0.0:0 over Run.
func TestSSHRunGatewayStartRefused(t *testing.T) {
	id := "scope-gw"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	var runCalls atomic.Int32
	c := dialMonitorRun(t, id, allowGate, func(context.Context, []string, io.Reader, io.Writer, io.Writer) (int, error) {
		runCalls.Add(1)
		return 0, nil
	})
	sendRun(t, c, 1, []string{"gateway", "start", "--listen", "0.0.0.0:0", "--target", "127.0.0.1:22"}, nil)
	res := readRun(t, c, 1)
	if res.exit.Code == 0 || !strings.Contains(res.exit.Error, "not available in an SSH session") || runCalls.Load() != 0 {
		t.Fatalf("exit=%+v runs=%d", res.exit, runCalls.Load())
	}
	for _, args := range [][]string{{"gateway", "list"}, {"gateway", "stop", "gw-1"}} {
		if err := sshListenerRunRefusal(args); err != nil {
			t.Fatalf("%v refused: %v", args, err)
		}
	}
}

func TestSSHRunGlobalVBinsRefused(t *testing.T) {
	for _, args := range [][]string{
		{"guard", "unban", "203.0.113.1"},
		{"guard", "reload"},
		{"guard", "--json", "reload"},
		{"guard", "list"},
		{"admin", "sessions"},
		{"admin", "approvals"},
		{"admin", "gateways"},
		{"grant", "request", "dba"},
		{"evidence", "--session", "someone-else"},
		{"evidence", "--change", "--session", "--session", "someone-else"},
		{"evidence", "--session", "own-session", "--session", "someone-else"},
		{"mirror", "kill", "someone-else"},
		{"grid", "drain"},
	} {
		if _, err := sshListenerRunArgs("own-session", args); err == nil {
			t.Fatalf("%v accepted over Run", args)
		}
	}
	for _, args := range [][]string{
		{"guard", "status"},
		{"guard", "status", "--json"},
		{"guard", "--json", "status"},
		{"cm", "set", "CHG1"},
		{"cm", "status"},
		{"cm", "clear"},
		{"cm", "require", "rm*"},
		{"evidence", "--session", "own-session"},
		{"mirror", "kill", "own-session"},
	} {
		if _, err := sshListenerRunArgs("own-session", args); err != nil {
			t.Fatalf("%v refused: %v", args, err)
		}
	}
}

func gatewayAdminEngine(t *testing.T) *Engine {
	t.Helper()
	t.Setenv("ADSSH_GATEWAY_LOG", t.TempDir()+"/gw.jsonl")
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func bindTest(t *testing.T, eng *Engine, id, user string, groups ...string) {
	t.Helper()
	registerTestSession(t, &sys.Session{ID: id, User: user, Principals: groups})
	if err := eng.BindSessionIdentity(id, user, groups); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.UnbindSessionIdentity(id) })
}

// writeBlockConn accepts reads from the peer but never drains writes.
func TestSSHMonitorWriteDeadlineMarksBroken(t *testing.T) {
	prev := sshMonitorWriteTimeout
	sshMonitorWriteTimeout = 100 * time.Millisecond
	defer func() { sshMonitorWriteTimeout = prev }()
	id := "scope-deadline"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	server, client := net.Pipe()
	defer client.Close()
	canceled := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeSSHMonitorRun(server, id, allowGate, func(ctx context.Context, _ []string, _ io.Reader, stdout, _ io.Writer) (int, error) {
			_, _ = stdout.Write([]byte("hello"))
			select {
			case <-ctx.Done():
				close(canceled)
			case <-time.After(5 * time.Second):
			}
			return 0, nil
		})
	}()
	sendRun(t, client, 1, []string{"whoami"}, nil)
	// The client never reads again.
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("a stalled reader did not cancel the run")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("listener goroutine pinned by a stalled reader")
	}
}

func TestSSHMonitorCancelBeforeRunHonoured(t *testing.T) {
	id := "scope-precancel"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	var runCalls atomic.Int32
	c := dialMonitorRun(t, id, allowGate, func(ctx context.Context, _ []string, _ io.Reader, _, _ io.Writer) (int, error) {
		runCalls.Add(1)
		return 0, nil
	})
	writeAuthFrame(t, c, 40, []string{"true"})
	if resp := readAuth(t, c); !resp.OK {
		t.Fatalf("auth: %+v", resp)
	}
	body, _ := json.Marshal(sys.MonitorCancel{ID: 41})
	if err := sys.WriteMonitorFrame(c, sys.MonitorFrameCancel, body); err != nil {
		t.Fatal(err)
	}
	sendRun(t, c, 41, []string{"whoami"}, nil)
	res := readRun(t, c, 41)
	if res.exit.Code == 0 || !strings.Contains(res.exit.Error, "cancel") || runCalls.Load() != 0 {
		t.Fatalf("exit=%+v runs=%d", res.exit, runCalls.Load())
	}
	// The next request is not affected.
	sendRun(t, c, 42, []string{"whoami"}, nil)
	if res := readRun(t, c, 42); res.exit.Code != 0 || runCalls.Load() != 1 {
		t.Fatalf("after cancel: exit=%+v runs=%d", res.exit, runCalls.Load())
	}
}

// testHandlerCtx is a context carrying an interp handler context with
// discarded output, so a vbin's Run can be called directly.
func testHandlerCtx() context.Context {
	var hctx context.Context
	runner, err := interp.New(
		interp.StdIO(nil, io.Discard, io.Discard),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			hctx = ctx
			return nil
		}),
	)
	if err != nil {
		panic(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("capture"), "")
	if err != nil {
		panic(err)
	}
	if err := runner.Run(context.Background(), file); err != nil && !errors.Is(err, context.Canceled) {
		panic(err)
	}
	return hctx
}
