package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
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

// Probe: certificate principal dev -> grant request dba -> psql allowed.
func TestSSHRunGrantRequestCannotAddGroup(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte(psqlNeedsDBA)})
	if err != nil {
		t.Fatal(err)
	}
	id := "scope-grant"
	sess := &sys.Session{ID: id, User: "bob", Principals: []string{"dev"}}
	registerTestSession(t, sess)
	if err := eng.BindSessionIdentity(id, "bob", []string{"dev"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.UnbindSessionIdentity(id) })
	gate, run := listenerRun(eng, id)
	c := dialMonitorRun(t, id, gate, run)

	sendRun(t, c, 1, []string{"grant", "request", "dba"}, nil)
	res := readRun(t, c, 1)
	if res.exit.Code == 0 || !strings.Contains(res.exit.Error, "not available in an SSH session") {
		t.Fatalf("grant request over Run: exit=%+v stdout=%q", res.exit, res.stdout.String())
	}
	writeAuthFrame(t, c, 2, []string{"psql"})
	if resp := readAuth(t, c); resp.OK {
		t.Fatal("psql allowed after grant request")
	}

	// Even a grant that reaches the session object (a local dispatch)
	// does not change the bound groups policy sees.
	if err := (grantBinary{}).Run(WithSessionID(testHandlerCtx(), id), []string{"grant", "request", "dba"}); err != nil {
		t.Fatal(err)
	}
	if err := eng.AuthorizeCommandContext(context.Background(), []string{"psql"}, id); err == nil {
		t.Fatal("psql allowed for a bound identity after grant request")
	}
	// drop is still accepted over Run.
	if err := sshListenerRunRefusal([]string{"grant", "drop", "dba"}); err != nil {
		t.Fatalf("grant drop refused: %v", err)
	}
}

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

func TestSSHRunEvidenceScopedToOwnSession(t *testing.T) {
	eng, _, _ := chainEngine(t)
	id := "scope-evidence"
	registerTestSession(t, &sys.Session{ID: id, User: "bob"})
	if err := eng.AppendChain(ChainEntry{SessionID: "other-session", Type: "event", Command: "OTHER-SECRET"}); err != nil {
		t.Fatal(err)
	}
	if err := eng.AppendChain(ChainEntry{SessionID: id, Type: "event", Command: "MINE"}); err != nil {
		t.Fatal(err)
	}
	gate, run := listenerRun(eng, id)
	c := dialMonitorRun(t, id, gate, run)

	sendRun(t, c, 1, []string{"evidence", "--session", "other-session"}, nil)
	res := readRun(t, c, 1)
	if res.exit.Code == 0 || strings.Contains(res.stdout.String(), "OTHER-SECRET") {
		t.Fatalf("evidence --session other: exit=%+v", res.exit)
	}
	sendRun(t, c, 2, []string{"evidence"}, nil)
	res = readRun(t, c, 2)
	if res.exit.Code != 0 {
		t.Fatalf("evidence: exit=%+v stderr=%q", res.exit, res.stderr.String())
	}
	var bundle EvidenceBundle
	if err := json.Unmarshal(res.stdout.Bytes(), &bundle); err != nil {
		t.Fatalf("bundle %q: %v", res.stdout.String(), err)
	}
	if bundle.Filter.SessionID != id || strings.Contains(res.stdout.String(), "OTHER-SECRET") || !strings.Contains(res.stdout.String(), "MINE") {
		t.Fatalf("bundle filter=%+v out=%s", bundle.Filter, res.stdout.String())
	}
	sendRun(t, c, 3, []string{"evidence", "--session", id}, nil)
	if res := readRun(t, c, 3); res.exit.Code != 0 {
		t.Fatalf("evidence --session own: exit=%+v", res.exit)
	}
}

func runGatewayAs(t *testing.T, eng *Engine, sessionID string, args []string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(WithSessionID(ctx, sessionID), gatewayBinary{}, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("gateway-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	return out.String(), runErr
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

func gatewayExists(id string) bool {
	gatewayMu.RLock()
	defer gatewayMu.RUnlock()
	return gatewaySessions[id] != nil
}

func TestGatewayStopOwnerOnly(t *testing.T) {
	target, closeTarget := startGatewayEchoServer(t)
	defer closeTarget()
	eng := gatewayAdminEngine(t)
	bindTest(t, eng, "gw-owner", "alice")
	bindTest(t, eng, "gw-other", "bob")
	bindTest(t, eng, "gw-admin", "root", RoleAdsshAdmin)

	out, err := runGatewayAs(t, eng, "gw-owner", []string{"gateway", "start", "--listen", "127.0.0.1:0", "--target", target})
	if err != nil {
		t.Fatal(err)
	}
	gw, _ := parseGatewayStartOutput(t, out)
	t.Cleanup(func() { _, _ = runGatewayAs(t, eng, "gw-admin", []string{"gateway", "stop", gw}) })

	if _, err := runGatewayAs(t, eng, "gw-other", []string{"gateway", "stop", gw}); err == nil || !gatewayExists(gw) {
		t.Fatalf("another session stopped the gateway: %v", err)
	}
	if _, err := runGatewayAs(t, eng, "gw-admin", []string{"gateway", "stop", gw}); err != nil || gatewayExists(gw) {
		t.Fatalf("admin stop: %v", err)
	}

	out, err = runGatewayAs(t, eng, "gw-owner", []string{"gateway", "start", "--listen", "127.0.0.1:0", "--target", target})
	if err != nil {
		t.Fatal(err)
	}
	gw2, _ := parseGatewayStartOutput(t, out)
	if _, err := runGatewayAs(t, eng, "gw-owner", []string{"gateway", "stop", gw2}); err != nil || gatewayExists(gw2) {
		t.Fatalf("owner stop: %v", err)
	}
}

func TestGatewayListOverRunShowsOwnOnly(t *testing.T) {
	target, closeTarget := startGatewayEchoServer(t)
	defer closeTarget()
	eng := gatewayAdminEngine(t)
	bindTest(t, eng, "gwl-mine", "alice")
	bindTest(t, eng, "gwl-theirs", "bob")
	out, err := runGatewayAs(t, eng, "gwl-theirs", []string{"gateway", "start", "--listen", "127.0.0.1:0", "--target", target, "--name", "theirs"})
	if err != nil {
		t.Fatal(err)
	}
	theirs, _ := parseGatewayStartOutput(t, out)
	t.Cleanup(func() { _, _ = runGatewayAs(t, eng, "gwl-theirs", []string{"gateway", "stop", theirs}) })
	var stdout, stderr bytes.Buffer
	// The monitor marks a Run's context; RunVBinForSession carries it.
	if _, err := eng.RunVBinForSession(withSSHRun(context.Background()), "gwl-mine", []string{"gateway", "list"}, nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), theirs+" ") {
		t.Fatalf("Run list shows another session's gateway:\n%s", stdout.String())
	}
	// A local list still shows every gateway.
	stdout.Reset()
	if _, err := eng.RunVBinForSession(context.Background(), "gwl-mine", []string{"gateway", "list"}, nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), theirs+" ") {
		t.Fatalf("local list:\n%s", stdout.String())
	}
}

func TestGatewayTornDownOnUnregister(t *testing.T) {
	target, closeTarget := startGatewayEchoServer(t)
	defer closeTarget()
	eng := gatewayAdminEngine(t)
	id := "gw-unreg"
	if err := sys.RegisterSession(&sys.Session{ID: id, User: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := eng.BindSessionIdentity(id, "alice", nil); err != nil {
		t.Fatal(err)
	}
	defer eng.UnbindSessionIdentity(id)
	out, err := runGatewayAs(t, eng, id, []string{"gateway", "start", "--listen", "127.0.0.1:0", "--target", target})
	if err != nil {
		sys.UnregisterSession(id)
		t.Fatal(err)
	}
	gw, listen := parseGatewayStartOutput(t, out)
	sys.UnregisterSession(id)
	if gatewayExists(gw) {
		t.Fatal("gateway survived its session")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", listen, 200*time.Millisecond)
		if err != nil {
			break
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("gateway listener still accepting")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestGatewayListenRestrictions(t *testing.T) {
	eng := gatewayAdminEngine(t)
	bindTest(t, eng, "gwr-user", "alice")
	bindTest(t, eng, "gwr-admin", "root", RoleAdsshAdmin)
	for _, args := range [][]string{
		{"gateway", "start", "--listen", "0.0.0.0:0", "--target", "127.0.0.1:22"},
		{"gateway", "start", "--listen", "0.0.0.0:0", "--listen-any", "--target", "127.0.0.1:22"},
		{"gateway", "start", "--listen", "127.0.0.1:80", "--target", "127.0.0.1:22"},
	} {
		if _, err := runGatewayAs(t, eng, "gwr-user", args); err == nil {
			t.Fatalf("%v allowed for a non-admin", args)
		}
	}
	// An admin still needs --listen-any for a non-loopback address.
	if _, err := runGatewayAs(t, eng, "gwr-admin", []string{"gateway", "start", "--listen", "0.0.0.0:0", "--target", "127.0.0.1:22"}); err == nil {
		t.Fatal("non-loopback listen without --listen-any")
	}
	out, err := runGatewayAs(t, eng, "gwr-admin", []string{"gateway", "start", "--listen", "0.0.0.0:0", "--listen-any", "--target", "127.0.0.1:22"})
	if err != nil {
		t.Fatalf("admin --listen-any: %v", err)
	}
	gw, _ := parseGatewayStartOutput(t, out)
	if _, err := runGatewayAs(t, eng, "gwr-admin", []string{"gateway", "stop", gw}); err != nil {
		t.Fatal(err)
	}
}

func TestMirrorGrantsClearedOnUnregister(t *testing.T) {
	eng, _, _ := chainEngine(t)
	id := "mirror-unreg"
	if err := sys.RegisterSession(&sys.Session{ID: id, User: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := eng.shareMirror(id, "bob", time.Hour, false); err != nil {
		sys.UnregisterSession(id)
		t.Fatal(err)
	}
	sys.UnregisterSession(id)
	mirrorGrantsMu.Lock()
	left := mirrorGrants[id]
	mirrorGrantsMu.Unlock()
	if left != nil {
		t.Fatalf("grants survived the session: %v", left)
	}
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

// grant and policy reads of a session's principals do not race.
func TestPrincipalsNoRaceWithPolicyReads(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	id := "scope-race"
	registerTestSession(t, &sys.Session{ID: id, User: "bob", Principals: []string{"dev"}})
	ctx := WithSessionID(testHandlerCtx(), id)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = eng.buildPolicyContext("x", nil, id)
				_ = sys.GetSession(id).Info()
			}
		}()
	}
	for i := 0; i < 200; i++ {
		_ = (grantBinary{}).Run(ctx, []string{"grant", "request", "ops"})
		_ = (grantBinary{}).Run(ctx, []string{"grant", "drop", "ops"})
	}
	close(stop)
	wg.Wait()
	if got := sys.GetSession(id).PrincipalList(); len(got) != 1 || got[0] != "dev" {
		t.Fatalf("principals = %v", got)
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
