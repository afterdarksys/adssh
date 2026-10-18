//go:build ee

package security

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

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
