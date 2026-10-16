package security

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
	"go.starlark.net/starlark"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

const sshRefusalText = "not available in an SSH session"

type remoteGateRecorder struct {
	mu    sync.Mutex
	calls [][]string
	ids   []string
}

func (r *remoteGateRecorder) gate(_ bool, args []string, sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string(nil), args...))
	r.ids = append(r.ids, sessionID)
	return nil
}

func (r *remoteGateRecorder) saw(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == name {
			return true
		}
	}
	return false
}

// installRemoteGateProcess marks this test process as an SSH login child with
// an allow-everything remote gate, so only the local refusal can deny.
func installRemoteGateProcess(t *testing.T) *remoteGateRecorder {
	t.Helper()
	rec := &remoteGateRecorder{}
	SetRemoteGate(rec.gate)
	MarkRemoteGateProcess()
	t.Cleanup(func() {
		SetRemoteGate(nil)
		remoteGateProcess.Store(false)
	})
	return rec
}

func TestRemoteGateProcessRefusesStatefulVBins(t *testing.T) {
	rec := installRemoteGateProcess(t)
	eng := DefaultEngine()
	for _, args := range [][]string{
		{"elevate", "request", "ops"},
		{"4eyes", "approve", "abc123"},
		{"gateway", "start", "--listen", "127.0.0.1:9000", "--target", "10.0.0.1:22"},
		{"why", "--", "rm"},
		{"??"},
		{"identity", "status"},
		{"cm", "set", "CHG-1"},
		{"lease", "list"},
		{"grant", "add", "x"},
		{"admin", "serve"},
		{"guard", "status"},
		{"grid", "status"},
		{"flight", "list"},
		{"agent", "list"},
		{"worktree", "list"},
		{"repo", "list"},
		{"evidence", "list"},
		{"plugin", "load", "x"},
		{"plugin", "reload", "--all"},
		{"mirror", "kill", "other"},
		{"mirror", "view", "other"},
	} {
		err := eng.AuthorizeCommand(args, "ssh-child")
		if err == nil || !strings.Contains(err.Error(), args[0]+": "+sshRefusalText) {
			t.Fatalf("%v: err = %v", args, err)
		}
		if !rec.saw(args[0]) {
			t.Fatalf("%v: refusal did not reach the remote gate", args)
		}
	}
}

func TestRemoteGateProcessKeepsReadOnlyVBins(t *testing.T) {
	installRemoteGateProcess(t)
	eng := DefaultEngine()
	for _, args := range [][]string{
		{"help"}, {"vbins"}, {"jq", "."}, {"plugin", "list"}, {"mirror", "list"},
		{"audit", "tail"}, {"runbook", "list"}, {"ls"},
	} {
		if err := eng.AuthorizeCommand(args, "ssh-child"); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

// A refused vbin reached without the gate seeing its name (command 4eyes)
// is refused at dispatch.
func TestRemoteGateProcessRefusesAtDispatch(t *testing.T) {
	rec := installRemoteGateProcess(t)
	eng := DefaultEngine()
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
	prog, err := syntax.NewParser().Parse(strings.NewReader("command 4eyes approve abc"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), prog)
	if runErr == nil || !strings.Contains(runErr.Error(), "4eyes: "+sshRefusalText) {
		t.Fatalf("command 4eyes: err = %v stderr=%q", runErr, errOut.String())
	}
	if !rec.saw("4eyes") {
		t.Fatal("dispatch refusal did not reach the remote gate")
	}
}

func TestRemoteGateProcessDeniesLocalPolicy(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte("package adssh\nauthz := {\"allow\": true}\n")})
	if err != nil {
		t.Fatal(err)
	}
	// Local process: an allow-all policy allows.
	if ok, _, err := eng.EvaluatePolicy(PolicyContext{User: "alice", Command: "ls"}); err != nil || !ok {
		t.Fatalf("local evaluate = %v %v", ok, err)
	}
	gw := GatewayPolicyRequest{SessionID: "ssh-child", User: "alice", Action: "connect", TargetHost: "127.0.0.1", TargetPort: 22}
	if err := eng.AuthorizeGateway(gw); err != nil {
		t.Fatalf("local gateway: %v", err)
	}

	rec := installRemoteGateProcess(t)
	const want = "policy is evaluated by the listener; not available in this process"
	if ok, _, err := eng.EvaluatePolicy(PolicyContext{User: "alice", Command: "ls"}); ok || err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("remote evaluate = %v %v", ok, err)
	}
	if ok, _, err := EvaluatePolicy(PolicyContext{User: "alice", Command: "ls"}); ok || err == nil {
		t.Fatalf("package evaluate = %v %v", ok, err)
	}
	if err := eng.AuthorizeGateway(gw); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("remote gateway = %v", err)
	}
	exp, err := eng.ExplainCommand("ssh-child", []string{"rm"})
	if err != nil {
		t.Fatal(err)
	}
	if exp.Outcome != "denied" {
		t.Fatalf("explain outcome = %q", exp.Outcome)
	}
	found := false
	for _, st := range exp.Stages {
		if st.Name == "policy" && st.Status == "denied" && strings.Contains(st.Reason, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("explain stages = %#v", exp.Stages)
	}
	// A governed Starlark operation is authorized through the remote gate,
	// not against the local engine.
	if err := eng.AuthorizeCommand([]string{"starlark.aws.ec2.list_instances"}, "ssh-child"); err != nil {
		t.Fatal(err)
	}
	if !rec.saw("starlark.aws.ec2.list_instances") {
		t.Fatal("starlark operation did not reach the remote gate")
	}
}

func TestLocalProcessDoesNotRefuseVBins(t *testing.T) {
	SetRemoteGate(nil)
	if RemoteGateProcess() {
		t.Fatal("local process reports remote gate")
	}
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.AuthorizeCommand([]string{"elevate", "request", "ops"}, ""); err != nil {
		t.Fatalf("local elevate gate: %v", err)
	}
}

// The listener refuses the same commands on the monitor socket and records
// the denial, so a child that skips its own check is still refused.
func TestSSHMonitorRefusesStatefulVBins(t *testing.T) {
	id := "mon-refuse"
	registerMonitorSession(t, id)
	called := false
	client, _ := dialMonitor(t, id, func([]string) error {
		called = true
		return nil
	})
	body, err := json.Marshal(sys.MonitorAuthRequest{ID: 7, Args: []string{"4eyes", "approve", "abc"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.WriteMonitorFrame(client, sys.MonitorFrameAuthorize, body); err != nil {
		t.Fatal(err)
	}
	resp := readAuth(t, client)
	if resp.OK || !strings.Contains(resp.Error, "4eyes: "+sshRefusalText) {
		t.Fatalf("resp = %+v", resp)
	}
	if called {
		t.Fatal("listener gate ran a refused command")
	}
	body, err = json.Marshal(sys.MonitorAuthRequest{ID: 8, Args: []string{"plugin", "list"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.WriteMonitorFrame(client, sys.MonitorFrameAuthorize, body); err != nil {
		t.Fatal(err)
	}
	if resp := readAuth(t, client); !resp.OK {
		t.Fatalf("plugin list resp = %+v", resp)
	}
}

func TestMarkRemoteGateProcessIsOneWay(t *testing.T) {
	SetRemoteGate(nil)
	t.Cleanup(func() { remoteGateProcess.Store(false) })
	if RemoteGateProcess() {
		t.Fatal("flag set before mark")
	}
	MarkRemoteGateProcess()
	SetRemoteGate(nil)
	if !RemoteGateProcess() {
		t.Fatal("clearing the gate cleared the process flag")
	}
	// With the flag and no gate, a refused command still fails closed.
	if err := DefaultEngine().AuthorizeCommand([]string{"elevate", "request", "x"}, "s"); err == nil {
		t.Fatal("refused command allowed with no gate")
	}
}

// B: vbin dispatch and env writes use SessionState.SessionID, not the global.
type sessionProbeVBin struct{ saw *string }

func (sessionProbeVBin) Name() string        { return "session-probe-vbin" }
func (sessionProbeVBin) Description() string { return "test vbin" }
func (sessionProbeVBin) Usage() string       { return "session-probe-vbin" }
func (v sessionProbeVBin) Run(ctx context.Context, _ []string) error {
	*v.saw = SessionIDFromContext(ctx)
	return nil
}

func TestVBinAndSetUseSessionStateID(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var saw string
	eng.Register(sessionProbeVBin{saw: &saw})
	for _, id := range []string{"probe-a", "probe-b"} {
		if err := sys.RegisterSession(&sys.Session{ID: id, User: id}); err != nil {
			t.Fatal(err)
		}
		id := id
		t.Cleanup(func() { sys.UnregisterSession(id) })
	}
	globals := starlark.StringDict{"SESSION_ID": starlark.String("probe-b")}
	sess := &SessionState{Globals: globals, SessionID: "probe-a"}
	runner, err := interp.New(
		interp.StdIO(nil, &strings.Builder{}, &strings.Builder{}),
		interp.ExecHandlers(eng.BashInterceptorSession(sess)),
	)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := syntax.NewParser().Parse(strings.NewReader("session-probe-vbin\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background(), prog); err != nil {
		t.Fatal(err)
	}
	if saw != "probe-a" {
		t.Fatalf("vbin saw session %q, want probe-a", saw)
	}
	h := eng.BashInterceptorSession(sess)(func(context.Context, []string) error { return nil })
	if err := h(context.Background(), []string{"set", "PROBE_VAR=1"}); err != nil {
		t.Fatal(err)
	}
	if v, ok := sys.GetSession("probe-a").OverlayGet("PROBE_VAR"); !ok || v != "1" {
		t.Fatalf("probe-a env = %q %v", v, ok)
	}
	if _, ok := sys.GetSession("probe-b").OverlayGet("PROBE_VAR"); ok {
		t.Fatal("set wrote the global's session")
	}
}
