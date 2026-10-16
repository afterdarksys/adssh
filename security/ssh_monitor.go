package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Threats: the listener is the only process that evaluates policy, holds
// session state (elevation, CM, lease, grant, four-eyes, identity, grid),
// and writes the audit log and chain. The client does not send a session id
// and cannot impersonate one: Authorize and Run both act on the session the
// listener bound when it accepted the socket, and a frame with a session
// field is a decode error. A missing listener session, a protocol error, an
// oversized frame, or an I/O failure denies the command. Request ids must
// rise by exactly one after the first, across Authorize and Run; a
// repeated, older, or skipped id closes the socket. Each response echoes
// the id and a digest of the request. OK=true with an error string is
// denied. One request is in flight per connection; a second Authorize or
// Run while one is in flight is answered with a denial and does not run.
// Cancel ends the in-flight request's context, which ends a pending
// four-eyes wait; a Cancel for the next id that arrives before it is
// remembered for 2s and denies that request; any other id is ignored. Each
// frame write has a deadline (sshMonitorWriteTimeout); a client that stops
// reading breaks the connection and cancels the run instead of pinning the
// listener goroutine. Starlark file,
// network, and cloud calls that do not pass the gate stay in the session
// process and are policy-bypassable. A native exploit in that process can
// still execve. The pre-auth handshake still runs in the listener. Argument
// errors do not echo the argument. Payloads are not logged.
//
// What runs where. The session process has an empty engine. Every local
// policy evaluation there denies (evaluatePolicy). Virtual binaries that
// change the bound session's state, or read or explain listener state, run
// in the listener over a Run frame (sshListenerRuns): the listener gates
// the Run through the same AuthorizeCommandContext as Authorize (policy,
// entitlements, CM, four-eyes, audit), then runs the binary under the bound
// session with its output streamed back and capped at 1 MiB. Rego is the
// only other check and the default policy allows all, so a Run never
// changes listener-global state: four-eyes rules, guard bans, CM patterns,
// the admin surface, grid drain, another session's gateways, evidence or
// session, and the session's own principals (bound from the certificate at
// login) are refused by sshListenerRunArgs before the gate. The listener runs as its own uid, so a
// subcommand that names a host path (identity token files and CA keys, grid
// tokens and certificates, flight sources and CAs, worktree checkout
// --from, evidence --out, admin evidence and serve), that runs a command
// (lease), or that reads the listener's shared scratch root without
// elevation (repo) is refused for SSH sessions. Interactive ones (mirror
// view and console) and plugin load are refused: a plugin is Starlark that
// would execute in the session process, and loading it there has no
// listener state to act on. The child refuses these by name before
// dispatch, the listener refuses them on Authorize and on Run, and the
// listener records each refusal as a denied command. The process flag is
// one-way.

var (
	remoteGateMu sync.Mutex
	remoteGate   func(restricted bool, args []string, sessionID string) error
	// remoteGateProcess is set once by the SSH session process and never
	// cleared.
	remoteGateProcess atomic.Bool
)

// MarkRemoteGateProcess records that this process is an SSH login child
// whose policy, audit and session state live in the listener. It cannot be
// undone.
func MarkRemoteGateProcess() {
	remoteGateProcess.Store(true)
}

// RemoteGateProcess reports whether policy is evaluated by the listener:
// the process was marked, or a remote gate is installed.
func RemoteGateProcess() bool {
	return remoteGateProcess.Load() || currentRemoteGate() != nil
}

// sshSessionRefusedVBins change engine or session state that the session
// process does not hold, or evaluate policy locally. They never run in the
// session process. The ones in sshListenerRuns run in the listener instead.
var sshSessionRefusedVBins = map[string]bool{
	"elevate": true, "cm": true, "lease": true, "grant": true,
	"identity": true, "4eyes": true, "why": true, "??": true,
	"admin": true, "gateway": true, "guard": true, "grid": true,
	"flight": true, "agent": true, "worktree": true, "repo": true,
	"evidence": true, "whoami": true,
}

// sshSessionRefusal returns the refusal for args in an SSH session, or nil.
// plugin and mirror keep only their list subcommand.
func sshSessionRefusal(args []string) error {
	if len(args) == 0 {
		return nil
	}
	name := args[0]
	refused := sshSessionRefusedVBins[name]
	if name == "plugin" || name == "mirror" {
		refused = len(args) < 2 || args[1] != "list"
	}
	if !refused {
		return nil
	}
	return sshRefusal(name)
}

func sshRefusal(name string) error {
	return fmt.Errorf("%s: not available in an SSH session; run it in a local session or over the admin API", name)
}

func subcommands(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}

// sshListenerRuns are the virtual binaries the listener runs for an SSH
// session over a Run frame. A Run may change only the bound session's own
// state or read listener state; anything that changes listener-global
// state (rules, bans, gateways it does not own, other sessions, process
// environment) is refused, because Rego is the only other check and the
// default policy allows everything. A nil set accepts every subcommand;
// otherwise args[1] must be in the set. --help and help always pass.
//
//	elevate, agent: the bound session's elevation or agent lease.
//	whoami: identity and capabilities as the listener's policy sees them.
//	why, ??: explain the listener's policy and last denial.
//	cm: set, check, clear, status, providers, require (require adds a
//	  pattern to the bound session's own list on the engine).
//	grant: drop. Not request: principals are the certificate's, bound at
//	  login, and cannot be added to mid-session.
//	4eyes: approve, deny, pending, list. Not add or remove: rules are
//	  global to the listener.
//	guard: status (--json allowed). Not unban, reload, config, list.
//	gateway: list (own gateways only), stop (own only; gatewayStop also
//	  checks the owner). Not start: a listening socket in the listener.
//	evidence: own session only. --session must name the bound session;
//	  without it the listener adds it. Not --out (host path).
//	identity: status. Device login, OIDC import, and ssh-ca read or write
//	  host paths or the listener's environment.
//	grid: status. Not drain (listener-wide), init or serve (host paths).
//	flight: rehearse, cancel, status, each behind a live gridops elevation
//	  (requireGridOps). Not place (source, CA, token paths).
//	worktree: create, destroy. Not checkout (--from is a host path).
//	mirror: share, unshare (grants on the bound session), kill of the
//	  bound session only. view and console need a terminal.
//
// Refused entirely: admin (the admin API is the admin surface), lease
// (runs a command and reads secret paths as the listener), repo (reads the
// listener's shared scratch root without elevation), plugin load
// (Starlark that executes in the session process).
var sshListenerRuns = map[string]map[string]bool{
	"elevate": nil, "why": nil, "??": nil, "agent": nil, "whoami": nil,
	"evidence": nil,
	"cm":       subcommands("set", "check", "clear", "status", "providers", "require"),
	"grant":    subcommands("drop"),
	"4eyes":    subcommands("approve", "deny", "pending", "list"),
	"guard":    subcommands("status"),
	"gateway":  subcommands("list", "stop"),
	"identity": subcommands("status"),
	"grid":     subcommands("status"),
	"flight":   subcommands("rehearse", "cancel", "status"),
	"worktree": subcommands("create", "destroy"),
	"mirror":   subcommands("kill", "share", "unshare"),
}

// sshRunsInListener reports whether the session process sends args to the
// listener as a Run. The listener still checks the subcommand.
func sshRunsInListener(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == "mirror" {
		return len(args) >= 2 && sshListenerRuns["mirror"][args[1]]
	}
	_, ok := sshListenerRuns[args[0]]
	return ok
}

// fourEyesRulesRefusal refuses 4eyes rule changes over a Run.
func fourEyesRulesRefusal(sub string) error {
	return fmt.Errorf("4eyes %s: changes listener rules; use a local session or the admin API", sub)
}

// sshListenerRunRefusal returns the refusal for a Run of args, or nil. It
// does not know the session; sshListenerRunArgs adds the checks that do.
func sshListenerRunRefusal(args []string) error {
	if len(args) == 0 {
		return errMonitorRunEmpty
	}
	name := args[0]
	allowed, ok := sshListenerRuns[name]
	if !ok {
		return sshRefusal(name)
	}
	sub := args[1:]
	if name == "guard" {
		// guard takes --json anywhere after its name.
		sub = make([]string, 0, len(args))
		for _, arg := range args[1:] {
			if arg != "--json" {
				sub = append(sub, arg)
			}
		}
		if len(sub) > 1 && sub[0] != "--help" && sub[0] != "help" {
			return sshRefusal(name)
		}
	}
	if allowed != nil {
		if len(sub) == 0 {
			return sshRefusal(name)
		}
		if !allowed[sub[0]] && sub[0] != "--help" && sub[0] != "help" {
			if name == "4eyes" && (sub[0] == "add" || sub[0] == "remove" || sub[0] == "rm") {
				return fourEyesRulesRefusal(sub[0])
			}
			return sshRefusal(name)
		}
	}
	if name == "evidence" {
		// Mirror the evidence parser: flag/value pairs.
		for i := 1; i < len(args); i += 2 {
			if args[i] == "--out" {
				return sshRefusal(name)
			}
		}
	}
	return nil
}

// sshListenerRunArgs checks args against the bound session and returns
// the args to run. evidence is scoped to sessionID: a --session naming
// another session is refused, and with none the listener adds it. mirror
// kill may name only the bound session.
func sshListenerRunArgs(sessionID string, args []string) ([]string, error) {
	if err := sshListenerRunRefusal(args); err != nil {
		return nil, err
	}
	switch args[0] {
	case "evidence":
		scoped := false
		for i := 1; i < len(args); i += 2 {
			if args[i] != "--session" {
				continue
			}
			if i+1 >= len(args) || args[i+1] != sessionID {
				return nil, fmt.Errorf("evidence: over SSH only the session's own evidence is available")
			}
			scoped = true
		}
		if !scoped {
			args = append(append([]string(nil), args...), "--session", sessionID)
		}
	case "mirror":
		if args[1] == "kill" && (len(args) != 3 || args[2] != sessionID) {
			return nil, fmt.Errorf("mirror kill: over SSH only the session itself can be ended")
		}
	}
	return args, nil
}

// refuseInRemoteGateProcess refuses args in the SSH session process. The
// refused command is still sent to the listener, which records it as denied.
// A listener that allows it does not change the refusal.
func refuseInRemoteGateProcess(restricted bool, args []string, sessionID string) error {
	if !RemoteGateProcess() {
		return nil
	}
	refusal := sshSessionRefusal(args)
	if refusal == nil {
		return nil
	}
	if fn := currentRemoteGate(); fn != nil {
		if err := fn(restricted, args, sessionID); err != nil && err.Error() != refusal.Error() {
			return fmt.Errorf("%v (gate: %v)", refusal, err)
		}
	}
	return refusal
}

// SetRemoteGate installs the session process's monitor client as the
// authorization choke point. The listener never sets it. A nil function
// clears it. A nil function cannot be stored in an atomic.Value.
func SetRemoteGate(fn func(restricted bool, args []string, sessionID string) error) {
	remoteGateMu.Lock()
	remoteGate = fn
	remoteGateMu.Unlock()
}

func currentRemoteGate() func(restricted bool, args []string, sessionID string) error {
	remoteGateMu.Lock()
	defer remoteGateMu.Unlock()
	return remoteGate
}

// RemoteGateEnabled reports whether a monitor client is installed. The session
// process exits before the REPL when this is false, because the default
// engine allows commands.
func RemoteGateEnabled() bool {
	return currentRemoteGate() != nil
}

// SSHRunFunc runs one virtual binary for the bound SSH session in the
// listener and returns its exit code. A non-nil error is a failure.
type SSHRunFunc func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error)

// ServeSSHMonitor serves Ping and Authorize for one bound SSH session. A Run
// frame is answered with a denial. See ServeSSHMonitorRun.
func ServeSSHMonitor(conn net.Conn, sessionID string, gate func(args []string) error) {
	var ctxGate func(context.Context, []string) error
	if gate != nil {
		ctxGate = func(_ context.Context, args []string) error { return gate(args) }
	}
	ServeSSHMonitorRun(conn, sessionID, ctxGate, nil)
}

// ServeSSHMonitorRun reads monitor frames for one bound SSH session. The
// session id comes from the listener, not from the frame. gate authorizes
// Authorize and Run requests; its context is canceled by a Cancel frame or
// when the connection ends. run executes an allowed Run; nil denies every
// Run. A policy deny is a normal response and the connection stays open. A
// protocol error, including an out-of-sequence request id, closes it.
func ServeSSHMonitorRun(conn net.Conn, sessionID string, gate func(ctx context.Context, args []string) error, run SSHRunFunc) {
	if conn == nil {
		return
	}
	if gate == nil || sessionID == "" {
		_ = conn.Close()
		return
	}
	base, cancelAll := context.WithCancel(context.Background())
	m := &sshMonitor{conn: conn, sessionID: sessionID, gate: gate, run: run, cancelAll: cancelAll}
	defer func() {
		cancelAll()
		_ = conn.Close()
		m.wg.Wait()
	}()
	var lastID uint64
	inSequence := func(id uint64) bool {
		// lastID+1 wraps to 0 at the top, which no request may use.
		if lastID != 0 && id != lastID+1 {
			return false
		}
		lastID = id
		return true
	}
	for {
		typ, payload, err := sys.ReadMonitorFrame(conn)
		if err != nil {
			return
		}
		switch typ {
		case sys.MonitorFramePing:
			if len(payload) != 0 {
				return
			}
			if err := m.write(sys.MonitorFramePing, nil); err != nil {
				return
			}
		case sys.MonitorFrameAuthorize:
			req, err := sys.DecodeMonitorAuth(payload)
			if err != nil || !inSequence(req.ID) {
				return
			}
			ctx, ok := m.begin(base, req.ID)
			if !ok {
				resp := sys.MonitorAuthResponse{ID: req.ID, ArgsDigest: sys.MonitorArgsDigest(req.Args), Error: errMonitorBusy.Error()}
				if err := m.writeJSON(sys.MonitorFrameAuthorize, resp); err != nil {
					return
				}
				continue
			}
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				resp := m.authorize(ctx, req)
				m.end(req.ID)
				_ = m.writeJSON(sys.MonitorFrameAuthorize, resp)
			}()
		case sys.MonitorFrameRun:
			req, err := sys.DecodeMonitorRun(payload)
			if err != nil || !inSequence(req.ID) {
				return
			}
			ctx, ok := m.begin(base, req.ID)
			if !ok {
				exit := sys.MonitorExit{ID: req.ID, Digest: sys.MonitorRunDigest(req.Args, req.StdinMode, req.Stdin), Code: 1, Error: errMonitorBusy.Error()}
				if err := m.writeJSON(sys.MonitorFrameExit, exit); err != nil {
					return
				}
				continue
			}
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				exit := m.runVBin(ctx, req)
				m.end(req.ID)
				_ = m.writeJSON(sys.MonitorFrameExit, exit)
			}()
		case sys.MonitorFrameCancel:
			c, err := sys.DecodeMonitorCancel(payload)
			if err != nil {
				return
			}
			m.cancelID(c.ID, lastID)
		default:
			return
		}
	}
}

var (
	errMonitorBusy     = errors.New("adssh: ssh monitor: a request is already in flight")
	errMonitorRunEmpty = errors.New("adssh: ssh monitor: empty run")
)

// sshMonitorWriteTimeout bounds one frame write. A client that stops
// reading cannot pin the listener goroutine: the write fails, the
// connection is marked broken and closed, and the in-flight run is
// canceled.
var sshMonitorWriteTimeout = 5 * time.Second

// sshMonitorEarlyCancelWindow is how long a Cancel for the next request id
// is remembered when it arrives before that request.
const sshMonitorEarlyCancelWindow = 2 * time.Second

var errMonitorCancelled = errors.New("adssh: ssh monitor: request canceled")

// sshMonitor is one served connection. wmu serializes frame writes; mu
// guards the in-flight request and the remembered early Cancel.
type sshMonitor struct {
	conn      net.Conn
	sessionID string
	gate      func(context.Context, []string) error
	run       SSHRunFunc
	cancelAll context.CancelFunc
	broken    atomic.Bool
	wmu       sync.Mutex
	mu        sync.Mutex
	inflight  uint64
	cancel    context.CancelFunc
	earlyID   uint64
	earlyAt   time.Time
	wg        sync.WaitGroup
}

func (m *sshMonitor) write(typ byte, payload []byte) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	if m.broken.Load() {
		return errMonitorBroken
	}
	if err := m.conn.SetWriteDeadline(time.Now().Add(sshMonitorWriteTimeout)); err != nil {
		m.breakConn()
		return err
	}
	if err := sys.WriteMonitorFrame(m.conn, typ, payload); err != nil {
		m.breakConn()
		return err
	}
	return nil
}

var errMonitorBroken = errors.New("adssh: ssh monitor: connection broken")

// breakConn marks the connection broken, cancels every request on it, and
// closes it so the read loop ends.
func (m *sshMonitor) breakConn() {
	m.broken.Store(true)
	m.cancelAll()
	_ = m.conn.Close()
}

func (m *sshMonitor) writeJSON(typ byte, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return m.write(typ, body)
}

// begin claims the in-flight slot for id. It fails when one is held.
func (m *sshMonitor) begin(base context.Context, id uint64) (context.Context, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inflight != 0 {
		return nil, false
	}
	ctx, cancel := context.WithCancel(base)
	m.inflight, m.cancel = id, cancel
	if m.earlyID == id && m.earlyID != 0 {
		if time.Since(m.earlyAt) <= sshMonitorEarlyCancelWindow {
			cancel()
		}
		m.earlyID = 0
	}
	return ctx, true
}

// end releases the slot before the final response is written, so the
// client's next request never finds it held.
func (m *sshMonitor) end(id uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inflight == id {
		m.cancel()
		m.inflight, m.cancel = 0, nil
	}
}

// cancelID cancels the in-flight request id. A Cancel for lastID+1, the
// next request, that arrives before it is remembered for a short window;
// any other id is ignored.
func (m *sshMonitor) cancelID(id, lastID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inflight == id && m.cancel != nil {
		m.cancel()
		return
	}
	if lastID != 0 && id == lastID+1 {
		m.earlyID, m.earlyAt = id, time.Now()
	}
}

func (m *sshMonitor) authorize(ctx context.Context, req sys.MonitorAuthRequest) sys.MonitorAuthResponse {
	resp := sys.MonitorAuthResponse{ID: req.ID, ArgsDigest: sys.MonitorArgsDigest(req.Args)}
	if ctx.Err() != nil {
		resp.Error = errMonitorCancelled.Error()
	} else if sys.GetSession(m.sessionID) == nil {
		resp.Error = errSSHMonitorSessionGone.Error()
	} else if refusal := sshSessionRefusal(req.Args); refusal != nil {
		resp.Error = recordSSHRefusal(m.sessionID, req.Args, refusal).Error()
	} else if err := m.gate(ctx, req.Args); err != nil {
		resp.Error = err.Error()
	} else {
		resp.OK = true
	}
	return resp
}

// runVBin gates and runs one Run request under the bound session. A
// refused or denied Run does not reach run.
func (m *sshMonitor) runVBin(ctx context.Context, req sys.MonitorRunRequest) sys.MonitorExit {
	exit := sys.MonitorExit{ID: req.ID, Digest: sys.MonitorRunDigest(req.Args, req.StdinMode, req.Stdin), Code: 1}
	if ctx.Err() != nil {
		exit.Error = errMonitorCancelled.Error()
		return exit
	}
	if sys.GetSession(m.sessionID) == nil {
		exit.Error = errSSHMonitorSessionGone.Error()
		return exit
	}
	args, refusal := sshListenerRunArgs(m.sessionID, req.Args)
	if refusal != nil {
		exit.Error = recordSSHRefusal(m.sessionID, req.Args, refusal).Error()
		return exit
	}
	if m.run == nil {
		exit.Error = recordSSHRefusal(m.sessionID, req.Args, sshRefusal(req.Args[0])).Error()
		return exit
	}
	if err := m.gate(ctx, args); err != nil {
		exit.Error = err.Error()
		return exit
	}
	out := &monitorOutWriter{m: m, id: req.ID}
	code, err := m.run(withSSHRun(ctx), args, bytes.NewReader(req.Stdin), out.stream(sys.MonitorStreamStdout), out.stream(sys.MonitorStreamStderr))
	out.finish()
	exit.Code = code
	if err != nil {
		exit.Error = err.Error()
		if exit.Code == 0 {
			exit.Code = 1
		}
	}
	if exit.Code < 0 || exit.Code > 255 {
		exit.Code = 1
	}
	return exit
}

// monitorOutWriter streams one run's output as Out frames in bounded
// chunks. After MaxMonitorRunOutput bytes the rest is dropped and one
// truncation marker goes to stderr. Writes never fail, so a truncated run
// keeps its exit code.
type monitorOutWriter struct {
	m         *sshMonitor
	id        uint64
	mu        sync.Mutex
	seq       uint64
	total     int
	truncated bool
	broken    bool
}

type monitorOutStream struct {
	w      *monitorOutWriter
	stream int
}

func (w *monitorOutWriter) stream(n int) io.Writer { return monitorOutStream{w: w, stream: n} }

func (s monitorOutStream) Write(p []byte) (int, error) {
	s.w.emit(s.stream, p)
	return len(p), nil
}

func (w *monitorOutWriter) emit(stream int, p []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(p) > 0 && !w.broken {
		room := sys.MaxMonitorRunOutput - w.total
		if room <= 0 {
			w.truncated = true
			return
		}
		n := len(p)
		if n > sys.MaxMonitorOutChunk {
			n = sys.MaxMonitorOutChunk
		}
		if n > room {
			n = room
		}
		w.send(stream, p[:n])
		w.total += n
		p = p[n:]
	}
}

func (w *monitorOutWriter) send(stream int, data []byte) {
	w.seq++
	if err := w.m.writeJSON(sys.MonitorFrameOut, sys.MonitorOut{ID: w.id, Seq: w.seq, Stream: stream, Data: data}); err != nil {
		w.broken = true
	}
}

// finish writes the truncation marker, once, after the run returns.
func (w *monitorOutWriter) finish() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.truncated && !w.broken {
		w.send(sys.MonitorStreamStderr, []byte(sys.MonitorRunTruncated))
	}
}

// RunVBinForSession runs the virtual binary args[0] in this process under
// sessionID, with stdin, stdout and stderr, and returns its exit code. It
// does not authorize: the caller gates first. The listener uses it for SSH
// Run frames. The binary's environment is empty.
func (e *Engine) RunVBinForSession(ctx context.Context, sessionID string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	runCtx := ctx
	if len(args) == 0 {
		return 1, errMonitorRunEmpty
	}
	vb, ok := e.Lookup(args[0])
	if !ok {
		return 127, fmt.Errorf("%s: not found", args[0])
	}
	runner, err := interp.New(
		interp.StdIO(stdin, stdout, stderr),
		interp.Env(expand.ListEnviron()),
		interp.ExecHandlers(func(interp.ExecHandlerFunc) interp.ExecHandlerFunc {
			return func(ctx context.Context, _ []string) error {
				if sshRunFrom(runCtx) {
					ctx = withSSHRun(ctx)
				}
				return e.DispatchVBin(WithVBinSession(WithSessionID(ctx, sessionID), e.restricted, nil), vb, args)
			}
		}),
	)
	if err != nil {
		return 1, err
	}
	prog, err := syntax.NewParser().Parse(strings.NewReader("adssh-ssh-run"), "")
	if err != nil {
		return 1, err
	}
	err = runner.Run(ctx, prog)
	if err == nil {
		return 0, nil
	}
	var status interp.ExitStatus
	if errors.As(err, &status) {
		return int(status), nil
	}
	return 1, err
}

type sshRunCtxKey struct{}

// withSSHRun marks ctx as an SSH Run in the listener, so a virtual binary
// can narrow what it shows to the bound session.
func withSSHRun(ctx context.Context) context.Context {
	return context.WithValue(ctx, sshRunCtxKey{}, true)
}

// sshRunFrom reports whether ctx carries an SSH Run.
func sshRunFrom(ctx context.Context) bool {
	v, _ := ctx.Value(sshRunCtxKey{}).(bool)
	return v
}

// recordSSHRefusal writes the refusal to the listener's audit log and chain
// as a denied command. An audit failure is added to the denial.
func recordSSHRefusal(sessionID string, args []string, refusal error) error {
	e := DefaultEngine()
	user := ""
	if s := sys.GetSession(sessionID); s != nil {
		user = s.User
	}
	cmd := strings.Join(args, " ")
	if err := e.LogCommand("BASH", cmd); err != nil {
		return joinDeny(refusal.Error(), err)
	}
	e.rememberDeniedCommand(sessionID, args)
	return joinDeny(refusal.Error(), e.LogPolicyDecision(user, cmd, false, refusal.Error()))
}

// errSSHMonitorSessionGone is the deny used when the listener no longer has
// the session the socket was bound to. Policy must not fall through to the
// listener's os user.
var errSSHMonitorSessionGone = errors.New("adssh: ssh monitor: session is gone")

var (
	remoteRunMu sync.Mutex
	remoteRun   func(args []string, stdinMode string, stdin []byte, stdout, stderr io.Writer) (int, error)
)

// SetRemoteRun installs the session process's monitor Run. The listener
// never sets it. A nil function clears it; listener-run vbins are then
// refused.
func SetRemoteRun(fn func(args []string, stdinMode string, stdin []byte, stdout, stderr io.Writer) (int, error)) {
	remoteRunMu.Lock()
	remoteRun = fn
	remoteRunMu.Unlock()
}

func currentRemoteRun() func(args []string, stdinMode string, stdin []byte, stdout, stderr io.Writer) (int, error) {
	remoteRunMu.Lock()
	defer remoteRunMu.Unlock()
	return remoteRun
}

// runInListener sends args to the listener as a Run from the session
// process and writes its output to the command's stdout and stderr. Stdin
// from a pipe or file goes with it, up to sys.MaxMonitorRunStdin; a
// terminal does not. A non-zero exit becomes an exit status; a listener
// error is returned as is. With no Run installed it refuses.
func runInListener(ctx context.Context, restricted bool, args []string, sessionID string) error {
	fn := currentRemoteRun()
	if fn == nil {
		if err := refuseInRemoteGateProcess(restricted, args, sessionID); err != nil {
			return err
		}
		return sshRefusal(args[0])
	}
	hc := interp.HandlerCtx(ctx)
	mode, stdin, err := runStdin(hc.Stdin)
	if err != nil {
		return err
	}
	code, err := fn(args, mode, stdin, hc.Stdout, hc.Stderr)
	if err != nil {
		return err
	}
	if code != 0 {
		return interp.ExitStatus(uint8(code))
	}
	return nil
}

func runStdin(r io.Reader) (string, []byte, error) {
	if r == nil {
		return sys.MonitorStdinNone, nil, nil
	}
	if f, ok := r.(*os.File); ok {
		if info, err := f.Stat(); err != nil || info.Mode()&os.ModeCharDevice != 0 {
			return sys.MonitorStdinNone, nil, nil
		}
	}
	data, err := io.ReadAll(io.LimitReader(r, sys.MaxMonitorRunStdin+1))
	if err != nil {
		return "", nil, fmt.Errorf("adssh: ssh session: read stdin: %w", err)
	}
	if len(data) > sys.MaxMonitorRunStdin {
		return "", nil, fmt.Errorf("adssh: ssh session: stdin over %d bytes", sys.MaxMonitorRunStdin)
	}
	if len(data) == 0 {
		return sys.MonitorStdinNone, nil, nil
	}
	return sys.MonitorStdinBytes, data, nil
}

// ConfiguredPluginDir returns ADSSH_PLUGIN_DIR when it is an absolute path,
// else "". The listener passes it to SSH session processes.
func ConfiguredPluginDir() string {
	dir := os.Getenv("ADSSH_PLUGIN_DIR")
	if dir == "" || !filepath.IsAbs(dir) {
		return ""
	}
	return filepath.Clean(dir)
}
