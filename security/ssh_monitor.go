package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/afterdarksys/adssh/internal/sys"
)

// Threats: the listener is the only process that evaluates policy and writes
// the audit chain. The client does not send a session id and cannot
// impersonate one. A missing listener session, a protocol error, an oversized
// frame, or an I/O failure denies the command. Authorize ids must rise by
// exactly one after the first; a repeated, older, or skipped id closes the
// socket. Each response echoes the id and the argument digest. OK=true with an error string
// is denied. Starlark file, network, and cloud calls that do not pass the
// gate stay in the session process and are policy-bypassable. A native
// exploit in that process can still execve. The pre-auth handshake still
// runs in the listener. Argument errors do not echo the argument. Payloads
// are not logged.
//
// The session process has an empty engine: no policy, no audit sink, no
// elevation, CM, lease, grant, four-eyes or identity state. Virtual binaries
// that change that state or evaluate policy locally would act on the empty
// engine, so both sides refuse them by name (sshSessionRefusal), the child
// before dispatch and the listener on the socket, and the listener records
// the refusal as a denied command. Every local policy evaluation in the
// session process denies (evaluatePolicy). The process flag is one-way.
// Not covered: a pending four-eyes wait cannot be cancelled over SSH. The
// listener's wait sleeps until the request's TTL with no context, so Ctrl-C
// in the session does not end it; ending it needs a cancel frame and a
// context through the four-eyes wait.

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
// process does not hold, or evaluate policy locally.
var sshSessionRefusedVBins = map[string]bool{
	"elevate": true, "cm": true, "lease": true, "grant": true,
	"identity": true, "4eyes": true, "why": true, "??": true,
	"admin": true, "gateway": true, "guard": true, "grid": true,
	"flight": true, "agent": true, "worktree": true, "repo": true,
	"evidence": true,
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
	return fmt.Errorf("%s: not available in an SSH session; run it in a local session or over the admin API", name)
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

// ServeSSHMonitor reads monitor frames for one bound SSH session. The session
// id comes from the listener, not from the frame. A policy deny is a normal
// response and the connection stays open. A protocol error, including an
// out-of-sequence request id, closes it.
func ServeSSHMonitor(conn net.Conn, sessionID string, gate func(args []string) error) {
	if conn == nil {
		return
	}
	defer conn.Close()
	if gate == nil || sessionID == "" {
		return
	}
	var lastID uint64
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
			if err := sys.WriteMonitorFrame(conn, sys.MonitorFramePing, nil); err != nil {
				return
			}
		case sys.MonitorFrameAuthorize:
			req, err := sys.DecodeMonitorAuth(payload)
			if err != nil {
				return
			}
			// lastID+1 wraps to 0 at the top, which no request may use.
			if lastID != 0 && req.ID != lastID+1 {
				return
			}
			lastID = req.ID
			resp := sys.MonitorAuthResponse{ID: req.ID, ArgsDigest: sys.MonitorArgsDigest(req.Args)}
			if sys.GetSession(sessionID) == nil {
				resp.Error = errSSHMonitorSessionGone.Error()
			} else if refusal := sshSessionRefusal(req.Args); refusal != nil {
				resp.Error = recordSSHRefusal(sessionID, req.Args, refusal).Error()
			} else if err := gate(req.Args); err != nil {
				resp.Error = err.Error()
			} else {
				resp.OK = true
			}
			if err := writeMonitorAuth(conn, resp); err != nil {
				return
			}
		default:
			return
		}
	}
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

func writeMonitorAuth(conn net.Conn, resp sys.MonitorAuthResponse) error {
	body, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return sys.WriteMonitorFrame(conn, sys.MonitorFrameAuthorize, body)
}

// errSSHMonitorSessionGone is the deny used when the listener no longer has
// the session the socket was bound to. Policy must not fall through to the
// listener's os user.
var errSSHMonitorSessionGone = errors.New("adssh: ssh monitor: session is gone")
