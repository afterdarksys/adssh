package security

import (
	"encoding/json"
	"errors"
	"net"
	"sync"

	"github.com/afterdarksys/adssh/internal/sys"
)

// Threats: the listener is the only process that evaluates policy and writes
// the audit chain. The client does not send a session id and cannot
// impersonate one. A missing listener session, a protocol error, an oversized
// frame, or an I/O failure denies the command. OK=true with an error string
// is denied. Starlark file, network, and cloud calls that do not pass the
// gate stay in the session process and are policy-bypassable. A native
// exploit in that process can still execve. The pre-auth handshake still
// runs in the listener. Argument errors do not echo the argument. Payloads
// are not logged.

var (
	remoteGateMu sync.Mutex
	remoteGate   func(restricted bool, args []string, sessionID string) error
)

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
// response and the connection stays open. A protocol error closes it.
func ServeSSHMonitor(conn net.Conn, sessionID string, gate func(args []string) error) {
	if conn == nil {
		return
	}
	defer conn.Close()
	if gate == nil || sessionID == "" {
		return
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
			if err := sys.WriteMonitorFrame(conn, sys.MonitorFramePing, nil); err != nil {
				return
			}
		case sys.MonitorFrameAuthorize:
			req, err := sys.DecodeMonitorAuth(payload)
			if err != nil {
				return
			}
			if sys.GetSession(sessionID) == nil {
				if err := writeMonitorAuth(conn, sys.MonitorAuthResponse{
					OK:    false,
					Error: errSSHMonitorSessionGone.Error(),
				}); err != nil {
					return
				}
				continue
			}
			if err := gate(req.Args); err != nil {
				if werr := writeMonitorAuth(conn, sys.MonitorAuthResponse{
					OK:    false,
					Error: err.Error(),
				}); werr != nil {
					return
				}
				continue
			}
			if err := writeMonitorAuth(conn, sys.MonitorAuthResponse{OK: true}); err != nil {
				return
			}
		default:
			return
		}
	}
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
