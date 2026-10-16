package sys

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Threats: monitor frames are length-prefixed and capped at 1 MiB. An
// oversized length is rejected before the body is allocated. A short write
// fails closed so the stream cannot desync. JSON objects reject unknown
// fields and a second value. Arguments are bounded, reject NUL, and an
// argument error does not include the argument. Empty args are rejected
// before any gate. The client fails closed on I/O errors, a malformed
// response, a wrong type, OK=false, or OK=true with an error. There is no
// client deadline: four-eyes may wait for its TTL. Frames do not carry a
// session id. Payloads are not logged.

const (
	MaxMonitorFrame       = 1 << 20
	maxMonitorArgs        = 4096
	maxMonitorArgLen      = 256 << 10
	MonitorFrameAuthorize = byte(1)
	MonitorFramePing      = byte(2)
)

var (
	errMonitorInvalidArgument = errors.New("adssh: ssh monitor: invalid argument")
	errMonitorDenied          = errors.New("adssh: ssh monitor: denied")
	errMonitorClosed          = errors.New("adssh: ssh monitor: closed")
	errMonitorFrameTooLarge   = errors.New("adssh: ssh monitor: frame too large")
)

// MonitorAuthRequest is the authorize payload. The session id is not a field:
// the listener binds it when it accepts the socket.
type MonitorAuthRequest struct {
	Args []string `json:"args"`
}

// MonitorAuthResponse is the authorize result. OK with a non-empty Error is denied.
type MonitorAuthResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// SSHSessionSpec is the listener's description of one SSH login. The child
// receives these values on its argv. It does not choose them.
type SSHSessionSpec struct {
	SessionID   string
	User        string
	Principals  []string
	Restricted  bool
	MenuPath    string
	HistoryFile string
	ProfilePath string
	RCPath      string
	PTY         *os.File
}

var (
	sshMonitorMu     sync.Mutex
	sshMonitorServer func(conn net.Conn, sessionID string)
)

// SetSSHMonitorServer installs the listener hook that serves one session's
// monitor socket. A nil hook fails closed at spawn. The listener sets this.
// The session process does not.
func SetSSHMonitorServer(fn func(conn net.Conn, sessionID string)) {
	sshMonitorMu.Lock()
	sshMonitorServer = fn
	sshMonitorMu.Unlock()
}

func currentSSHMonitorServer() func(conn net.Conn, sessionID string) {
	sshMonitorMu.Lock()
	defer sshMonitorMu.Unlock()
	return sshMonitorServer
}

// ReadMonitorFrame reads one frame. The length is checked before the type
// byte and before the body is allocated.
func ReadMonitorFrame(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, errMonitorClosed
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxMonitorFrame {
		return 0, nil, errMonitorFrameTooLarge
	}
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return 0, nil, errMonitorClosed
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, errMonitorClosed
		}
	}
	return typ[0], payload, nil
}

// WriteMonitorFrame writes the length, type, and payload in one Write.
// A short write fails closed.
func WriteMonitorFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > MaxMonitorFrame {
		return errMonitorFrameTooLarge
	}
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	buf[4] = typ
	copy(buf[5:], payload)
	n, err := w.Write(buf)
	if err != nil || n != len(buf) {
		return errMonitorClosed
	}
	return nil
}

// ValidateMonitorArgs rejects empty, oversized, or NUL-bearing arguments.
// The error does not include the argument.
func ValidateMonitorArgs(args []string) error {
	if len(args) == 0 || len(args) > maxMonitorArgs {
		return errMonitorInvalidArgument
	}
	for _, arg := range args {
		if len(arg) > maxMonitorArgLen || strings.ContainsRune(arg, 0) {
			return errMonitorInvalidArgument
		}
	}
	return nil
}

// DecodeMonitorAuth parses one authorize payload. Unknown fields, a second
// JSON value, and invalid arguments fail closed. Trailing whitespace is EOF.
func DecodeMonitorAuth(payload []byte) (MonitorAuthRequest, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var req MonitorAuthRequest
	if err := dec.Decode(&req); err != nil {
		return MonitorAuthRequest{}, errMonitorInvalidArgument
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return MonitorAuthRequest{}, errMonitorInvalidArgument
	}
	if err := ValidateMonitorArgs(req.Args); err != nil {
		return MonitorAuthRequest{}, err
	}
	return req, nil
}

func decodeMonitorResponse(payload []byte) (MonitorAuthResponse, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var resp MonitorAuthResponse
	if err := dec.Decode(&resp); err != nil {
		return MonitorAuthResponse{}, errMonitorClosed
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return MonitorAuthResponse{}, errMonitorClosed
	}
	return resp, nil
}

// MonitorClient is the session process's monitor socket. The mutex covers one
// round trip so frames cannot interleave. Methods do not set a deadline.
type MonitorClient struct {
	conn net.Conn
	mu   sync.Mutex
}

// NewMonitorClient wraps the monitor connection. The caller keeps it open for
// the life of the session.
func NewMonitorClient(conn net.Conn) *MonitorClient {
	return &MonitorClient{conn: conn}
}

// Ping checks that the listener is answering before the REPL starts.
func (c *MonitorClient) Ping() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := WriteMonitorFrame(c.conn, MonitorFramePing, nil); err != nil {
		return errMonitorClosed
	}
	typ, payload, err := readMonitorClientFrame(c.conn)
	if err != nil {
		return err
	}
	if typ != MonitorFramePing || len(payload) != 0 {
		return errMonitorClosed
	}
	return nil
}

// Authorize asks the listener to allow args. The session id is not sent.
// Validation runs before the connection is touched.
func (c *MonitorClient) Authorize(args []string) error {
	if err := ValidateMonitorArgs(args); err != nil {
		return err
	}
	body, err := json.Marshal(MonitorAuthRequest{Args: args})
	if err != nil {
		return errMonitorClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := WriteMonitorFrame(c.conn, MonitorFrameAuthorize, body); err != nil {
		return errMonitorClosed
	}
	typ, payload, err := readMonitorClientFrame(c.conn)
	if err != nil {
		return err
	}
	if typ != MonitorFrameAuthorize {
		return errMonitorClosed
	}
	resp, err := decodeMonitorResponse(payload)
	if err != nil {
		return errMonitorClosed
	}
	if !resp.OK || resp.Error != "" {
		if resp.Error == "" {
			return errMonitorDenied
		}
		return errors.New(resp.Error)
	}
	return nil
}

func readMonitorClientFrame(r io.Reader) (byte, []byte, error) {
	typ, payload, err := ReadMonitorFrame(r)
	if err != nil {
		if errors.Is(err, errMonitorFrameTooLarge) {
			return 0, nil, err
		}
		return 0, nil, errMonitorClosed
	}
	return typ, payload, nil
}

type monitorAddr struct{}

func (monitorAddr) Network() string { return "unix" }
func (monitorAddr) String() string  { return "ssh-monitor" }

type osMonitorConn struct {
	*os.File
}

// NewMonitorConn adapts a socketpair file to net.Conn. *os.File has no
// addresses; the monitor protocol does not use them.
func NewMonitorConn(f *os.File) net.Conn {
	if f == nil {
		return nil
	}
	return osMonitorConn{File: f}
}

func (c osMonitorConn) LocalAddr() net.Addr  { return monitorAddr{} }
func (c osMonitorConn) RemoteAddr() net.Addr { return monitorAddr{} }

func (c osMonitorConn) SetDeadline(t time.Time) error {
	return c.File.SetDeadline(t)
}

func (c osMonitorConn) SetReadDeadline(t time.Time) error {
	return c.File.SetReadDeadline(t)
}

func (c osMonitorConn) SetWriteDeadline(t time.Time) error {
	return c.File.SetWriteDeadline(t)
}
