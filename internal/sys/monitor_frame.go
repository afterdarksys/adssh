package sys

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Threats: monitor frames are length-prefixed and capped at 1 MiB. An
// oversized length is rejected before the body is allocated. A short write
// fails closed so the stream cannot desync. JSON objects reject unknown
// fields and a second value, so a frame cannot carry a session id. Arguments
// are bounded, must be UTF-8, reject NUL, and an argument error does not
// include the argument. Empty args are rejected before any gate. Every
// Authorize and Run carries a request id from one sequence; a client starts
// at a random id and adds one per request, and the listener closes the
// socket on a repeated, older, or skipped id. An Authorize response echoes
// the id and a SHA-256 of the length-prefixed arguments; a Run's Exit echoes
// the id and a SHA-256 over the arguments, the stdin mode, and the stdin
// bytes. Out frames carry the run id and a sequence number from 1. The
// client fails closed on I/O errors, a malformed frame, a wrong type, an id,
// sequence, stream, or digest that does not match the request, OK=false, or
// OK=true with an error, and after a mismatch it refuses every later call
// without touching the socket. Run stdin is at most 64 KiB, an Out chunk at
// most 32 KiB, and a run's output at most 1 MiB plus the listener's
// truncation marker; more is a desync. Run executes a virtual binary in the
// listener, which is the only process with policy, session state, and audit
// sinks; the child sends only args and stdin, never an identity. Cancel
// names the in-flight id. The client marks a request in flight only after
// its frame is written, and a Cancel that arrives during the write is sent
// after it, so a Cancel never precedes its request on the wire; the
// listener also remembers a Cancel for the next id for a short window. A process that
// holds a copy of the socket can still inject requests for the same
// session; a queued answer can only satisfy a later request for the
// identical arguments at the identical id, which policy already allowed. The
// session process sets FD_CLOEXEC on fd 3 so the commands it runs do not
// inherit the socket. There is no client deadline: four-eyes may wait for
// its TTL, and Cancel ends the wait. Payloads are not logged.

const (
	MaxMonitorFrame       = 1 << 20
	maxMonitorArgs        = 4096
	maxMonitorArgLen      = 256 << 10
	MonitorFrameAuthorize = byte(1)
	MonitorFramePing      = byte(2)
	// MonitorFrameRun asks the listener to run a virtual binary.
	MonitorFrameRun = byte(3)
	// MonitorFrameOut carries one chunk of a run's stdout or stderr.
	MonitorFrameOut = byte(4)
	// MonitorFrameExit ends a run.
	MonitorFrameExit = byte(5)
	// MonitorFrameCancel cancels the in-flight Authorize or Run.
	MonitorFrameCancel = byte(6)

	// MaxMonitorRunStdin bounds the stdin a Run carries.
	MaxMonitorRunStdin = 64 << 10
	// MaxMonitorOutChunk bounds the data in one Out frame.
	MaxMonitorOutChunk = 32 << 10
	// MaxMonitorRunOutput bounds a run's stdout and stderr together.
	MaxMonitorRunOutput = 1 << 20
	// MonitorRunTruncated is the stderr marker after MaxMonitorRunOutput.
	MonitorRunTruncated = "\nadssh: output truncated at 1 MiB\n"

	MonitorStdinNone    = "none"
	MonitorStdinBytes   = "bytes"
	MonitorStreamStdout = 1
	MonitorStreamStderr = 2
)

var (
	errMonitorInvalidArgument = errors.New("adssh: ssh monitor: invalid argument")
	errMonitorDenied          = errors.New("adssh: ssh monitor: denied")
	errMonitorClosed          = errors.New("adssh: ssh monitor: closed")
	errMonitorFrameTooLarge   = errors.New("adssh: ssh monitor: frame too large")
	errMonitorDesync          = errors.New("adssh: ssh monitor: response does not match request")
)

// MonitorAuthRequest is the authorize payload. The session id is not a field:
// the listener binds it when it accepts the socket. ID is the request
// sequence number and is never zero.
type MonitorAuthRequest struct {
	ID   uint64   `json:"id"`
	Args []string `json:"args"`
}

// MonitorAuthResponse is the authorize result. ID and ArgsDigest echo the
// request. OK with a non-empty Error is denied.
type MonitorAuthResponse struct {
	ID         uint64 `json:"id"`
	ArgsDigest string `json:"args_sha256"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

// MonitorRunRequest asks the listener to run args as a virtual binary under
// the session it bound to the socket. There is no session or user field.
type MonitorRunRequest struct {
	ID        uint64   `json:"id"`
	Args      []string `json:"args"`
	StdinMode string   `json:"stdin_mode"`
	Stdin     []byte   `json:"stdin,omitempty"`
}

// MonitorOut is one chunk of run output. Seq starts at 1 for each run.
type MonitorOut struct {
	ID     uint64 `json:"id"`
	Seq    uint64 `json:"seq"`
	Stream int    `json:"stream"`
	Data   []byte `json:"data"`
}

// MonitorExit ends a run. Digest is MonitorRunDigest of the request. A
// non-empty Error is a failure or a denial.
type MonitorExit struct {
	ID     uint64 `json:"id"`
	Digest string `json:"run_sha256"`
	Code   int    `json:"code"`
	Error  string `json:"error,omitempty"`
}

// MonitorCancel cancels the in-flight request with this id.
type MonitorCancel struct {
	ID uint64 `json:"id"`
}

// SSHSessionSpec is the listener's description of one SSH login. The child
// receives these values on its argv. It does not choose them. History,
// profile, and rc paths are not fields: they derive from the target user's
// home so one user never runs another's rc.
type SSHSessionSpec struct {
	SessionID  string
	User       string
	Principals []string
	Restricted bool
	MenuPath   string
	// PluginDir is the listener's configured plugin directory, passed so
	// plugin list works. Empty leaves the child's default.
	PluginDir string
	PTY       *os.File
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
		if len(arg) > maxMonitorArgLen || strings.ContainsRune(arg, 0) || !utf8.ValidString(arg) {
			return errMonitorInvalidArgument
		}
	}
	return nil
}

// MonitorArgsDigest binds a response to the arguments it answers. Each
// argument is length-prefixed so boundaries cannot shift.
func MonitorArgsDigest(args []string) string {
	h := sha256.New()
	var n [8]byte
	for _, arg := range args {
		binary.BigEndian.PutUint64(n[:], uint64(len(arg)))
		h.Write(n[:])
		h.Write([]byte(arg))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// DecodeMonitorAuth parses one authorize payload. Unknown fields, a second
// JSON value, a zero or missing id, and invalid arguments fail closed.
// Trailing whitespace is EOF.
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
	if req.ID == 0 {
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

func validateRunStdin(mode string, stdin []byte) error {
	switch mode {
	case MonitorStdinNone:
		if len(stdin) != 0 {
			return errMonitorInvalidArgument
		}
	case MonitorStdinBytes:
		if len(stdin) > MaxMonitorRunStdin {
			return errMonitorInvalidArgument
		}
	default:
		return errMonitorInvalidArgument
	}
	return nil
}

// decodeStrict decodes exactly one JSON value and rejects unknown fields.
func decodeStrict(payload []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errMonitorInvalidArgument
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errMonitorInvalidArgument
	}
	return nil
}

// DecodeMonitorRun parses one Run payload. Unknown fields (a session id
// among them), a second value, a zero id, invalid arguments, and a bad or
// oversized stdin fail closed.
func DecodeMonitorRun(payload []byte) (MonitorRunRequest, error) {
	var req MonitorRunRequest
	if err := decodeStrict(payload, &req); err != nil {
		return MonitorRunRequest{}, err
	}
	if req.ID == 0 {
		return MonitorRunRequest{}, errMonitorInvalidArgument
	}
	if err := ValidateMonitorArgs(req.Args); err != nil {
		return MonitorRunRequest{}, err
	}
	if err := validateRunStdin(req.StdinMode, req.Stdin); err != nil {
		return MonitorRunRequest{}, err
	}
	return req, nil
}

// DecodeMonitorCancel parses one Cancel payload. A zero id fails closed.
func DecodeMonitorCancel(payload []byte) (MonitorCancel, error) {
	var c MonitorCancel
	if err := decodeStrict(payload, &c); err != nil {
		return MonitorCancel{}, err
	}
	if c.ID == 0 {
		return MonitorCancel{}, errMonitorInvalidArgument
	}
	return c, nil
}

func decodeMonitorOut(payload []byte) (MonitorOut, error) {
	var out MonitorOut
	if err := decodeStrict(payload, &out); err != nil {
		return MonitorOut{}, err
	}
	if out.Stream != MonitorStreamStdout && out.Stream != MonitorStreamStderr {
		return MonitorOut{}, errMonitorInvalidArgument
	}
	if len(out.Data) == 0 || len(out.Data) > MaxMonitorOutChunk {
		return MonitorOut{}, errMonitorInvalidArgument
	}
	return out, nil
}

func decodeMonitorExit(payload []byte) (MonitorExit, error) {
	var exit MonitorExit
	if err := decodeStrict(payload, &exit); err != nil {
		return MonitorExit{}, err
	}
	if exit.Code < 0 || exit.Code > 255 {
		return MonitorExit{}, errMonitorInvalidArgument
	}
	return exit, nil
}

// MonitorRunDigest binds an Exit to the Run it answers: the arguments, the
// stdin mode, and the stdin bytes, each length-prefixed after a domain tag,
// so it never equals an Authorize digest.
func MonitorRunDigest(args []string, stdinMode string, stdin []byte) string {
	h := sha256.New()
	var n [8]byte
	put := func(b []byte) {
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	put([]byte("adssh-monitor-run"))
	binary.BigEndian.PutUint64(n[:], uint64(len(args)))
	h.Write(n[:])
	for _, arg := range args {
		put([]byte(arg))
	}
	put([]byte(stdinMode))
	put(stdin)
	return hex.EncodeToString(h.Sum(nil))
}

// MonitorClient is the session process's monitor socket. mu covers one
// round trip so requests cannot interleave; wmu covers each frame write, so
// Cancel can be sent while a round trip waits. Methods do not set a
// deadline. Once a round trip fails the client is broken and refuses every
// call.
type MonitorClient struct {
	conn   net.Conn
	mu     sync.Mutex
	wmu    sync.Mutex
	nextID uint64
	broken atomic.Bool
	// active is the id of the in-flight request, or 0. It is set only
	// after the request frame is fully written, so a Cancel never precedes
	// its request on the wire.
	active atomic.Uint64
	// writing is the id of a request whose frame is being written, or 0.
	writing atomic.Uint64
	// cancelEarly is an id that Cancel saw while it was being written. The
	// writer or Cancel, whichever sees both, sends the Cancel once.
	cancelEarly atomic.Uint64
}

// NewMonitorClient wraps the monitor connection. The caller keeps it open for
// the life of the session. The first request id is random, so a process that
// cannot read the socket cannot predict it. A random-source failure leaves
// the client broken.
func NewMonitorClient(conn net.Conn) *MonitorClient {
	c := &MonitorClient{conn: conn}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		c.broken.Store(true)
		return c
	}
	// 62 bits keeps the sequence far from wrapping; +1 keeps it nonzero.
	c.nextID = binary.BigEndian.Uint64(b[:])>>2 + 1
	return c
}

func (c *MonitorClient) write(typ byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := WriteMonitorFrame(c.conn, typ, payload); err != nil {
		c.broken.Store(true)
		return errMonitorClosed
	}
	return nil
}

// writeRequest writes a request frame for id and only then marks id in
// flight. A Cancel that arrived during the write is sent after the frame.
func (c *MonitorClient) writeRequest(id uint64, typ byte, body []byte) error {
	c.writing.Store(id)
	err := c.write(typ, body)
	if err != nil {
		c.writing.Store(0)
		return err
	}
	c.active.Store(id)
	c.writing.Store(0)
	if c.cancelEarly.CompareAndSwap(id, 0) {
		c.sendCancel(id)
	}
	return nil
}

// idle clears the in-flight state when a round trip ends.
func (c *MonitorClient) idle() {
	c.active.Store(0)
	c.writing.Store(0)
	c.cancelEarly.Store(0)
}

// fail marks the client broken and returns err.
func (c *MonitorClient) fail(err error) error {
	c.broken.Store(true)
	return err
}

// Ping checks that the listener is answering before the REPL starts.
func (c *MonitorClient) Ping() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken.Load() {
		return errMonitorClosed
	}
	if err := c.write(MonitorFramePing, nil); err != nil {
		return err
	}
	typ, payload, err := readMonitorClientFrame(c.conn)
	if err != nil {
		return c.fail(err)
	}
	if typ != MonitorFramePing || len(payload) != 0 {
		return c.fail(errMonitorClosed)
	}
	return nil
}

// Authorize asks the listener to allow args. The session id is not sent.
// Validation runs before the connection is touched. A response whose id or
// argument digest differs from this request is a desync: the call is denied
// and the client is broken.
func (c *MonitorClient) Authorize(args []string) error {
	if err := ValidateMonitorArgs(args); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken.Load() {
		return errMonitorClosed
	}
	id := c.nextID
	c.nextID++
	body, err := json.Marshal(MonitorAuthRequest{ID: id, Args: args})
	if err != nil {
		return c.fail(errMonitorClosed)
	}
	defer c.idle()
	if err := c.writeRequest(id, MonitorFrameAuthorize, body); err != nil {
		return err
	}
	typ, payload, err := readMonitorClientFrame(c.conn)
	if err != nil {
		return c.fail(err)
	}
	if typ != MonitorFrameAuthorize {
		return c.fail(errMonitorClosed)
	}
	resp, err := decodeMonitorResponse(payload)
	if err != nil {
		return c.fail(errMonitorClosed)
	}
	if resp.ID != id || resp.ArgsDigest != MonitorArgsDigest(args) {
		return c.fail(errMonitorDesync)
	}
	if !resp.OK || resp.Error != "" {
		if resp.Error == "" {
			return errMonitorDenied
		}
		return errors.New(resp.Error)
	}
	return nil
}

// Run asks the listener to run args as a virtual binary for this session.
// Output chunks are written to stdout and stderr in order. It returns the
// exit code, and the listener's error for a denial or failure. A frame for
// another id, an out-of-order chunk, too much output, or a wrong digest is a
// desync: nothing more is written and the client is broken.
func (c *MonitorClient) Run(args []string, stdinMode string, stdin []byte, stdout, stderr io.Writer) (int, error) {
	if err := ValidateMonitorArgs(args); err != nil {
		return 1, err
	}
	if err := validateRunStdin(stdinMode, stdin); err != nil {
		return 1, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken.Load() {
		return 1, errMonitorClosed
	}
	id := c.nextID
	c.nextID++
	req := MonitorRunRequest{ID: id, Args: args, StdinMode: stdinMode, Stdin: stdin}
	body, err := json.Marshal(req)
	if err != nil {
		return 1, c.fail(errMonitorClosed)
	}
	defer c.idle()
	if err := c.writeRequest(id, MonitorFrameRun, body); err != nil {
		return 1, err
	}
	var seq uint64
	total := 0
	for {
		typ, payload, err := readMonitorClientFrame(c.conn)
		if err != nil {
			return 1, c.fail(err)
		}
		switch typ {
		case MonitorFrameOut:
			out, err := decodeMonitorOut(payload)
			if err != nil {
				return 1, c.fail(errMonitorClosed)
			}
			seq++
			total += len(out.Data)
			if out.ID != id || out.Seq != seq || total > MaxMonitorRunOutput+len(MonitorRunTruncated) {
				return 1, c.fail(errMonitorDesync)
			}
			w := stdout
			if out.Stream == MonitorStreamStderr {
				w = stderr
			}
			// A local write error does not stop the read: the stream must
			// stay in step with the listener.
			if w != nil {
				_, _ = w.Write(out.Data)
			}
		case MonitorFrameExit:
			exit, err := decodeMonitorExit(payload)
			if err != nil {
				return 1, c.fail(errMonitorClosed)
			}
			if exit.ID != id || exit.Digest != MonitorRunDigest(args, stdinMode, stdin) {
				return 1, c.fail(errMonitorDesync)
			}
			if exit.Error != "" {
				return exit.Code, errors.New(exit.Error)
			}
			return exit.Code, nil
		default:
			return 1, c.fail(errMonitorClosed)
		}
	}
}

// Cancel asks the listener to cancel the in-flight Authorize or Run, which
// ends a pending four-eyes wait. With nothing in flight it does nothing. It
// does not take the round-trip lock.
func (c *MonitorClient) Cancel() {
	if c.broken.Load() {
		return
	}
	// writing is read before active: a request that is not yet writing
	// has not been sent, and one that finished writing is active.
	w := c.writing.Load()
	if id := c.active.Load(); id != 0 {
		c.sendCancel(id)
		return
	}
	if w == 0 {
		return
	}
	c.cancelEarly.Store(w)
	if c.active.Load() == w && c.cancelEarly.CompareAndSwap(w, 0) {
		c.sendCancel(w)
	}
}

func (c *MonitorClient) sendCancel(id uint64) {
	body, err := json.Marshal(MonitorCancel{ID: id})
	if err != nil {
		return
	}
	_ = c.write(MonitorFrameCancel, body)
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
