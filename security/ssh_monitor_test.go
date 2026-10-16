package security

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

type safeBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type captureConn struct {
	net.Conn
	mu      sync.Mutex
	written strings.Builder
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	_, _ = c.written.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *captureConn) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written.String()
}

type countConn struct {
	net.Conn
	reads atomic.Int32
}

func (c *countConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(p)
}

func dialMonitor(t *testing.T, sessionID string, gate func([]string) error) (net.Conn, *captureConn) {
	t.Helper()
	server, client := net.Pipe()
	capc := &captureConn{Conn: server}
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	go ServeSSHMonitor(capc, sessionID, gate)
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	return client, capc
}

func TestServeSSHMonitorNilConn(t *testing.T) {
	var calls atomic.Int32
	ServeSSHMonitor(nil, "s", func([]string) error {
		calls.Add(1)
		return nil
	})
	if calls.Load() != 0 {
		t.Fatal("gate called")
	}
}

func TestServeSSHMonitorSkipsRead(t *testing.T) {
	cases := []struct {
		name string
		id   string
		gate func([]string) error
	}{
		{name: "nil gate", id: "s", gate: nil},
		{name: "empty session", id: "", gate: func([]string) error { return nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			cc := &countConn{Conn: server}
			t.Cleanup(func() {
				_ = server.Close()
				_ = client.Close()
			})
			done := make(chan struct{})
			go func() {
				ServeSSHMonitor(cc, tc.id, tc.gate)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("did not return")
			}
			if cc.reads.Load() != 0 {
				t.Fatalf("reads = %d", cc.reads.Load())
			}
		})
	}
}

func TestServeSSHMonitorProtocolErrors(t *testing.T) {
	secret := "sekret-frame"
	cases := []struct {
		name  string
		write func(net.Conn) error
	}{
		{
			name: "unknown type",
			write: func(c net.Conn) error {
				return sys.WriteMonitorFrame(c, 9, nil)
			},
		},
		{
			name: "bad json",
			write: func(c net.Conn) error {
				return sys.WriteMonitorFrame(c, sys.MonitorFrameAuthorize, []byte("{"))
			},
		},
		{
			name: "unknown field",
			write: func(c net.Conn) error {
				body := []byte(`{"id":1,"args":["ls"],"session_id":"` + secret + `"}`)
				return sys.WriteMonitorFrame(c, sys.MonitorFrameAuthorize, body)
			},
		},
		{
			name: "trailing junk",
			write: func(c net.Conn) error {
				return sys.WriteMonitorFrame(c, sys.MonitorFrameAuthorize, []byte(`{"id":1,"args":["ls"]}{"a":1}`))
			},
		},
		{
			name: "empty args",
			write: func(c net.Conn) error {
				return sys.WriteMonitorFrame(c, sys.MonitorFrameAuthorize, []byte(`{"id":1,"args":[]}`))
			},
		},
		{
			name: "nul arg",
			write: func(c net.Conn) error {
				body := []byte(`{"id":1,"args":["` + secret + `\u0000"]}`)
				return sys.WriteMonitorFrame(c, sys.MonitorFrameAuthorize, body)
			},
		},
		{
			name: "missing id",
			write: func(c net.Conn) error {
				return sys.WriteMonitorFrame(c, sys.MonitorFrameAuthorize, []byte(`{"args":["ls"]}`))
			},
		},
		{
			name: "ping payload",
			write: func(c net.Conn) error {
				return sys.WriteMonitorFrame(c, sys.MonitorFramePing, []byte("x"))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			client, capc := dialMonitor(t, "unregistered-session", func([]string) error {
				calls.Add(1)
				return nil
			})
			if err := tc.write(client); err != nil {
				t.Fatal(err)
			}
			_, _, err := sys.ReadMonitorFrame(client)
			if err == nil || err.Error() != "adssh: ssh monitor: closed" {
				t.Fatalf("err = %v", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("gate calls = %d", calls.Load())
			}
			if strings.Contains(capc.text(), secret) {
				t.Fatal("value leaked")
			}
		})
	}
}

func TestServeSSHMonitorOversizedCloses(t *testing.T) {
	server, client := net.Pipe()
	capc := &captureConn{Conn: server}
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	var calls atomic.Int32
	go ServeSSHMonitor(capc, "sess", func([]string) error {
		calls.Add(1)
		return nil
	})
	_ = client.SetWriteDeadline(time.Now().Add(3 * time.Second))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(sys.MaxMonitorFrame+1))
	if _, err := client.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	_ = client.SetWriteDeadline(time.Time{})
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	_, err := client.Read(buf)
	if err == nil {
		t.Fatal("server wrote a response")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server read the frame body")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("gate called")
	}
}

func registerMonitorSession(t *testing.T, id string) {
	t.Helper()
	if err := sys.RegisterSession(&sys.Session{ID: id, User: "bob"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
}

func readAuth(t *testing.T, c net.Conn) sys.MonitorAuthResponse {
	t.Helper()
	typ, payload, err := sys.ReadMonitorFrame(c)
	if err != nil {
		t.Fatal(err)
	}
	if typ != sys.MonitorFrameAuthorize {
		t.Fatalf("type = %d", typ)
	}
	var resp sys.MonitorAuthResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestServeSSHMonitorHappy(t *testing.T) {
	id := "mon-happy"
	registerMonitorSession(t, id)
	var calls atomic.Int32
	client, _ := dialMonitor(t, id, func(args []string) error {
		calls.Add(1)
		if len(args) != 2 || args[0] != "ls" || args[1] != "-l" {
			return errors.New("bad args")
		}
		return nil
	})
	if err := sys.WriteMonitorFrame(client, sys.MonitorFramePing, nil); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := sys.ReadMonitorFrame(client)
	if err != nil || typ != sys.MonitorFramePing || len(payload) != 0 {
		t.Fatalf("ping type=%d payload=%d err=%v", typ, len(payload), err)
	}
	body, err := json.Marshal(sys.MonitorAuthRequest{ID: 41, Args: []string{"ls", "-l"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.WriteMonitorFrame(client, sys.MonitorFrameAuthorize, body); err != nil {
		t.Fatal(err)
	}
	resp := readAuth(t, client)
	if !resp.OK || resp.Error != "" || resp.ID != 41 || resp.ArgsDigest != sys.MonitorArgsDigest([]string{"ls", "-l"}) {
		t.Fatalf("resp = %+v", resp)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestServeSSHMonitorGateErrorKeepsConnection(t *testing.T) {
	id := "mon-deny"
	registerMonitorSession(t, id)
	var calls atomic.Int32
	client, _ := dialMonitor(t, id, func(args []string) error {
		calls.Add(1)
		if args[0] == "bad" {
			return errors.New("nope")
		}
		return nil
	})
	var next uint64 = 5
	writeAuth := func(args []string) {
		t.Helper()
		next++
		body, err := json.Marshal(sys.MonitorAuthRequest{ID: next, Args: args})
		if err != nil {
			t.Fatal(err)
		}
		if err := sys.WriteMonitorFrame(client, sys.MonitorFrameAuthorize, body); err != nil {
			t.Fatal(err)
		}
	}
	writeAuth([]string{"bad"})
	resp := readAuth(t, client)
	if resp.OK || resp.Error != "nope" {
		t.Fatalf("resp = %+v", resp)
	}
	writeAuth([]string{"ls"})
	resp = readAuth(t, client)
	if !resp.OK || resp.Error != "" {
		t.Fatalf("resp = %+v", resp)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestServeSSHMonitorSessionGone(t *testing.T) {
	var calls atomic.Int32
	client, capc := dialMonitor(t, "missing-sess", func([]string) error {
		calls.Add(1)
		return nil
	})
	body, err := json.Marshal(sys.MonitorAuthRequest{ID: 1, Args: []string{"ls"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.WriteMonitorFrame(client, sys.MonitorFrameAuthorize, body); err != nil {
		t.Fatal(err)
	}
	resp := readAuth(t, client)
	if resp.OK || resp.Error != "adssh: ssh monitor: session is gone" || resp.ID != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if calls.Load() != 0 {
		t.Fatal("gate called")
	}
	if err := sys.WriteMonitorFrame(client, sys.MonitorFramePing, nil); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := sys.ReadMonitorFrame(client)
	if err != nil || typ != sys.MonitorFramePing || len(payload) != 0 {
		t.Fatalf("ping type=%d err=%v", typ, err)
	}
	if strings.Contains(capc.text(), "sekret") {
		t.Fatal("value leaked")
	}
}

func TestServeSSHMonitorDoesNotEchoArgument(t *testing.T) {
	id := "mon-secret"
	registerMonitorSession(t, id)
	client, capc := dialMonitor(t, id, func([]string) error {
		return errors.New("denied")
	})
	body, err := json.Marshal(sys.MonitorAuthRequest{ID: 1, Args: []string{"sekret-arg"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.WriteMonitorFrame(client, sys.MonitorFrameAuthorize, body); err != nil {
		t.Fatal(err)
	}
	resp := readAuth(t, client)
	if resp.OK || resp.Error != "denied" {
		t.Fatalf("resp = %+v", resp)
	}
	if strings.Contains(capc.text(), "sekret-arg") {
		t.Fatal("value leaked")
	}
}

func TestRemoteGateAuthorizeCommand(t *testing.T) {
	SetRemoteGate(nil)
	t.Cleanup(func() { SetRemoteGate(nil) })
	var calls atomic.Int32
	var sawRestricted bool
	var sawID string
	SetRemoteGate(func(restricted bool, args []string, sessionID string) error {
		calls.Add(1)
		sawRestricted = restricted
		sawID = sessionID
		if len(args) > 0 && args[0] == "deny" {
			return errors.New("hook deny")
		}
		return nil
	})
	eng := DefaultEngine()
	if err := eng.AuthorizeCommand([]string{"ls"}, "sess-remote"); err != nil {
		t.Fatal(err)
	}
	if sawRestricted {
		t.Fatal("hook saw restricted")
	}
	if sawID != "sess-remote" {
		t.Fatalf("session = %s", sawID)
	}
	err := eng.AuthorizeCommand([]string{"deny"}, "sess-remote")
	if err == nil || err.Error() != "hook deny" {
		t.Fatalf("deny = %v", err)
	}
	before := calls.Load()
	if err := eng.AuthorizeCommand(nil, "sess-remote"); err != nil {
		t.Fatal(err)
	}
	if err := eng.AuthorizeCommand([]string{}, "sess-remote"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before {
		t.Fatal("empty args called the hook")
	}
}

func TestApprovalSink(t *testing.T) {
	id := "prompt-sink"
	sess := &sys.Session{ID: id, User: "u"}
	if err := sys.RegisterSession(sess); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
	buf := &safeBuf{}
	sess.SetPromptWriter(buf)
	if approvalSink(id) != buf {
		t.Fatal("writer")
	}
	if approvalSink("") != os.Stderr {
		t.Fatal("empty id")
	}
	if approvalSink("missing-session-id") != os.Stderr {
		t.Fatal("missing session")
	}
	sess.SetPromptWriter(nil)
	if approvalSink(id) != os.Stderr {
		t.Fatal("no writer")
	}
}

func TestRequestApprovalForSessionUsesPromptWriter(t *testing.T) {
	t.Setenv("ADSSH_4EYES_WEBHOOK", "")
	dir := t.TempDir()
	eng := &Engine{fourEyesDir: dir}
	id := "foureyes-prompt-1"
	sess := &sys.Session{ID: id, User: "requester"}
	if err := sys.RegisterSession(sess); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
	buf := &safeBuf{}
	sess.SetPromptWriter(buf)
	errCh := make(chan error, 1)
	go func() {
		errCh <- eng.RequestApprovalForSession("foureyes-probe-cmd", FourEyesRule{
			Approver: "other",
			TTL:      8,
		}, id)
	}()

	deadline := time.Now().Add(5 * time.Second)
	var requestID, pendingPath string
	for requestID == "" || pendingPath == "" {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatal("approval returned before the prompt")
			}
			t.Fatal("approval returned before the prompt")
		default:
		}
		text := buf.String()
		if i := strings.Index(text, "\nRequest: "); i >= 0 {
			rest := text[i+len("\nRequest: "):]
			if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
				requestID = rest[:nl]
			}
		}
		if j := strings.Index(buf.String(), "\nPending: "); j >= 0 {
			rest := buf.String()[j+len("\nPending: "):]
			if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
				pendingPath = rest[:nl]
			}
		}
		if requestID != "" && pendingPath != "" {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("prompt not visible")
		}
		time.Sleep(20 * time.Millisecond)
	}

	data, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatal("pending file")
	}
	var pending FourEyesPending
	if err := json.Unmarshal(data, &pending); err != nil {
		t.Fatal("pending json")
	}
	if pending.Token == "" || pending.RequestID != requestID {
		t.Fatal("pending id")
	}
	if strings.Contains(buf.String(), pending.Token) {
		t.Fatal("token leaked")
	}
	if strings.Contains(buf.String(), "foureyes-probe-cmd") {
		t.Fatal("command in prompt")
	}

	approved := filepath.Join(eng.fourEyesApprovedDir(), requestID)
	if err := os.WriteFile(approved, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case err := <-errCh:
		if err != nil {
			if strings.Contains(err.Error(), pending.Token) {
				t.Fatal("token leaked")
			}
			t.Fatal("approval failed")
		}
	case <-timer.C:
		t.Fatal("approval did not finish")
	}
	if strings.Contains(buf.String(), pending.Token) {
		t.Fatal("token leaked")
	}
	if strings.Contains(buf.String(), "foureyes-probe-cmd") {
		t.Fatal("command in prompt")
	}
}
