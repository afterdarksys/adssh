//go:build unix

package security

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/afterdarksys/adssh/internal/sys"
)

// monitorSocketpair returns two connected unix stream conns, like the fd 3
// pair the listener creates for a session.
func monitorSocketpair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]net.Conn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c
	}
	t.Cleanup(func() { _ = conns[0].Close(); _ = conns[1].Close() })
	return conns[0], conns[1]
}

// lastFrame returns the body of the last frame in a captured byte stream.
func lastFrame(t *testing.T, raw string) []byte {
	t.Helper()
	r := strings.NewReader(raw)
	var body []byte
	for r.Len() > 0 {
		_, payload, err := sys.ReadMonitorFrame(r)
		if err != nil {
			t.Fatal(err)
		}
		body = payload
	}
	return body
}

// A process that holds a copy of the session's monitor socket replays an
// allowed request with the next sequence number, so the listener queues an
// extra allow. The session's next request is denied by policy and must not
// be satisfied by that queued allow.
func TestServeSSHMonitorForgedFrameCannotDesync(t *testing.T) {
	id := "mon-desync"
	registerMonitorSession(t, id)
	server, clientSide := monitorSocketpair(t)
	var calls atomic.Int32
	go ServeSSHMonitor(server, id, func(args []string) error {
		calls.Add(1)
		if args[0] == "rm" {
			return errors.New("rm is denied")
		}
		return nil
	})
	_ = clientSide.SetDeadline(time.Now().Add(3 * time.Second))
	capc := &captureConn{Conn: clientSide}
	client := sys.NewMonitorClient(capc)
	if err := client.Authorize([]string{"ls"}); err != nil {
		t.Fatal(err)
	}

	// The forger replays the allowed request with the next id.
	var forged sys.MonitorAuthRequest
	if err := json.Unmarshal(lastFrame(t, capc.text()), &forged); err != nil {
		t.Fatal(err)
	}
	forged.ID++
	body, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.WriteMonitorFrame(clientSide, sys.MonitorFrameAuthorize, body); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatal("forged frame did not reach the gate")
	}

	if err := client.Authorize([]string{"rm", "-rf", "/"}); err == nil {
		t.Fatal("denied command was allowed by a queued forged response")
	}
	if err := client.Authorize([]string{"ls"}); err == nil {
		t.Fatal("client kept using a desynchronised monitor")
	}
}

func authRequest(t *testing.T, c net.Conn, id uint64, args ...string) {
	t.Helper()
	body, err := json.Marshal(sys.MonitorAuthRequest{ID: id, Args: args})
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.WriteMonitorFrame(c, sys.MonitorFrameAuthorize, body); err != nil {
		t.Fatal(err)
	}
}

func TestServeSSHMonitorRejectsBadSequence(t *testing.T) {
	cases := []struct {
		name   string
		second uint64
	}{
		{"repeated", 10},
		{"older", 9},
		{"gap", 12},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := "mon-seq-" + tc.name
			registerMonitorSession(t, id)
			var calls atomic.Int32
			client, _ := dialMonitor(t, id, func([]string) error {
				calls.Add(1)
				return nil
			})
			authRequest(t, client, 10, "ls")
			resp := readAuth(t, client)
			if !resp.OK || resp.ID != 10 || resp.ArgsDigest != sys.MonitorArgsDigest([]string{"ls"}) {
				t.Fatalf("first = %+v", resp)
			}
			authRequest(t, client, tc.second, "ls")
			if _, _, err := sys.ReadMonitorFrame(client); err == nil {
				t.Fatal("server answered an out-of-sequence request")
			}
			if calls.Load() != 1 {
				t.Fatalf("gate calls = %d", calls.Load())
			}
		})
	}
}
