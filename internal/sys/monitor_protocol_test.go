//go:build unix

package sys

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// respondWith reads one authorize request and answers with build(req).
func respondWith(t *testing.T, build func(MonitorAuthRequest) MonitorAuthResponse) (*MonitorClient, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	go func() {
		for {
			typ, payload, err := ReadMonitorFrame(server)
			if err != nil || typ != MonitorFrameAuthorize {
				return
			}
			req, err := DecodeMonitorAuth(payload)
			if err != nil {
				return
			}
			body, err := json.Marshal(build(req))
			if err != nil {
				return
			}
			if err := WriteMonitorFrame(server, MonitorFrameAuthorize, body); err != nil {
				return
			}
		}
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	return NewMonitorClient(client), client
}

func TestMonitorClientEchoedIDAndDigest(t *testing.T) {
	var ids []uint64
	mc, _ := respondWith(t, func(req MonitorAuthRequest) MonitorAuthResponse {
		ids = append(ids, req.ID)
		return MonitorAuthResponse{ID: req.ID, ArgsDigest: MonitorArgsDigest(req.Args), OK: true}
	})
	for i := 0; i < 3; i++ {
		if err := mc.Authorize([]string{"ls", "-l"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(ids) != 3 || ids[0] == 0 || ids[1] != ids[0]+1 || ids[2] != ids[1]+1 {
		t.Fatalf("ids = %v, want nonzero and strictly +1", ids)
	}
}

func TestMonitorClientStartIDIsNotFixed(t *testing.T) {
	a := NewMonitorClient(nil)
	b := NewMonitorClient(nil)
	if a.nextID == 0 || b.nextID == 0 {
		t.Fatal("start id is zero")
	}
	if a.nextID == b.nextID {
		t.Fatal("two clients started at the same id")
	}
}

func TestMonitorClientFailsClosedOnMismatch(t *testing.T) {
	cases := []struct {
		name  string
		build func(MonitorAuthRequest) MonitorAuthResponse
	}{
		{"stale id", func(req MonitorAuthRequest) MonitorAuthResponse {
			return MonitorAuthResponse{ID: req.ID - 1, ArgsDigest: MonitorArgsDigest(req.Args), OK: true}
		}},
		{"future id", func(req MonitorAuthRequest) MonitorAuthResponse {
			return MonitorAuthResponse{ID: req.ID + 1, ArgsDigest: MonitorArgsDigest(req.Args), OK: true}
		}},
		{"missing id", func(req MonitorAuthRequest) MonitorAuthResponse {
			return MonitorAuthResponse{ArgsDigest: MonitorArgsDigest(req.Args), OK: true}
		}},
		{"other args", func(req MonitorAuthRequest) MonitorAuthResponse {
			return MonitorAuthResponse{ID: req.ID, ArgsDigest: MonitorArgsDigest([]string{"ls"}), OK: true}
		}},
		{"missing digest", func(req MonitorAuthRequest) MonitorAuthResponse {
			return MonitorAuthResponse{ID: req.ID, OK: true}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, _ := respondWith(t, tc.build)
			err := mc.Authorize([]string{"rm", "-rf", "/"})
			if err == nil || !errors.Is(err, errMonitorDesync) {
				t.Fatalf("err = %v", err)
			}
			// The client stays broken: a later call must not reach the wire.
			if err := mc.Authorize([]string{"ls"}); err == nil || !errors.Is(err, errMonitorClosed) {
				t.Fatalf("after desync = %v", err)
			}
			if err := mc.Ping(); err == nil || !errors.Is(err, errMonitorClosed) {
				t.Fatalf("ping after desync = %v", err)
			}
		})
	}
}

func TestDecodeMonitorAuthRequiresID(t *testing.T) {
	for _, body := range []string{`{"args":["ls"]}`, `{"id":0,"args":["ls"]}`, `{"id":-1,"args":["ls"]}`} {
		if _, err := DecodeMonitorAuth([]byte(body)); !errors.Is(err, errMonitorInvalidArgument) {
			t.Fatalf("%s = %v", body, err)
		}
	}
	req, err := DecodeMonitorAuth([]byte(`{"id":7,"args":["ls"]}`))
	if err != nil || req.ID != 7 {
		t.Fatalf("id 7 = %v %#v", err, req)
	}
}

func TestValidateMonitorArgsRejectsInvalidUTF8(t *testing.T) {
	if err := ValidateMonitorArgs([]string{"ls", "\xff\xfe"}); !errors.Is(err, errMonitorInvalidArgument) {
		t.Fatalf("invalid utf-8 = %v", err)
	}
}

func TestMonitorArgsDigestSeparatesArguments(t *testing.T) {
	if MonitorArgsDigest([]string{"ab", "c"}) == MonitorArgsDigest([]string{"a", "bc"}) {
		t.Fatal("argument boundaries are not bound")
	}
	if MonitorArgsDigest([]string{"ls"}) != MonitorArgsDigest([]string{"ls"}) {
		t.Fatal("digest is not stable")
	}
}

// The listener end of the pair must be pollable, so Close and deadlines
// release a reader even while a leaked copy of the child end stays open.
func TestMonitorPairCloseUnblocksReader(t *testing.T) {
	parent, child, err := newMonitorPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Close() })
	conn := NewMonitorConn(parent)
	done := make(chan error, 1)
	go func() {
		_, _, err := ReadMonitorFrame(conn)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Fatalf("reader released after %v", d)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Close did not unblock the monitor reader")
	}
}

func TestMonitorPairSupportsReadDeadline(t *testing.T) {
	parent, child, err := newMonitorPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close(); _ = child.Close() })
	if err := NewMonitorConn(parent).SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := ReadMonitorFrame(NewMonitorConn(parent))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read returned a frame")
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not fire")
	}
}

const monitorFDHelperEnv = "ADSSH_TEST_MONITOR_FD_HELPER"

// TestHelperMonitorFDCloexec runs only as a child of
// TestOpenMonitorFDSetsCloexec. It takes fd 3 the way the session process
// does and reports whether a command it starts can still see fd 3.
func TestHelperMonitorFDCloexec(t *testing.T) {
	if os.Getenv(monitorFDHelperEnv) != "1" {
		t.Skip("helper process")
	}
	f, err := OpenMonitorFD(3)
	if err != nil {
		os.Stdout.WriteString("open-error\n")
		os.Exit(2)
	}
	defer f.Close()
	out, _ := exec.Command("/bin/sh", "-c", "{ : >&3; } 2>/dev/null && echo fd3=open || echo fd3=closed").Output()
	os.Stdout.Write(out)
	os.Exit(0)
}

func TestOpenMonitorFDSetsCloexec(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is not available")
	}
	parent, child, err := newMonitorPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMonitorFDCloexec$")
	cmd.Env = append(os.Environ(), monitorFDHelperEnv+"=1")
	cmd.ExtraFiles = []*os.File{child}
	out, err := cmd.Output()
	_ = child.Close()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "fd3=closed") {
		t.Fatalf("a command run by the session can use the monitor socket: %q", out)
	}
}
