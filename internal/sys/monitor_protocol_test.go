//go:build unix

package sys

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
	first, second := MonitorArgsDigest([]string{"ls"}), MonitorArgsDigest([]string{"ls"})
	if first != second {
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
	case readErr := <-done:
		if readErr == nil {
			t.Fatal("reader returned no error after Close")
		}
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

const (
	monitorFDHelperEnv = "ADSSH_TEST_MONITOR_FD_HELPER"
	monitorFDInodeEnv  = "ADSSH_TEST_MONITOR_FD_INODE"
)

// fdInode returns "dev:ino" of an open descriptor.
func fdInode(fd int) (string, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), nil
}

// TestHelperMonitorFDCloexec runs only as a child of
// TestOpenMonitorFDSetsCloexec, in two stages. Stage "session" takes fd 3
// the way the session process does and re-execs this binary with no extra
// files. Stage "probe" is that command: it checks fd 3 with fstat and prints
// exactly one token. fd3=open means fd 3 is the monitor socket (same dev and
// inode); fd3=closed means fd 3 is closed or is some other descriptor the Go
// runtime opened. A shell probe is not used: in dash a failed redirection on
// the special builtin ":" exits the shell, which printed nothing on Linux.
func TestHelperMonitorFDCloexec(t *testing.T) {
	switch os.Getenv(monitorFDHelperEnv) {
	case "session":
		f, err := OpenMonitorFD(3)
		if err != nil {
			os.Stdout.WriteString("open-error\n")
			os.Exit(2)
		}
		defer f.Close()
		ino, err := fdInode(3)
		if err != nil {
			os.Stdout.WriteString("stat-error\n")
			os.Exit(2)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMonitorFDCloexec$")
		cmd.Env = append(os.Environ(), monitorFDHelperEnv+"=probe", monitorFDInodeEnv+"="+ino)
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			fmt.Fprintf(os.Stdout, "probe-error:%v\n", err)
			os.Exit(2)
		}
		os.Stdout.Write(out)
		os.Exit(0)
	case "probe":
		ino, err := fdInode(3)
		if err == nil && ino == os.Getenv(monitorFDInodeEnv) {
			os.Stdout.WriteString("fd3=open\n")
		} else {
			os.Stdout.WriteString("fd3=closed\n")
		}
		os.Exit(0)
	default:
		t.Skip("helper process")
	}
}

func TestOpenMonitorFDSetsCloexec(t *testing.T) {
	parent, child, err := newMonitorPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMonitorFDCloexec$")
	cmd.Env = append(os.Environ(), monitorFDHelperEnv+"=session")
	cmd.ExtraFiles = []*os.File{child}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	_ = child.Close()
	got := strings.TrimSpace(string(out))
	if err != nil {
		t.Fatalf("helper: %v\nstdout: %q\nstderr: %s", err, got, stderr.String())
	}
	switch got {
	case "fd3=closed":
	case "fd3=open":
		t.Fatal("a command run by the session can use the monitor socket")
	default:
		t.Fatalf("helper printed %q, want fd3=closed or fd3=open\nstderr: %s", got, stderr.String())
	}
}
