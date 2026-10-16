package sys

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func writeJSONFrame(t *testing.T, conn net.Conn, typ byte, v any) error {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return WriteMonitorFrame(conn, typ, body)
}

// fakeRunListener reads one Run frame and lets answer write the replies.
func fakeRunListener(t *testing.T, answer func(server net.Conn, req MonitorRunRequest) error) (*MonitorClient, chan error) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	errCh := make(chan error, 1)
	go func() {
		typ, payload, err := ReadMonitorFrame(server)
		if err != nil {
			errCh <- err
			return
		}
		if typ != MonitorFrameRun {
			errCh <- errors.New("not a run frame")
			return
		}
		req, err := DecodeMonitorRun(payload)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- answer(server, req)
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	return NewMonitorClient(client), errCh
}

func TestMonitorClientRunStreamsOutputAndStdin(t *testing.T) {
	mc, errCh := fakeRunListener(t, func(server net.Conn, req MonitorRunRequest) error {
		if req.StdinMode != MonitorStdinBytes || string(req.Stdin) != "hello stdin" {
			return errors.New("stdin did not reach the listener")
		}
		if len(req.Args) != 2 || req.Args[0] != "why" {
			return errors.New("args")
		}
		if err := writeJSONFrame(t, server, MonitorFrameOut, MonitorOut{ID: req.ID, Seq: 1, Stream: MonitorStreamStdout, Data: []byte("out-1 ")}); err != nil {
			return err
		}
		if err := writeJSONFrame(t, server, MonitorFrameOut, MonitorOut{ID: req.ID, Seq: 2, Stream: MonitorStreamStderr, Data: []byte("err-1")}); err != nil {
			return err
		}
		if err := writeJSONFrame(t, server, MonitorFrameOut, MonitorOut{ID: req.ID, Seq: 3, Stream: MonitorStreamStdout, Data: []byte("out-2")}); err != nil {
			return err
		}
		return writeJSONFrame(t, server, MonitorFrameExit, MonitorExit{ID: req.ID, Digest: MonitorRunDigest(req.Args, req.StdinMode, req.Stdin), Code: 3})
	})
	var stdout, stderr lockedBuf
	code, err := mc.Run([]string{"why", "rm"}, MonitorStdinBytes, []byte("hello stdin"), &stdout, &stderr)
	if err != nil || code != 3 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if stdout.String() != "out-1 out-2" || stderr.String() != "err-1" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestMonitorClientRunExitError(t *testing.T) {
	mc, _ := fakeRunListener(t, func(server net.Conn, req MonitorRunRequest) error {
		return writeJSONFrame(t, server, MonitorFrameExit, MonitorExit{ID: req.ID, Digest: MonitorRunDigest(req.Args, req.StdinMode, req.Stdin), Code: 1, Error: "adssh: access denied"})
	})
	code, err := mc.Run([]string{"elevate", "status"}, MonitorStdinNone, nil, &lockedBuf{}, &lockedBuf{})
	if err == nil || err.Error() != "adssh: access denied" || code != 1 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if mc.broken.Load() {
		t.Fatal("a listener deny broke the client")
	}
}

func TestMonitorClientRunForgedFramesMarkBroken(t *testing.T) {
	cases := []struct {
		name   string
		answer func(t *testing.T, server net.Conn, req MonitorRunRequest) error
	}{
		{name: "out wrong id", answer: func(t *testing.T, server net.Conn, req MonitorRunRequest) error {
			return writeJSONFrame(t, server, MonitorFrameOut, MonitorOut{ID: req.ID + 1, Seq: 1, Stream: 1, Data: []byte("x")})
		}},
		{name: "exit wrong id", answer: func(t *testing.T, server net.Conn, req MonitorRunRequest) error {
			return writeJSONFrame(t, server, MonitorFrameExit, MonitorExit{ID: req.ID - 1, Digest: MonitorRunDigest(req.Args, req.StdinMode, req.Stdin)})
		}},
		{name: "exit wrong digest", answer: func(t *testing.T, server net.Conn, req MonitorRunRequest) error {
			return writeJSONFrame(t, server, MonitorFrameExit, MonitorExit{ID: req.ID, Digest: MonitorRunDigest(req.Args, MonitorStdinBytes, []byte("other"))})
		}},
		{name: "out skipped seq", answer: func(t *testing.T, server net.Conn, req MonitorRunRequest) error {
			return writeJSONFrame(t, server, MonitorFrameOut, MonitorOut{ID: req.ID, Seq: 2, Stream: 1, Data: []byte("x")})
		}},
		{name: "out bad stream", answer: func(t *testing.T, server net.Conn, req MonitorRunRequest) error {
			return writeJSONFrame(t, server, MonitorFrameOut, MonitorOut{ID: req.ID, Seq: 1, Stream: 3, Data: []byte("x")})
		}},
		{name: "authorize during run", answer: func(t *testing.T, server net.Conn, req MonitorRunRequest) error {
			return writeJSONFrame(t, server, MonitorFrameAuthorize, MonitorAuthResponse{ID: req.ID, ArgsDigest: MonitorArgsDigest(req.Args), OK: true})
		}},
		{name: "exit unknown field", answer: func(t *testing.T, server net.Conn, req MonitorRunRequest) error {
			return WriteMonitorFrame(server, MonitorFrameExit, []byte(`{"id":1,"code":0,"session_id":"x"}`))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, _ := fakeRunListener(t, func(server net.Conn, req MonitorRunRequest) error {
				return tc.answer(t, server, req)
			})
			var stdout lockedBuf
			if _, err := mc.Run([]string{"why", "rm"}, MonitorStdinNone, nil, &stdout, &lockedBuf{}); err == nil {
				t.Fatal("forged frame accepted")
			}
			if !mc.broken.Load() {
				t.Fatal("client not broken")
			}
			if stdout.String() != "" {
				t.Fatalf("forged output written: %q", stdout.String())
			}
			// A broken client refuses without touching the socket.
			if err := mc.Authorize([]string{"ls"}); !errors.Is(err, errMonitorClosed) {
				t.Fatalf("after break: %v", err)
			}
		})
	}
}

func TestMonitorClientRunRejectsBeforeSocket(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	mc := NewMonitorClient(client)
	big := bytes.Repeat([]byte("a"), MaxMonitorRunStdin+1)
	cases := []struct {
		args  []string
		mode  string
		stdin []byte
	}{
		{args: []string{"why"}, mode: MonitorStdinBytes, stdin: big},
		{args: []string{"why"}, mode: "file", stdin: nil},
		{args: []string{"why"}, mode: MonitorStdinNone, stdin: []byte("x")},
		{args: nil, mode: MonitorStdinNone},
		{args: []string{"a\x00b"}, mode: MonitorStdinNone},
	}
	for _, tc := range cases {
		if _, err := mc.Run(tc.args, tc.mode, tc.stdin, &lockedBuf{}, &lockedBuf{}); err == nil {
			t.Fatalf("%q %q accepted", tc.args, tc.mode)
		}
	}
	if mc.broken.Load() {
		t.Fatal("argument errors broke the client")
	}
}

func TestDecodeMonitorRunRejects(t *testing.T) {
	big := strings.Repeat("a", MaxMonitorRunStdin+1)
	bigB64, _ := json.Marshal([]byte(big))
	for _, payload := range []string{
		`{"id":1,"args":["why"],"stdin_mode":"none","session_id":"other"}`,
		`{"id":1,"args":["why"],"stdin_mode":"none","session":"other"}`,
		`{"id":0,"args":["why"],"stdin_mode":"none"}`,
		`{"id":1,"args":[],"stdin_mode":"none"}`,
		`{"id":1,"args":["why"],"stdin_mode":"tty"}`,
		`{"id":1,"args":["why"]}`,
		`{"id":1,"args":["why"],"stdin_mode":"none","stdin":"eA=="}`,
		`{"id":1,"args":["why"],"stdin_mode":"bytes","stdin":` + string(bigB64) + `}`,
		`{"id":1,"args":["why"],"stdin_mode":"none"}{}`,
		`{`,
	} {
		if _, err := DecodeMonitorRun([]byte(payload)); err == nil {
			t.Fatalf("accepted %.80s", payload)
		}
	}
	req, err := DecodeMonitorRun([]byte(`{"id":9,"args":["why","rm"],"stdin_mode":"bytes","stdin":"aGk="}`))
	if err != nil || req.ID != 9 || string(req.Stdin) != "hi" {
		t.Fatalf("req=%+v err=%v", req, err)
	}
	for _, payload := range []string{`{"id":0}`, `{"id":1,"session_id":"x"}`, `{}`, `[`} {
		if _, err := DecodeMonitorCancel([]byte(payload)); err == nil {
			t.Fatalf("cancel accepted %s", payload)
		}
	}
}

func TestMonitorRunDigestBindsStdin(t *testing.T) {
	a := MonitorRunDigest([]string{"why", "rm"}, MonitorStdinNone, nil)
	if a == MonitorRunDigest([]string{"why", "rm"}, MonitorStdinBytes, nil) ||
		a == MonitorRunDigest([]string{"why", "rm"}, MonitorStdinBytes, []byte("x")) ||
		a == MonitorRunDigest([]string{"whyrm"}, MonitorStdinNone, nil) ||
		a == MonitorArgsDigest([]string{"why", "rm"}) {
		t.Fatal("digest does not bind args, stdin mode and stdin")
	}
}

// Cancel during a run sends the run's id; the listener then finishes it.
func TestMonitorClientCancelSendsRunID(t *testing.T) {
	gotCancel := make(chan uint64, 1)
	mc, errCh := fakeRunListener(t, func(server net.Conn, req MonitorRunRequest) error {
		typ, payload, err := ReadMonitorFrame(server)
		if err != nil {
			return err
		}
		if typ != MonitorFrameCancel {
			return errors.New("not a cancel frame")
		}
		c, err := DecodeMonitorCancel(payload)
		if err != nil {
			return err
		}
		gotCancel <- c.ID
		if c.ID != req.ID {
			return errors.New("cancel id")
		}
		return writeJSONFrame(t, server, MonitorFrameExit, MonitorExit{ID: req.ID, Digest: MonitorRunDigest(req.Args, req.StdinMode, req.Stdin), Code: 1, Error: "canceled"})
	})
	done := make(chan error, 1)
	go func() {
		_, err := mc.Run([]string{"elevate", "status"}, MonitorStdinNone, nil, &lockedBuf{}, &lockedBuf{})
		done <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for mc.active.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("run never became active")
		}
		time.Sleep(5 * time.Millisecond)
	}
	mc.Cancel()
	select {
	case err := <-done:
		if err == nil || err.Error() != "canceled" {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not finish after cancel")
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if mc.active.Load() != 0 {
		t.Fatal("active id not cleared")
	}
	// Cancel with nothing in flight does not touch the socket.
	mc.Cancel()
}
