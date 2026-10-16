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
	"testing"
	"time"
)

type stopAfter struct {
	buf []byte
	off int
}

func (r *stopAfter) Read(p []byte) (int, error) {
	if r.off >= 4 {
		return 0, errors.New("read past header")
	}
	n := copy(p, r.buf[r.off:])
	if r.off+n > 4 {
		n = 4 - r.off
	}
	r.off += n
	if n == 0 {
		return 0, errors.New("read past header")
	}
	return n, nil
}

func TestReadMonitorFrameRejectsOversizedBeforeBody(t *testing.T) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(MaxMonitorFrame+1))
	r := &stopAfter{buf: hdr}
	_, _, err := ReadMonitorFrame(r)
	if !errors.Is(err, errMonitorFrameTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if r.off != 4 {
		t.Fatalf("off = %d, want 4", r.off)
	}
}

func TestReadMonitorFrameShortHeaderClosed(t *testing.T) {
	_, _, err := ReadMonitorFrame(bytes.NewReader([]byte{0, 0}))
	if err == nil || err.Error() != "adssh: ssh monitor: closed" || !errors.Is(err, errMonitorClosed) {
		t.Fatalf("err = %v", err)
	}
}

func TestReadMonitorFrameTruncatedBodyClosed(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 20)
	buf.Write(hdr[:])
	buf.WriteByte(MonitorFrameAuthorize)
	buf.WriteByte('x')
	_, _, err := ReadMonitorFrame(&buf)
	if err == nil || err.Error() != "adssh: ssh monitor: closed" || !errors.Is(err, errMonitorClosed) {
		t.Fatalf("err = %v", err)
	}
}

type oneShot struct {
	n   int
	buf bytes.Buffer
}

func (w *oneShot) Write(p []byte) (int, error) {
	w.n++
	if w.n > 1 {
		return 0, errors.New("second write")
	}
	return w.buf.Write(p)
}

func TestWriteMonitorFrameOneWrite(t *testing.T) {
	w := &oneShot{}
	if err := WriteMonitorFrame(w, MonitorFramePing, nil); err != nil {
		t.Fatal(err)
	}
	if w.n != 1 {
		t.Fatalf("writes = %d, want 1", w.n)
	}
}

type shortWrite struct{}

func (shortWrite) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return 1, nil
}

func TestWriteMonitorFrameShortWriteClosed(t *testing.T) {
	err := WriteMonitorFrame(shortWrite{}, MonitorFramePing, []byte("x"))
	if err == nil || err.Error() != "adssh: ssh monitor: closed" || !errors.Is(err, errMonitorClosed) {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateMonitorArgsBounds(t *testing.T) {
	if maxMonitorArgLen != maxEnvValueLen {
		t.Fatalf("maxMonitorArgLen = %d, maxEnvValueLen = %d", maxMonitorArgLen, maxEnvValueLen)
	}
	c := NewMonitorClient(nil)
	if err := c.Authorize(nil); !errors.Is(err, errMonitorInvalidArgument) {
		t.Fatalf("empty = %v", err)
	}
	if err := c.Authorize([]string{}); !errors.Is(err, errMonitorInvalidArgument) {
		t.Fatalf("empty slice = %v", err)
	}
	err := c.Authorize([]string{"sekret\x00"})
	if err == nil || !errors.Is(err, errMonitorInvalidArgument) {
		t.Fatalf("nul = %v", err)
	}
	if strings.Contains(err.Error(), "sekret") {
		t.Fatal("value leaked")
	}
	long := strings.Repeat("a", maxMonitorArgLen+1)
	err = c.Authorize([]string{long})
	if err == nil || !errors.Is(err, errMonitorInvalidArgument) {
		t.Fatalf("oversize = %v", err)
	}

	ok := make([]string, maxMonitorArgs)
	for i := range ok {
		ok[i] = "a"
	}
	if err := ValidateMonitorArgs(ok); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMonitorArgs(append(ok, "a")); !errors.Is(err, errMonitorInvalidArgument) {
		t.Fatalf("4097 = %v", err)
	}
	if err := ValidateMonitorArgs([]string{strings.Repeat("b", maxMonitorArgLen)}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMonitorArgs([]string{""}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeMonitorAuthRejects(t *testing.T) {
	if _, err := DecodeMonitorAuth([]byte(`{"args":[]}`)); !errors.Is(err, errMonitorInvalidArgument) {
		t.Fatalf("empty args = %v", err)
	}
	if _, err := DecodeMonitorAuth([]byte(`{}`)); !errors.Is(err, errMonitorInvalidArgument) {
		t.Fatalf("missing args = %v", err)
	}
	_, err := DecodeMonitorAuth([]byte(`{"args":["ls"],"session_id":"sekret"}`))
	if err == nil || !errors.Is(err, errMonitorInvalidArgument) {
		t.Fatalf("unknown field = %v", err)
	}
	if strings.Contains(err.Error(), "sekret") {
		t.Fatal("value leaked")
	}
	if _, err := DecodeMonitorAuth([]byte(`{"args":["ls"]}{"args":["ls"]}`)); !errors.Is(err, errMonitorInvalidArgument) {
		t.Fatalf("junk = %v", err)
	}
	req, err := DecodeMonitorAuth([]byte("{\"args\":[\"ls\"]}\n"))
	if err != nil || len(req.Args) != 1 || req.Args[0] != "ls" {
		t.Fatalf("whitespace = %v %#v", err, req)
	}
	req, err = DecodeMonitorAuth([]byte(`{"args":[""]}`))
	if err != nil || len(req.Args) != 1 || req.Args[0] != "" {
		t.Fatalf("empty element = %v %#v", err, req)
	}
}

func TestNewMonitorConn(t *testing.T) {
	if NewMonitorConn(nil) != nil {
		t.Fatal("nil file became a conn")
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	c := NewMonitorConn(f)
	if c.LocalAddr().Network() != "unix" || c.LocalAddr().String() != "ssh-monitor" {
		t.Fatalf("local = %s %s", c.LocalAddr().Network(), c.LocalAddr().String())
	}
	if c.RemoteAddr().Network() != "unix" || c.RemoteAddr().String() != "ssh-monitor" {
		t.Fatalf("remote = %s %s", c.RemoteAddr().Network(), c.RemoteAddr().String())
	}
}

func TestMonitorClientHappy(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	errCh := make(chan error, 1)
	go func() {
		defer server.Close()
		for i := 0; i < 2; i++ {
			typ, payload, err := ReadMonitorFrame(server)
			if err != nil {
				errCh <- err
				return
			}
			switch typ {
			case MonitorFramePing:
				if len(payload) != 0 {
					errCh <- errors.New("ping payload")
					return
				}
				if err := WriteMonitorFrame(server, MonitorFramePing, nil); err != nil {
					errCh <- err
					return
				}
			case MonitorFrameAuthorize:
				if _, err := DecodeMonitorAuth(payload); err != nil {
					errCh <- err
					return
				}
				body, err := json.Marshal(MonitorAuthResponse{OK: true})
				if err != nil {
					errCh <- err
					return
				}
				if err := WriteMonitorFrame(server, MonitorFrameAuthorize, body); err != nil {
					errCh <- err
					return
				}
			default:
				errCh <- errors.New("unexpected type")
				return
			}
		}
		errCh <- nil
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	mc := NewMonitorClient(client)
	if err := mc.Ping(); err != nil {
		t.Fatal(err)
	}
	if err := mc.Authorize([]string{"ls"}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not finish")
	}
}

func serveMonitorResponse(t *testing.T, typ byte, payload []byte) *MonitorClient {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	go func() {
		if _, _, err := ReadMonitorFrame(server); err != nil {
			return
		}
		_ = WriteMonitorFrame(server, typ, payload)
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	return NewMonitorClient(client)
}

func TestMonitorClientDenyShapes(t *testing.T) {
	body, err := json.Marshal(MonitorAuthResponse{OK: true, Error: "not allowed"})
	if err != nil {
		t.Fatal(err)
	}
	mc := serveMonitorResponse(t, MonitorFrameAuthorize, body)
	err = mc.Authorize([]string{"ls"})
	if err == nil || err.Error() != "not allowed" || errors.Is(err, errMonitorDenied) {
		t.Fatalf("ok+error = %v", err)
	}

	body, err = json.Marshal(MonitorAuthResponse{OK: false})
	if err != nil {
		t.Fatal(err)
	}
	mc = serveMonitorResponse(t, MonitorFrameAuthorize, body)
	err = mc.Authorize([]string{"ls"})
	if err == nil || err.Error() != "adssh: ssh monitor: denied" || !errors.Is(err, errMonitorDenied) {
		t.Fatalf("ok false = %v", err)
	}
}

func TestMonitorClientClosedResponses(t *testing.T) {
	cases := []struct {
		name    string
		typ     byte
		payload []byte
	}{
		{name: "malformed", typ: MonitorFrameAuthorize, payload: []byte("{")},
		{name: "wrong type", typ: MonitorFramePing, payload: nil},
		{name: "trailing junk", typ: MonitorFrameAuthorize, payload: []byte(`{"ok":true}{"ok":false}`)},
		{name: "unknown field", typ: MonitorFrameAuthorize, payload: []byte(`{"ok":true,"session_id":"sekret"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc := serveMonitorResponse(t, tc.typ, tc.payload)
			err := mc.Authorize([]string{"ls"})
			if err == nil || err.Error() != "adssh: ssh monitor: closed" || !errors.Is(err, errMonitorClosed) {
				t.Fatalf("err = %v", err)
			}
			if strings.Contains(err.Error(), "sekret") {
				t.Fatal("value leaked")
			}
		})
	}
}

func TestMonitorClientPingPayloadCloses(t *testing.T) {
	mc := serveMonitorResponse(t, MonitorFramePing, []byte("x"))
	err := mc.Ping()
	if err == nil || err.Error() != "adssh: ssh monitor: closed" || !errors.Is(err, errMonitorClosed) {
		t.Fatalf("err = %v", err)
	}
}

func TestMonitorClientPingFrameTooLarge(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	errCh := make(chan error, 1)
	go func() {
		if _, _, err := ReadMonitorFrame(server); err != nil {
			errCh <- err
			return
		}
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(MaxMonitorFrame+1))
		_, err := server.Write(hdr[:])
		errCh <- err
	}()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	err := NewMonitorClient(client).Ping()
	if !errors.Is(err, errMonitorFrameTooLarge) {
		t.Fatalf("err = %v", err)
	}
	select {
	case werr := <-errCh:
		if werr != nil && !errors.Is(werr, io.ErrClosedPipe) && !errors.Is(werr, net.ErrClosed) {
			t.Fatal(werr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not finish")
	}
}
