package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/security"
)

const (
	namedKey  = "named-key-0123456789abcdef0123456789abcdef"
	legacyKey = "legacy-key-0123456789abcdef0123456789abcdef"
)

func writeKeyFile(t *testing.T, key string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseEndpoint(t *testing.T) {
	for _, ok := range []string{"", "http://127.0.0.1:8787", "http://localhost:8787", "http://[::1]:9", "unix:/run/adssh/admin.sock"} {
		if _, err := parseEndpoint(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://10.0.0.5:8787", "http://example.com:8787", "https://127.0.0.1:8787",
		"http://user:pw@127.0.0.1:8787", "http://127.0.0.1:8787/v1", "http://127.0.0.1:8787?x=1",
		"unix:relative.sock", "ftp://127.0.0.1", "127.0.0.1:8787",
	} {
		if _, err := parseEndpoint(bad); err == nil {
			t.Errorf("%q accepted; a key must never leave loopback or the socket", bad)
		}
	}
}

func TestLoadKeyRefusesUnsafeFiles(t *testing.T) {
	if _, err := loadKey(writeKeyFile(t, namedKey, 0o600)); err != nil {
		t.Fatalf("0600 key refused: %v", err)
	}
	if _, err := loadKey(writeKeyFile(t, namedKey, 0o644)); err == nil {
		t.Error("group/world readable key file accepted")
	}
	if _, err := loadKey(writeKeyFile(t, "short", 0o600)); err == nil {
		t.Error("short key accepted")
	}
	if _, err := loadKey(writeKeyFile(t, "has space in the middle of a long key value", 0o600)); err == nil {
		t.Error("key with whitespace accepted")
	}
	if _, err := loadKey(writeKeyFile(t, strings.Repeat("k", keyFileMax+10), 0o600)); err == nil {
		t.Error("oversized key file accepted")
	}
	target := writeKeyFile(t, namedKey, 0o600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(link); err == nil {
		t.Error("symlinked key file accepted")
	}
	if _, err := loadKey(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing key file accepted")
	}
	if _, err := loadKey(""); err == nil {
		t.Error("empty path accepted")
	}
}

// realServer serves the actual adssh admin handler on loopback.
func realServer(t *testing.T) *httptest.Server {
	t.Helper()
	h := security.NewAdminHTTPHandlerWithKeys(nil, legacyKey, []security.AdminKey{{Name: "ryan", Key: namedKey}})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func testApp(t *testing.T, base, key string) (*app, *bytes.Buffer) {
	t.Helper()
	ep, err := parseEndpoint(base)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	return &app{c: newClient(ep, key), out: &out, yes: true}, &out
}

func TestListsAgainstRealAdminAPI(t *testing.T) {
	srv := realServer(t)
	a, out := testApp(t, srv.URL, legacyKey)
	ctx := context.Background()
	for _, cmd := range [][]string{{"sessions"}, {"approvals"}, {"gateways"}, {"guard"}} {
		out.Reset()
		if err := a.dispatch(ctx, cmd); err != nil {
			t.Fatalf("%v: %v", cmd, err)
		}
	}
}

func TestWrongKeyIsUnauthorized(t *testing.T) {
	srv := realServer(t)
	a, _ := testApp(t, srv.URL, "wrong-key-0123456789abcdef0123456789abcdef")
	err := a.dispatch(context.Background(), []string{"sessions"})
	var ae *apiError
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		t.Fatalf("want 401, got %v", err)
	}
}

func TestLegacyKeyCannotApproveOrUnban(t *testing.T) {
	srv := realServer(t)
	a, _ := testApp(t, srv.URL, legacyKey)
	for _, cmd := range [][]string{{"approve", "abc"}, {"deny", "abc"}, {"guard", "unban", "203.0.113.9"}} {
		err := a.dispatch(context.Background(), cmd)
		var ae *apiError
		if !errors.As(err, &ae) || ae.Status != http.StatusForbidden {
			t.Errorf("%v with the read-only key: want 403, got %v", cmd, err)
		}
	}
}

func TestWriteCommandsAskFirst(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	a, _ := testApp(t, srv.URL, namedKey)
	a.yes = false
	a.confirm = func(string) bool { return false }
	a.snoop = func(context.Context, *app, snoopRequest) error { hits.Add(1); return nil }
	for _, cmd := range [][]string{
		{"approve", "abc"}, {"deny", "abc"}, {"guard", "unban", "203.0.113.9"},
		{"snoop", "s1", "alice", "--purpose", "support", "--reason", "ticket 42"},
	} {
		if err := a.dispatch(context.Background(), cmd); err == nil || err.Error() != "canceled" {
			t.Errorf("%v: want canceled, got %v", cmd, err)
		}
	}
	a.confirm = nil // non-interactive, no --yes
	if err := a.dispatch(context.Background(), []string{"approve", "abc"}); err == nil {
		t.Error("non-interactive approve without --yes went through")
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests sent after the operator declined", hits.Load())
	}
}

func TestParseSnoopRequiresPurposeAndReason(t *testing.T) {
	good := []string{"s-1", "alice", "--purpose", "investigation", "--reason", "case 7"}
	r, err := parseSnoop(good)
	if err != nil || r.RW || r.mode() != "view" {
		t.Fatalf("good request: %+v %v", r, err)
	}
	if r, err := parseSnoop(append([]string{"--rw"}, good...)); err != nil || r.mode() != "rw" {
		t.Fatalf("--rw: %+v %v", r, err)
	}
	for name, args := range map[string][]string{
		"no purpose":    {"s-1", "alice", "--reason", "x"},
		"no reason":     {"s-1", "alice", "--purpose", "support"},
		"blank reason":  {"s-1", "alice", "--purpose", "support", "--reason", "   "},
		"bad purpose":   {"s-1", "alice", "--purpose", "curiosity", "--reason", "x"},
		"control char":  {"s-1", "alice", "--purpose", "support", "--reason", "a\x1b[2Jb"},
		"long reason":   {"s-1", "alice", "--purpose", "support", "--reason", strings.Repeat("r", maxReason+1)},
		"bad id":        {"../s", "alice", "--purpose", "support", "--reason", "x"},
		"bad user":      {"s-1", "al ice", "--purpose", "support", "--reason", "x"},
		"missing user":  {"s-1", "--purpose", "support", "--reason", "x"},
		"unknown flag":  {"s-1", "alice", "--silent", "--purpose", "support", "--reason", "x"},
		"dangling flag": {"s-1", "alice", "--purpose"},
	} {
		if _, err := parseSnoop(args); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAttachPathCarriesPurposeAndReason(t *testing.T) {
	p := attachPath(snoopRequest{SessionID: "s 1", User: "alice", RW: true, Purpose: "support", Reason: "ticket 42 & more"})
	if !strings.HasPrefix(p, "/v1/sessions/s%201/attach?") {
		t.Fatalf("path %q", p)
	}
	for _, want := range []string{"mode=rw", "purpose=support", "user=alice", "reason=ticket+42+%26+more"} {
		if !strings.Contains(p, want) {
			t.Errorf("%q lacks %q", p, want)
		}
	}
}

func TestSnoopAgainstServerWithoutAttachRoute(t *testing.T) {
	srv := realServer(t)
	a, _ := testApp(t, srv.URL, namedKey)
	_, _, err := a.c.openAttach(context.Background(), snoopRequest{SessionID: "s1", User: "alice", Purpose: "support", Reason: "x"})
	if !errors.Is(err, errNoAttach) {
		t.Fatalf("want errNoAttach, got %v", err)
	}
}

// fakeAttach upgrades and then runs serve on the raw stream.
func fakeAttach(t *testing.T, serve func(rw *bufio.ReadWriter)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+namedKey || r.Header.Get("Upgrade") != attachProtocol {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + attachProtocol + "\r\n\r\n")
		brw.Flush()
		serve(brw)
		brw.Flush()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func frame(typ byte, p string) []byte {
	b := make([]byte, 5+len(p))
	binary.BigEndian.PutUint32(b[:4], uint32(len(p)))
	b[4] = typ
	copy(b[5:], p)
	return b
}

func attachAndPump(t *testing.T, srv *httptest.Server, rw bool, keys io.Reader) (string, string, error) {
	stop := func() {}
	if s, ok := keys.(*stoppableReader); ok {
		stop = s.stop
	}
	t.Helper()
	a, _ := testApp(t, srv.URL, namedKey)
	conn, br, err := a.c.openAttach(context.Background(), snoopRequest{SessionID: "s1", User: "alice", RW: rw, Purpose: "support", Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var out bytes.Buffer
	reason, err := pump(conn, br, keys, stop, &out, rw)
	return reason, out.String(), err
}

func TestViewModeNeverSendsInput(t *testing.T) {
	got := make(chan []byte, 1)
	srv := fakeAttach(t, func(brw *bufio.ReadWriter) {
		_, _ = brw.Write(frame(frameOut, "hello\r\n"))
		brw.Flush()
		b, _ := io.ReadAll(brw) // everything the client sends until it closes
		got <- b
	})
	reason, out, err := attachAndPump(t, srv, false, strings.NewReader("rm -rf ~\r\x1d"))
	if err != nil || reason != "detached" || out != "hello\r\n" {
		t.Fatalf("reason=%q out=%q err=%v", reason, out, err)
	}
	sent := <-got
	if !bytes.Equal(sent, frame(frameClose, `{"reason":"detach"}`)) {
		t.Fatalf("view mode sent %q; only the detach close is allowed", sent)
	}
}

func TestReadWriteForwardsInputThenDetaches(t *testing.T) {
	got := make(chan []byte, 1)
	srv := fakeAttach(t, func(brw *bufio.ReadWriter) {
		b, _ := io.ReadAll(brw)
		got <- b
	})
	reason, _, err := attachAndPump(t, srv, true, strings.NewReader("ls\r\x1dIGNORED"))
	if err != nil || reason != "detached" {
		t.Fatalf("reason=%q err=%v", reason, err)
	}
	want := append(frame(frameIn, "ls\r"), frame(frameClose, `{"reason":"detach"}`)...)
	if sent := <-got; !bytes.Equal(sent, want) {
		t.Fatalf("sent %q want %q", sent, want)
	}
}

func TestServerCloseEndsAttach(t *testing.T) {
	srv := fakeAttach(t, func(brw *bufio.ReadWriter) {
		_, _ = brw.Write(frame(frameClose, `{"reason":"session ended"}`))
	})
	reason, _, err := attachAndPump(t, srv, false, blockingReader())
	if err != nil || reason != "session ended" {
		t.Fatalf("reason=%q err=%v", reason, err)
	}
}

func TestOversizedAndUnknownFramesFailClosed(t *testing.T) {
	big := make([]byte, 5)
	binary.BigEndian.PutUint32(big[:4], maxFrame+1)
	big[4] = frameOut
	for name, payload := range map[string][]byte{"oversized": big, "unknown type": frame(0x7f, "x")} {
		srv := fakeAttach(t, func(brw *bufio.ReadWriter) {
			_, _ = brw.Write(payload)
			brw.Flush()
			time.Sleep(200 * time.Millisecond)
		})
		if _, _, err := attachAndPump(t, srv, false, blockingReader()); err == nil {
			t.Errorf("%s frame accepted", name)
		}
	}
}

func TestOpenAttachRefusesWrongUpgrade(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, _ := w.(http.Hijacker).Hijack()
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		brw.Flush()
	}))
	defer srv.Close()
	a, _ := testApp(t, srv.URL, namedKey)
	if _, _, err := a.c.openAttach(context.Background(), snoopRequest{SessionID: "s1", User: "a", Purpose: "support", Reason: "x"}); err == nil {
		t.Fatal("wrong upgrade protocol accepted")
	}
}

// stoppableReader blocks like an idle terminal until stop is called, the way
// cancellableStdin's deadline unblocks a real one.
type stoppableReader struct {
	done chan struct{}
	once sync.Once
}

func blockingReader() *stoppableReader { return &stoppableReader{done: make(chan struct{})} }

func (s *stoppableReader) Read([]byte) (int, error) {
	<-s.done
	return 0, os.ErrDeadlineExceeded
}

func (s *stoppableReader) stop() { s.once.Do(func() { close(s.done) }) }

func TestSplitWords(t *testing.T) {
	got, err := splitWords(`snoop s1 alice --reason "ticket 42 \"x\"" --purpose 'support'`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"snoop", "s1", "alice", "--reason", `ticket 42 "x"`, "--purpose", "support"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
	for _, bad := range []string{`a "b`, `a 'b`, `a b\`} {
		if _, err := splitWords(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCompleterOffersCommandsAndLiveValues(t *testing.T) {
	srv := realServer(t)
	a, _ := testApp(t, srv.URL, legacyKey)
	c := &completer{a: a, ctx: context.Background()}
	got, n := c.Do([]rune("sn"), 2)
	if n != 2 || len(got) != 1 || string(got[0]) != "oop " {
		t.Fatalf("got %q n=%d", got, n)
	}
	got, _ = c.Do([]rune("guard "), 6)
	if len(got) != 1 || string(got[0]) != "unban " {
		t.Fatalf("guard completion %q", got)
	}
}
