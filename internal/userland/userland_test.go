package userland

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/userland/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testServer(t *testing.T, authorize func(context.Context, []string) error, record func(context.Context, []string, string) error) *grpc.ClientConn {
	t.Helper()
	// Keep the socket short enough for Darwin's sockaddr_un.
	dir, err := os.MkdirTemp("", "ul-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	worker := filepath.Join(dir, "worker")
	script := `#!/bin/sh
case "$1" in
cat) shift; exec /bin/cat "$@";;
head) printf 'out'; printf 'err' >&2; exit 7;;
grep) if [ -n "$2" ]; then echo $$ > "$2"; fi; exec /bin/sleep 60;;
find) exec /usr/bin/yes output;;
ls) /bin/pwd; printf '%s' "$USERLAND_TEST_SECRET";;
esac
`
	if err := os.WriteFile(worker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if authorize == nil {
		authorize = func(context.Context, []string) error { return nil }
	}
	if record == nil {
		record = func(context.Context, []string, string) error { return nil }
	}
	srv, err := NewServer(Config{Worker: worker, Authorize: authorize, Record: record})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "s")
	listener, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := srv.Serve(listener); err != nil {
			t.Log(err)
		}
	}()
	t.Cleanup(srv.Stop)
	conn, err := Dial(context.Background(), socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	return conn
}
func startFor(args ...string) *pb.Start { return &pb.Start{Argv: args, Directory: "/"} }

func TestStreamRoundTrip(t *testing.T) {
	conn := testServer(t, nil, nil)
	input := strings.Repeat("one\x00two\n", 20000)
	var out, stderr bytes.Buffer
	code, err := Execute(context.Background(), conn, startFor("cat"), strings.NewReader(input), &out, &stderr)
	if err != nil || code != 0 || out.String() != input || stderr.Len() != 0 {
		t.Fatalf("code=%d err=%v output=%d", code, err, out.Len())
	}
}
func TestExitAndSeparateStderr(t *testing.T) {
	conn := testServer(t, nil, nil)
	var out, stderr bytes.Buffer
	code, err := Execute(context.Background(), conn, startFor("head"), nil, &out, &stderr)
	if err != nil || code != 7 || out.String() != "out" || stderr.String() != "err" {
		t.Fatalf("code=%d err=%v out=%q stderr=%q", code, err, &out, &stderr)
	}
}
func TestDaemonDeniesDirectClient(t *testing.T) {
	var started atomic.Bool
	conn := testServer(t, func(context.Context, []string) error { return errors.New("blocked") }, func(context.Context, []string, string) error { started.Store(true); return nil })
	_, err := Execute(context.Background(), conn, startFor("cat"), nil, io.Discard, io.Discard)
	if status.Code(err) != codes.PermissionDenied || started.Load() {
		t.Fatalf("denial=%v started=%v", err, started.Load())
	}
}
func TestAuditFailureStopsWorker(t *testing.T) {
	conn := testServer(t, nil, func(context.Context, []string, string) error { return errors.New("disk full") })
	var out bytes.Buffer
	_, err := Execute(context.Background(), conn, startFor("head"), nil, &out, io.Discard)
	if status.Code(err) != codes.Internal || out.Len() != 0 {
		t.Fatalf("err=%v out=%q", err, &out)
	}
}
func TestCancellationAndEarlyExit(t *testing.T) {
	conn := testServer(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := Execute(ctx, conn, startFor("grep"), nil, io.Discard, io.Discard)
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("deadline: %v", err)
	}
	// An unread stdin pipe must not strand a sender or consume future shell input.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	done := make(chan error, 1)
	go func() {
		_, err := Execute(context.Background(), conn, startFor("head"), r, io.Discard, io.Discard)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("early exit blocked on stdin")
	}
}
func TestRejectMalformedAndOversizedFrames(t *testing.T) {
	conn := testServer(t, nil, nil)
	for _, first := range []*pb.ExecuteRequest{
		{Event: &pb.ExecuteRequest_Stdin{Stdin: []byte("bad")}},
		{Event: &pb.ExecuteRequest_Start{Start: startFor("/bin/sh")}},
		{Event: &pb.ExecuteRequest_Start{Start: startFor("cat", strings.Repeat("x", ChunkSize))}},
		{Event: &pb.ExecuteRequest_Start{Start: startFor("cat", "a\x00b")}},
	} {
		stream, err := pb.NewUserlandClient(conn).Execute(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(first); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("malformed accepted: %v", err)
		}
	}
	stream, err := pb.NewUserlandClient(conn).Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.ExecuteRequest{Event: &pb.ExecuteRequest_Start{Start: startFor("cat")}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.ExecuteRequest{Event: &pb.ExecuteRequest_Stdin{Stdin: make([]byte, ChunkSize+1)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversized stdin accepted: %v", err)
	}
}
func TestOutputLimit(t *testing.T) {
	conn := testServer(t, nil, nil)
	_, err := Execute(context.Background(), conn, startFor("find"), nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("unbounded output accepted")
	}
}
func TestDirectoryAndEnvironmentIsolation(t *testing.T) {
	t.Setenv("USERLAND_TEST_SECRET", "must-not-leak")
	conn := testServer(t, nil, nil)
	for _, dir := range []string{"/", "/tmp"} {
		var out bytes.Buffer
		req := startFor("ls")
		req.Directory = dir
		code, err := Execute(context.Background(), conn, req, nil, &out, io.Discard)
		expected, evalErr := filepath.EvalSymlinks(dir)
		if evalErr != nil {
			t.Fatal(evalErr)
		}
		actual, evalErr := filepath.EvalSymlinks(strings.TrimSpace(out.String()))
		if evalErr != nil {
			t.Fatal(evalErr)
		}
		if err != nil || code != 0 || actual != expected {
			t.Fatalf("dir=%s code=%d err=%v out=%q", dir, code, err, &out)
		}
	}
}
func TestSocketGuards(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(dir, "s")); err == nil {
		t.Fatal("public directory accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("existing file replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatal("existing path changed")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if verifyPeer(a) == nil {
		t.Fatal("non-Unix peer accepted")
	}
}
func TestRequireAuthorizationAndAudit(t *testing.T) {
	if _, err := NewServer(Config{Worker: "/bin/cat"}); err == nil {
		t.Fatal("missing gates accepted")
	}
}

func TestCancellationReapsWorker(t *testing.T) {
	conn := testServer(t, nil, nil)
	pidPath := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Execute(ctx, conn, startFor("grep", pidPath), nil, io.Discard, io.Discard)
		done <- err
	}()
	var pid int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidPath)
		if err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
			if pid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("worker did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel blocked")
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("worker survived cancellation")
}
