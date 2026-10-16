package repl

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"

	"github.com/creack/pty"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// openRealTerminal returns a slave PTY file that stands in for adssh's own
// controlling terminal in tests. The paired master is closed at cleanup.
func openRealTerminal(t *testing.T) *os.File {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty.Open unavailable in this environment: %v", err)
	}
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})
	return slave
}

// runForeground builds a runner with StdIO(in=tty, out, err) and the PTY handler,
// then runs src. tty doubles as the session's real terminal and top-level stdin.
func runForeground(t *testing.T, tty *os.File, src string, stdout *sys.OutputBroadcaster) error {
	t.Helper()
	errOut := &bytes.Buffer{}
	r, err := interp.New(
		interp.Env(expand.ListEnviron(os.Environ()...)),
		interp.StdIO(tty, stdout, errOut),
		interp.ExecHandlers(ptyExecHandler(tty, tty, stdout, errOut)),
	)
	if err != nil {
		t.Fatalf("interp.New: %v", err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(src), "test.sh")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return r.Run(context.Background(), file)
}

// TestForegroundCommandSeesTTYAndRecordingPreserved covers acceptance items 1
// and 2: an external foreground command runs on a real PTY (so isatty(1) is
// true) and the same output is still captured by a recording listener added to
// the broadcaster.
func TestForegroundCommandSeesTTYAndRecordingPreserved(t *testing.T) {
	tty := openRealTerminal(t)

	primary := &bytes.Buffer{}
	broadcaster := sys.NewOutputBroadcaster(primary)
	recording := &bytes.Buffer{}
	broadcaster.AddListener(recording)

	if err := runForeground(t, tty, `sh -c 'test -t 1 && echo IS_TTY || echo NO_TTY'`, broadcaster); err != nil {
		t.Fatalf("run: %v", err)
	}

	if got := primary.String(); !strings.Contains(got, "IS_TTY") {
		t.Errorf("foreground command did not see a TTY on stdout: primary output %q", got)
	}
	if got := recording.String(); !strings.Contains(got, "IS_TTY") {
		t.Errorf("recording listener did not capture PTY output: got %q", got)
	}
}

// TestPipelineIsNotPTYWrapped covers acceptance item 3: a pipeline still
// produces correct output and its trailing stage is NOT pty-wrapped (its stdin
// is the pipe, so ptyEligible is false and it uses the standard exec path).
func TestPipelineIsNotPTYWrapped(t *testing.T) {
	tty := openRealTerminal(t)

	primary := &bytes.Buffer{}
	broadcaster := sys.NewOutputBroadcaster(primary)

	// `cat` reproduces the piped input ("x"); the probe reports whether the
	// trailing stage's stdout is a real terminal. It must not be, because the
	// stage is not pty-wrapped inside a pipeline.
	if err := runForeground(t, tty, `printf x | sh -c 'cat; test -t 1 && echo R_TTY || echo R_NOTTY'`, broadcaster); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := primary.String()
	if !strings.Contains(got, "x") {
		t.Errorf("pipeline produced wrong output: %q", got)
	}
	if !strings.Contains(got, "R_NOTTY") {
		t.Errorf("pipeline stage was pty-wrapped (stdout reported as tty): %q", got)
	}
}

// TestNonTTYInvocationKeepsBehavior covers acceptance item 4: with no
// controlling terminal (tty == nil) the handler is a passthrough, so the child's
// stdout is NOT a tty and the command still runs.
func TestNonTTYInvocationKeepsBehavior(t *testing.T) {
	primary := &bytes.Buffer{}
	broadcaster := sys.NewOutputBroadcaster(primary)

	r, err := interp.New(
		interp.Env(expand.ListEnviron(os.Environ()...)),
		interp.StdIO(strings.NewReader(""), broadcaster, &bytes.Buffer{}),
		interp.ExecHandlers(ptyExecHandler(nil, strings.NewReader(""), broadcaster, nil)),
	)
	if err != nil {
		t.Fatalf("interp.New: %v", err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(`sh -c 'test -t 1 && echo IS_TTY || echo NO_TTY'`), "test.sh")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := r.Run(context.Background(), file); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := primary.String(); !strings.Contains(got, "NO_TTY") {
		t.Errorf("non-tty invocation should not see a tty on stdout, got %q", got)
	}
}

// TestTerminalRestoredAfterCommand covers acceptance item 5: the real terminal's
// attributes are identical before and after a PTY-backed command runs.
func TestTerminalRestoredAfterCommand(t *testing.T) {
	tty := openRealTerminal(t)

	before, err := sys.SaveTermios(int(tty.Fd()))
	if err != nil {
		t.Skipf("cannot read termios in this environment: %v", err)
	}

	primary := &bytes.Buffer{}
	broadcaster := sys.NewOutputBroadcaster(primary)
	if err := runForeground(t, tty, `sh -c 'echo hello'`, broadcaster); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Give any late restore a beat (restore is synchronous before return, but be
	// defensive against scheduler races on the copy goroutine).
	time.Sleep(20 * time.Millisecond)

	after, err := sys.SaveTermios(int(tty.Fd()))
	if err != nil {
		t.Fatalf("read termios after run: %v", err)
	}
	if !reflect.DeepEqual(*before, *after) {
		t.Errorf("terminal not restored to its pre-run state:\n before=%+v\n after =%+v", *before, *after)
	}
}

// TestTerminalInputAfterExitReachesNextReader: once a PTY-backed command has
// exited, no forwarding goroutine may still be reading the real terminal, so
// the first line typed afterwards reaches the next reader intact.
func TestTerminalInputAfterExitReachesNextReader(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty.Open unavailable in this environment: %v", err)
	}
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})

	broadcaster := sys.NewOutputBroadcaster(&bytes.Buffer{})
	// Warm-up run: signal.Notify starts os/signal's process-lifetime goroutine
	// once; it must not count as a leak.
	if err := runForeground(t, slave, `sh -c :`, broadcaster); err != nil {
		t.Fatalf("warm-up run: %v", err)
	}
	baseline := runtime.NumGoroutine()
	for i := 0; i < 3; i++ {
		if err := runForeground(t, slave, `sh -c :`, broadcaster); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline {
		t.Errorf("goroutines leaked: baseline=%d now=%d", baseline, n)
	}

	if _, err := master.Write([]byte("after-exit\nsecond-line\n")); err != nil {
		t.Fatalf("write to terminal: %v", err)
	}
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := slave.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case line := <-got:
		if line != "after-exit\n" {
			t.Fatalf("first read after exit = %q, want %q (an abandoned reader consumed input)", line, "after-exit\n")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading the terminal after the command exited")
	}
}

// TestStderrRedirectBypassesPTY: `2>file` lands in the file, never on the
// terminal or in the session recording.
func TestStderrRedirectBypassesPTY(t *testing.T) {
	tty := openRealTerminal(t)
	primary := &bytes.Buffer{}
	broadcaster := sys.NewOutputBroadcaster(primary)
	errFile := filepath.Join(t.TempDir(), "errors.log")

	if err := runForeground(t, tty, `sh -c 'echo SECRET >&2; echo OUT' 2>`+errFile, broadcaster); err != nil {
		t.Fatalf("run: %v", err)
	}
	data, err := os.ReadFile(errFile)
	if err != nil {
		t.Fatalf("read redirect target: %v", err)
	}
	if !strings.Contains(string(data), "SECRET") {
		t.Errorf("redirected stderr missing from file: %q", data)
	}
	if got := primary.String(); strings.Contains(got, "SECRET") || !strings.Contains(got, "OUT") {
		t.Errorf("broadcaster output = %q, want OUT without SECRET", got)
	}
}

// TestStderrToStdoutAndPlainStderrReachBroadcaster: `2>&1` and un-redirected
// stderr still reach the session output.
func TestStderrToStdoutAndPlainStderrReachBroadcaster(t *testing.T) {
	for _, src := range []string{`sh -c 'echo SECRET >&2' 2>&1`, `sh -c 'echo SECRET >&2'`} {
		tty := openRealTerminal(t)
		primary := &bytes.Buffer{}
		broadcaster := sys.NewOutputBroadcaster(primary)
		if err := runForeground(t, tty, src, broadcaster); err != nil {
			t.Fatalf("%s: run: %v", src, err)
		}
		if got := primary.String(); !strings.Contains(got, "SECRET") {
			t.Errorf("%s: stderr did not reach the broadcaster: %q", src, got)
		}
	}
}

// TestPTYCommandHonorsContextCancel: a PTY-backed child is killed when the
// runner's context ends instead of running to completion.
func TestPTYCommandHonorsContextCancel(t *testing.T) {
	tty := openRealTerminal(t)
	broadcaster := sys.NewOutputBroadcaster(&bytes.Buffer{})
	errOut := &bytes.Buffer{}
	r, err := interp.New(
		interp.Env(expand.ListEnviron(os.Environ()...)),
		interp.StdIO(tty, broadcaster, errOut),
		interp.ExecHandlers(ptyExecHandler(tty, tty, broadcaster, errOut)),
	)
	if err != nil {
		t.Fatalf("interp.New: %v", err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(`sleep 3`), "test.sh")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_ = r.Run(ctx, file)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("child ignored context cancellation: ran %v", elapsed)
	}
}

// TestPTYBackgroundGrandchildDoesNotHangPrompt: a grandchild that keeps the
// slave open must not hold the prompt after the command exits.
func TestPTYBackgroundGrandchildDoesNotHangPrompt(t *testing.T) {
	tty := openRealTerminal(t)
	broadcaster := sys.NewOutputBroadcaster(&bytes.Buffer{})
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- runForeground(t, tty, `sh -c 'sleep 5 & exit'`, broadcaster) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("prompt returned after %v, want under 1s", elapsed)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("prompt did not return while a background grandchild held the PTY")
	}
}

// TestPTYMasterCloseUnblocksReaderWhileSlaveHeld: with the slave held open
// (as a background grandchild would), closing the master after a resize must
// release the output copier.
func TestPTYMasterCloseUnblocksReaderWhileSlaveHeld(t *testing.T) {
	tty := openRealTerminal(t)
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty.Open unavailable in this environment: %v", err)
	}
	defer func() { _ = slave.Close() }()
	ptmx, err := sys.PollablePTY(master)
	if err != nil {
		t.Fatal(err)
	}
	if err := syncPTYSize(tty, ptmx); err != nil {
		t.Fatal(err)
	}
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
		close(copyDone)
	}()
	time.Sleep(50 * time.Millisecond)
	// A resize while the copier is blocked must not make Close wait on it.
	if err := syncPTYSize(tty, ptmx); err != nil {
		t.Fatal(err)
	}
	_ = ptmx.Close()
	select {
	case <-copyDone:
	case <-time.After(time.Second):
		t.Fatal("closing the master did not release the output copier")
	}
}
