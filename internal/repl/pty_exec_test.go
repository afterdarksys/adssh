package repl

import (
	"bytes"
	"context"
	"os"
	"reflect"
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
	r, err := interp.New(
		interp.Env(expand.ListEnviron(os.Environ()...)),
		interp.StdIO(tty, stdout, &bytes.Buffer{}),
		interp.ExecHandlers(ptyExecHandler(tty, tty, stdout)),
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
		interp.ExecHandlers(ptyExecHandler(nil, strings.NewReader(""), broadcaster)),
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
