package repl

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"mvdan.cc/sh/v3/interp"
)

// ptyExecHandler returns the innermost ExecHandlers middleware. It runs an
// already-authorized foreground external command on a real pseudo-terminal so
// the child sees a genuine TTY (isatty(1) true, TIOCGWINSZ works, raw mode can
// be set) — which full-screen apps such as vim, top, htop and less require.
// The child's output is copied to topStdout (the session OutputBroadcaster), so
// session recordings and any AddListener sinks still capture everything: no new
// output sink is introduced.
//
// It is installed AFTER security.BashInterceptorSession in the chain, so it only
// ever runs for commands that the security interceptor already authorized and
// then dispatched to the real OS exec (its final `next(ctx, args)`); builtins,
// virtual binaries and custom Starlark commands are handled earlier and never
// reach here. The authorization / audit chokepoint itself is the call handler
// (security.CallInterceptorSession), which fires before ANY exec handler — so
// adding this middleware changes only HOW an approved command runs, never
// whether it is allowed.
//
// The PTY is engaged ONLY for the interactive local foreground case; every
// other case falls through to next (today's non-PTY behavior):
//   - tty must be a real terminal (adssh's own controlling terminal),
//   - this command's stdout/stdin must be the session's own top-level streams —
//     not a pipeline stage and not a file redirect (mvdan swaps r.stdout /
//     r.stdin to pipes or files in those cases, so identity comparison against
//     topStdout / topStdin detects them),
//
// which also excludes SSH sessions and scripts, because there tty is nil.
func ptyExecHandler(tty *os.File, topStdin io.Reader, topStdout, topStderr io.Writer) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}
			hc := interp.HandlerCtx(ctx)
			if !ptyEligible(tty, topStdin, topStdout, hc) {
				return next(ctx, args)
			}
			ran, err := runOnPTY(ctx, args, tty, topStdout, topStderr, hc)
			if !ran {
				// Fail safe: the PTY could not be set up and NO child was
				// started, so fall back to the standard exec path rather than
				// dropping the command. runOnPTY restores the terminal before
				// returning in this case.
				return next(ctx, args)
			}
			return err
		}
	}
}

// ptyEligible reports whether args should run on a PTY: adssh owns a real
// terminal and this command's stdout/stdin are the session's own top-level
// streams (so it is a genuine foreground command, not a pipeline stage or a
// redirect target).
func ptyEligible(tty *os.File, topStdin io.Reader, topStdout io.Writer, hc interp.HandlerContext) bool {
	if tty == nil {
		return false
	}
	if !term.IsTerminal(int(tty.Fd())) {
		return false
	}
	// Top-level, un-redirected stdout: mvdan sets hc.Stdout to a pipe (pipeline)
	// or a file (redirect) otherwise, so identity against topStdout holds only
	// for a plain foreground command.
	if hc.Stdout != topStdout {
		return false
	}
	// Top-level stdin: the trailing stage of a pipeline (a | b) keeps r.stdout
	// but has r.stdin swapped to the pipe, so this also rejects `b` in `a | b`
	// and any `cmd < file` redirect.
	if hc.Stdin != topStdin {
		return false
	}
	return true
}

// runOnPTY executes args on a fresh PTY. It returns ran=true once the child has
// been started (the caller must NOT fall back in that case, to avoid running the
// command twice) and the child's exit status as err (an interp exit-status error
// for a non-zero exit). It returns ran=false only when nothing was started and
// the terminal is left as it was found, so the caller can fall back safely.
func runOnPTY(ctx context.Context, args []string, tty *os.File, out, topStderr io.Writer, hc interp.HandlerContext) (bool, error) {
	path, lookErr := interp.LookPathDir(hc.Dir, hc.Env, args[0])
	if lookErr != nil {
		// Match the default handler: report and return 127 without falling back.
		if hc.Stderr != nil {
			_, _ = io.WriteString(hc.Stderr, lookErr.Error()+"\n")
		}
		return true, interp.ExitStatus(127)
	}

	// CommandContext kills the child when the runner's context ends (timeout,
	// session teardown), as the default exec handler does.
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Args = args
	cmd.Dir = hc.Dir
	// pty.Start attaches only the std streams left nil. Keep a redirected
	// stderr (2>file, 2>/dev/null) off the terminal and out of the session
	// recording; stderr that is the session's own stream, or 2>&1 onto it,
	// stays on the PTY.
	if hc.Stderr != nil && hc.Stderr != topStderr && hc.Stderr != out {
		cmd.Stderr = hc.Stderr
	}
	cmd.Env = security.ChildEnviron(hc.Env)
	if err := sys.PrepareChild(cmd, security.SessionFromEnv(hc.Env)); err != nil {
		if hc.Stderr != nil {
			fmt.Fprintf(hc.Stderr, "%v\n", err)
		}
		return true, err
	}

	// Put the real terminal in raw mode BEFORE starting the child so the very
	// first keystrokes pass through untouched. Doing this first also means a
	// raw-mode failure leaves nothing started and lets the caller fall back.
	oldState, rawErr := term.MakeRaw(int(tty.Fd()))
	if rawErr != nil {
		return false, nil
	}
	restoreOnce := sync.Once{}
	restore := func() { restoreOnce.Do(func() { _ = term.Restore(int(tty.Fd()), oldState) }) }

	ptmx, startErr := pty.Start(cmd)
	if startErr != nil {
		// No child running: restore the terminal and let the caller fall back.
		restore()
		return false, nil
	}
	// A poller-owned master lets Close release the output copier and the
	// input pump even while a background grandchild holds the slave open.
	// If the copy fails, keep the blocking master: the child is running.
	if pollable, err := sys.PollablePTY(ptmx); err == nil {
		ptmx = pollable
	}
	defer restore()
	defer func() { _ = ptmx.Close() }()

	// Match the child PTY size to the real terminal and keep it in sync while
	// the command runs. syncPTYSize never calls ptmx.Fd, which would put the
	// master back into blocking mode. signal.Stop does not close winch, so the goroutine needs its own quit.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	winchQuit := make(chan struct{})
	winchDone := make(chan struct{})
	go func() {
		defer close(winchDone)
		for {
			select {
			case <-winch:
				_ = syncPTYSize(tty, ptmx)
			case <-winchQuit:
				return
			}
		}
	}()
	winch <- syscall.SIGWINCH // set the initial size

	// Pump the real terminal into the child and the child's output into the
	// session broadcaster (so recordings still capture it). The input pump is
	// stopped and joined before returning: a reader left blocked on the real
	// terminal would swallow the operator's next line.
	var stopInput atomic.Bool
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		pumpTerminalInput(tty, ptmx, &stopInput)
	}()
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(out, ptmx)
		close(copyDone)
	}()

	waitErr := cmd.Wait()

	stopInput.Store(true)
	signal.Stop(winch)
	close(winchQuit)
	<-winchDone
	// Give the copier a bounded time to drain what the child wrote. A
	// grandchild that keeps the slave open (sh -c 'sleep 600 & exit') would
	// otherwise hold the prompt. Closing the pollable master then unblocks the
	// output copy and a pump write to a child that no longer reads.
	select {
	case <-copyDone:
	case <-time.After(ptyDrainTimeout):
	}
	_ = ptmx.Close()
	<-copyDone
	<-inputDone

	restore()
	return true, exitStatusFromWait(waitErr)
}

// ptyDrainTimeout bounds how long runOnPTY waits for child output after the
// child exits before it closes the master.
const ptyDrainTimeout = 200 * time.Millisecond

// syncPTYSize copies the real terminal's window size onto the pty master
// through SyscallConn. pty.InheritSize calls ptmx.Fd, which puts a pollable
// master back into blocking mode so Close no longer unblocks a Read.
func syncPTYSize(tty, ptmx *os.File) error {
	ws, err := pty.GetsizeFull(tty)
	if err != nil {
		return err
	}
	return sys.SetPTYSize(ptmx, ws)
}

// pumpTerminalInput copies the real terminal into dst until stop is raised.
// It never blocks in read(2): it polls with a short timeout and reads only when
// input is ready and stop is still clear, so once stop is set no further byte
// is taken from the terminal. The Go poller cannot watch a tty on macOS
// (deadlines return ErrNoDeadline), hence unix.Poll on the raw descriptor.
func pumpTerminalInput(tty *os.File, dst io.Writer, stop *atomic.Bool) {
	fd := int(tty.Fd())
	buf := make([]byte, 4096)
	for !stop.Load() {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 50)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return
		}
		if n == 0 || stop.Load() {
			continue
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return
			}
			continue
		}
		r, err := unix.Read(fd, buf)
		if r > 0 {
			if _, werr := dst.Write(buf[:r]); werr != nil {
				return
			}
		}
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil || r == 0 {
			return
		}
	}
}

// exitStatusFromWait converts an *exec.Cmd.Wait error into the interp exit
// status the Runner expects: nil for success, a signal-encoded 128+n status for
// signaled children, and the plain exit code otherwise.
func exitStatusFromWait(waitErr error) error {
	if waitErr == nil {
		return nil
	}
	exitErr, ok := waitErr.(*exec.ExitError)
	if !ok {
		return waitErr
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return interp.ExitStatus(uint8(128 + int(status.Signal())))
	}
	code := exitErr.ExitCode()
	if code < 0 {
		code = 1
	}
	return interp.ExitStatus(uint8(code))
}
