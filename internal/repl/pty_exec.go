package repl

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"

	"github.com/creack/pty"
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
func ptyExecHandler(tty *os.File, topStdin io.Reader, topStdout io.Writer) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}
			hc := interp.HandlerCtx(ctx)
			if !ptyEligible(tty, topStdin, topStdout, hc) {
				return next(ctx, args)
			}
			ran, err := runOnPTY(ctx, args, tty, topStdout, hc)
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
func runOnPTY(ctx context.Context, args []string, tty *os.File, out io.Writer, hc interp.HandlerContext) (bool, error) {
	path, lookErr := interp.LookPathDir(hc.Dir, hc.Env, args[0])
	if lookErr != nil {
		// Match the default handler: report and return 127 without falling back.
		if hc.Stderr != nil {
			_, _ = io.WriteString(hc.Stderr, lookErr.Error()+"\n")
		}
		return true, interp.NewExitStatus(127)
	}

	cmd := exec.Command(path, args...)
	cmd.Args = args
	cmd.Dir = hc.Dir
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
	defer restore()
	defer func() { _ = ptmx.Close() }()

	// Match the child PTY size to the real terminal and keep it in sync while
	// the command runs. pty.InheritSize copies the size of its first argument
	// onto its second, so this reads the real tty and applies it to the master.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for range winch {
			_ = pty.InheritSize(tty, ptmx)
		}
	}()
	winch <- syscall.SIGWINCH // set the initial size

	// Pump the real terminal into the child and the child's output into the
	// session broadcaster (so recordings still capture it). The stdin copy is
	// detached: it blocks on the real terminal read and must not hold up the
	// child's exit.
	go func() { _, _ = io.Copy(ptmx, tty) }()
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(out, ptmx)
		close(copyDone)
	}()

	waitErr := cmd.Wait()

	// Drain any output the child produced right before exiting. Closing ptmx
	// (deferred) unblocks the copy goroutine; wait briefly for it to flush.
	_ = ptmx.Close()
	<-copyDone

	restore()
	return true, exitStatusFromWait(waitErr)
}

// exitStatusFromWait converts an *exec.Cmd.Wait error into the interp exit
// status the Runner expects: nil for success, a signal-encoded 128+n status for
// signalled children, and the plain exit code otherwise.
func exitStatusFromWait(waitErr error) error {
	if waitErr == nil {
		return nil
	}
	exitErr, ok := waitErr.(*exec.ExitError)
	if !ok {
		return waitErr
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return interp.NewExitStatus(uint8(128 + int(status.Signal())))
	}
	code := exitErr.ExitCode()
	if code < 0 {
		code = 1
	}
	return interp.NewExitStatus(uint8(code))
}
