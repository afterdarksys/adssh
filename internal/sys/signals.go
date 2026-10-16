// Threats: a process-wide SIGCHLD reaper (wait4(-1)) steals exit statuses
// from every exec.Cmd in the binary (foreground commands, the PTY path, SSH
// login children, sys.exec_cmd), so their owners see "wait: no child
// processes" instead of the real exit code or signal.  Ownership rule: each
// child pid has exactly one waiter, its exec.Cmd.  Nothing here waits on any
// pid, and no handler may call wait4(-1).
//
// Interrupt: SIGINT and SIGQUIT are caught into a drained channel, not
// ignored. execve resets a caught signal to the default but keeps an
// ignored one, so ignoring them here would make every command the shell
// runs (the plain exec path, the PTY path, SessionExecHandler, SSH session
// commands) survive Ctrl-C and Ctrl-\. The shell itself still survives
// both. SIGTSTP, SIGTTIN, and SIGTTOU stay ignored: the shell must be able
// to call tcsetpgrp from the background, and the REPL catches SIGTSTP
// itself; the --session-child wrapper resets them for wrapped commands.
//
// Hangup: by default SIGHUP is sent on to the shell's own process group and
// the shell exits. mvdan runs a `&` command in that group, and adssh keeps no
// job table, so the group is how a background command learns of the hangup.
// The shell ignores SIGHUP before it signals the group, so it does not
// re-enter the handler. The group is signaled only when the shell leads it:
// a shell started without its own group (a script, a test harness) shares
// the group with whoever started it, and must not hang that up. A process
// that installs OnHangup (the SSH listener) runs that hook instead and keeps
// running, so a hangup of the listener's terminal does not kill every SSH
// session.
// Not covered: SIGTSTP/SIGTTIN/SIGTTOU in a command that is not wrapped
// (every session limit zero) stay ignored.

package sys

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var (
	hangupMu   sync.Mutex
	hangupHook func()
	// exitProcess is os.Exit; tests replace it.
	exitProcess = os.Exit
	// killGroup signals process group pgid; tests replace it.
	killGroup = func(pgid int, sig syscall.Signal) error { return syscall.Kill(-pgid, sig) }
)

// OnHangup replaces the default SIGHUP action (hang up the process group, exit) with
// fn. A nil fn restores the default.
func OnHangup(fn func()) {
	hangupMu.Lock()
	hangupHook = fn
	hangupMu.Unlock()
}

func handleHangup() {
	hangupMu.Lock()
	fn := hangupHook
	hangupMu.Unlock()
	if fn != nil {
		fn()
		return
	}
	hangupProcessGroup()
	exitProcess(0)
}

// SetupSignals initializes the signal handlers for the shell.
func SetupSignals() {
	// Caught, not ignored: see the Interrupt note above. The channel is
	// drained so the runtime never blocks on it.
	intCh := make(chan os.Signal, 8)
	signal.Notify(intCh, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		for range intCh {
		}
	}()
	signal.Ignore(syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)

	// SIGCHLD is deliberately not handled: children are reaped only by their
	// owners (see the Threats note above).

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for range hupCh {
			handleHangup()
		}
	}()
}

// hangupProcessGroup sends SIGHUP to the shell's process group, minus the
// shell itself, when the shell leads that group.
func hangupProcessGroup() {
	pgid := syscall.Getpgrp()
	if pgid != os.Getpid() {
		return
	}
	signal.Ignore(syscall.SIGHUP)
	_ = killGroup(pgid, syscall.SIGHUP)
}
