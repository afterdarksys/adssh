// Threats: a process-wide SIGCHLD reaper (wait4(-1)) steals exit statuses
// from every exec.Cmd in the binary (foreground commands, the PTY path, SSH
// login children, sys.exec_cmd), so their owners see "wait: no child
// processes" instead of the real exit code or signal.  Ownership rule: each
// child pid has exactly one waiter.  The job table owns only the pids it
// started (NewJob), and waits on each of those by pid from a single owner
// goroutine.  Every other child is owned by its exec.Cmd.  Nothing here waits
// on any pid, and no handler may call wait4(-1).
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
// Hangup: by default SIGHUP sends SIGHUP to the shell's jobs and exits. A
// process that installs OnHangup (the SSH listener) runs that hook instead
// and keeps running, so a hangup of the listener's terminal does not kill
// every SSH session.
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
)

// OnHangup replaces the default SIGHUP action (propagate to jobs, exit) with
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
	propagateHUP()
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

// propagateHUP sends SIGHUP to every active child process group.
func propagateHUP() {
	t := globalJobTable
	t.mu.Lock()
	pids := make([]int, 0, len(t.jobs))
	for _, j := range t.jobs {
		if j.Status != JobDone {
			pids = append(pids, j.PGID)
		}
	}
	t.mu.Unlock()

	for _, pgid := range pids {
		_ = syscall.Kill(-pgid, syscall.SIGHUP)
	}
}
