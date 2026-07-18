package sys

import (
	"os"
	"os/signal"
	"syscall"
)

// SetupSignals initializes the signal handlers for the shell.
func SetupSignals() {
	// Ignore these signals so the shell doesn't exit when you press Ctrl+C or Ctrl+\
	// The child process will receive them if it's the foreground process group.
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)

	// SIGCHLD: reap zombie children and update job table status.
	chldCh := make(chan os.Signal, 16)
	signal.Notify(chldCh, syscall.SIGCHLD)
	go func() {
		for range chldCh {
			reapChildren()
		}
	}()

	// SIGHUP: propagate to all child process groups and then exit.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for range hupCh {
			propagateHUP()
			os.Exit(0)
		}
	}()
}

// reapChildren calls waitpid in a loop to collect any zombie children and
// updates the job table accordingly.
func reapChildren() {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG|syscall.WUNTRACED, nil)
		if err != nil || pid <= 0 {
			break
		}

		t := globalJobTable
		t.mu.Lock()
		for _, j := range t.jobs {
			if j.PID == pid {
				if ws.Stopped() {
					j.Status = JobStopped
				} else if ws.Exited() || ws.Signaled() {
					j.Status = JobDone
				}
				break
			}
		}
		t.mu.Unlock()
	}
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
