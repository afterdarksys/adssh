package sys

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// JobStatus describes the lifecycle state of a tracked job.
type JobStatus string

const (
	JobRunning  JobStatus = "running"
	JobStopped  JobStatus = "stopped"
	JobDone     JobStatus = "done"
)

// Job holds metadata for a single background/foreground job.
type Job struct {
	ID     int
	Cmd    *exec.Cmd
	Status JobStatus
	PID    int
	PGID   int
	Args   []string // human-readable command args for display
}

// JobTable is a mutex-protected table of active jobs.
type JobTable struct {
	mu     sync.Mutex
	jobs   map[int]*Job
	nextID int
}

// globalJobTable is the process-wide singleton.
var globalJobTable = &JobTable{
	jobs:   make(map[int]*Job),
	nextID: 1,
}

// GlobalJobTable returns the singleton job table.
func GlobalJobTable() *JobTable {
	return globalJobTable
}

// NewJob sets up cmd for a new process group (Setpgid), starts it, and
// registers it in the job table.  Returns the assigned job ID.
func NewJob(cmd *exec.Cmd) (int, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("job: start: %w", err)
	}

	pgid := cmd.Process.Pid // after Setpgid the PGID equals the PID of the child
	// Retrieve the actual pgid set by the kernel.
	if pg, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		pgid = pg
	}

	t := globalJobTable
	t.mu.Lock()
	id := t.nextID
	t.nextID++
	j := &Job{
		ID:     id,
		Cmd:    cmd,
		Status: JobRunning,
		PID:    cmd.Process.Pid,
		PGID:   pgid,
		Args:   cmd.Args,
	}
	t.jobs[id] = j
	t.mu.Unlock()

	// Reap the process in the background and mark it done when it exits.
	go func() {
		cmd.Wait() //nolint:errcheck
		t.mu.Lock()
		if jj, ok := t.jobs[id]; ok {
			jj.Status = JobDone
		}
		t.mu.Unlock()
	}()

	return id, nil
}

// Jobs returns a snapshot of all tracked jobs.
func Jobs() []Job {
	t := globalJobTable
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]Job, 0, len(t.jobs))
	for _, j := range t.jobs {
		out = append(out, *j)
	}
	return out
}

// FgJob brings job id to the foreground: gives it the terminal and sends SIGCONT.
func FgJob(id int) error {
	t := globalJobTable
	t.mu.Lock()
	j, ok := t.jobs[id]
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("fg: no such job: %d", id)
	}
	if j.Status == JobDone {
		return fmt.Errorf("fg: job %d has already finished", id)
	}

	// Give the terminal to the job's process group.
	if err := SetForegroundProcessGroup(j.PGID); err != nil {
		// Non-fatal — we may not have a controlling terminal (e.g. SSH).
		fmt.Fprintf(os.Stderr, "fg: tcsetpgrp: %v\n", err)
	}

	// Resume if it was stopped.
	if err := syscall.Kill(-j.PGID, syscall.SIGCONT); err != nil {
		return fmt.Errorf("fg: SIGCONT: %w", err)
	}

	t.mu.Lock()
	j.Status = JobRunning
	t.mu.Unlock()

	// Wait for the child to stop or exit, then reclaim the terminal.
	_ = j.Cmd.Wait()

	// Reclaim the terminal for the shell.
	shellPGID := syscall.Getpgrp()
	_ = SetForegroundProcessGroup(shellPGID)

	t.mu.Lock()
	if jj, ok := t.jobs[id]; ok {
		jj.Status = JobDone
	}
	t.mu.Unlock()

	return nil
}

// BgJob resumes a stopped job in the background (sends SIGCONT to its PGID).
func BgJob(id int) error {
	t := globalJobTable
	t.mu.Lock()
	j, ok := t.jobs[id]
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("bg: no such job: %d", id)
	}
	if j.Status == JobDone {
		return fmt.Errorf("bg: job %d has already finished", id)
	}

	if err := syscall.Kill(-j.PGID, syscall.SIGCONT); err != nil {
		return fmt.Errorf("bg: SIGCONT: %w", err)
	}

	t.mu.Lock()
	j.Status = JobRunning
	t.mu.Unlock()

	return nil
}

// WaitJob blocks until job id finishes.  If id is 0, wait for all jobs.
func WaitJob(id int) error {
	t := globalJobTable
	if id == 0 {
		// Wait for all running jobs.
		t.mu.Lock()
		ids := make([]int, 0, len(t.jobs))
		for jid := range t.jobs {
			ids = append(ids, jid)
		}
		t.mu.Unlock()

		for _, jid := range ids {
			_ = WaitJob(jid)
		}
		return nil
	}

	t.mu.Lock()
	j, ok := t.jobs[id]
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("wait: no such job: %d", id)
	}
	if j.Status == JobDone {
		return nil
	}

	j.Cmd.Wait() //nolint:errcheck

	t.mu.Lock()
	if jj, ok := t.jobs[id]; ok {
		jj.Status = JobDone
	}
	t.mu.Unlock()

	return nil
}

// Disown removes job id from the job table so it is no longer tracked.
func (t *JobTable) Disown(id int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.jobs, id)
}

// DisownAll removes all jobs from the job table.
func (t *JobTable) DisownAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id := range t.jobs {
		delete(t.jobs, id)
	}
}

// SetForegroundProcessGroup sets the terminal's foreground process group to pgid.
// This is critical for true POSIX job control on FreeBSD/Solaris/Linux.
func SetForegroundProcessGroup(pgid int) error {
	// We need to ignore SIGTTOU while we change the terminal process group
	// Otherwise, our shell will get suspended!
	// Currently handled safely by go os/signal for our own process, but we must make the ioctl.

	fd := int(os.Stdin.Fd())

	// Ensure we are actually attached to a terminal
	if _, err := unix.IoctlGetTermios(fd, unix.TIOCGETA); err != nil {
		// Not a terminal, silently skip job control
		return nil
	}

	err := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pgid)
	if err != nil {
		return fmt.Errorf("failed to tcsetpgrp: %v", err)
	}
	return nil
}

// GetForegroundProcessGroup returns the current foreground process group of the terminal.
func GetForegroundProcessGroup() (int, error) {
	fd := int(os.Stdin.Fd())
	pgid, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		return -1, fmt.Errorf("failed to tcgetpgrp: %v", err)
	}
	return pgid, nil
}
