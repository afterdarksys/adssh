package sys

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// JobStatus describes the lifecycle state of a tracked job.
type JobStatus string

const (
	JobRunning JobStatus = "running"
	JobStopped JobStatus = "stopped"
	JobDone    JobStatus = "done"
)

// Job holds metadata for a single background/foreground job.
type Job struct {
	ID     int
	Cmd    *exec.Cmd
	Status JobStatus
	PID    int
	PGID   int
	Args   []string // human-readable command args for display

	done chan struct{} // closed by the owner once the pid is reaped and output drained
}

// JobTable is a mutex-protected table of active jobs.
type JobTable struct {
	mu      sync.Mutex
	changed *sync.Cond // broadcast on every job status change; uses mu
	jobs    map[int]*Job
	nextID  int
}

// globalJobTable is the process-wide singleton.
var globalJobTable = func() *JobTable {
	t := &JobTable{jobs: make(map[int]*Job), nextID: 1}
	t.changed = sync.NewCond(&t.mu)
	return t
}()

// GlobalJobTable returns the singleton job table.
func GlobalJobTable() *JobTable {
	return globalJobTable
}

// NewJob sets up cmd for a new process group (Setpgid), starts it, and
// registers it in the job table.  Returns the assigned job ID.
//
// The job table is the only waiter for the child: a per-job owner goroutine
// waits on that one pid and nothing (including cmd.Wait) may wait on it again.
// Callers must not call cmd.Wait.  Non-file stdio is piped through copiers
// owned here so os/exec never needs Wait to drain or close them.
func NewJob(cmd *exec.Cmd) (int, error) {
	// A context-bound command's cancel path signals cmd.Process by pid and
	// expects cmd.Wait to run; both would race the owner's reap.
	if cmd.Cancel != nil || cmd.WaitDelay != 0 {
		return 0, errors.New("job: context-bound commands are not supported")
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true

	var (
		childEnds []*os.File // closed in the parent once the child holds them
		readEnds  []*os.File // parent read ends, closed by their copier
		copiers   []func()
		drained   sync.WaitGroup
	)
	closeAll := func() {
		for _, f := range childEnds {
			f.Close()
		}
		for _, f := range readEnds {
			f.Close()
		}
	}
	pipeOut := func(w io.Writer) (*os.File, error) {
		r, pw, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		childEnds = append(childEnds, pw)
		readEnds = append(readEnds, r)
		copiers = append(copiers, func() {
			defer drained.Done()
			io.Copy(w, r) //nolint:errcheck
			r.Close()
		})
		return pw, nil
	}
	if _, ok := cmd.Stdout.(*os.File); cmd.Stdout != nil && !ok {
		pw, err := pipeOut(cmd.Stdout)
		if err != nil {
			closeAll()
			return 0, fmt.Errorf("job: stdout pipe: %w", err)
		}
		if sameWriter(cmd.Stdout, cmd.Stderr) {
			cmd.Stderr = pw
		}
		cmd.Stdout = pw
	}
	if _, ok := cmd.Stderr.(*os.File); cmd.Stderr != nil && !ok {
		pw, err := pipeOut(cmd.Stderr)
		if err != nil {
			closeAll()
			return 0, fmt.Errorf("job: stderr pipe: %w", err)
		}
		cmd.Stderr = pw
	}
	var stdinW *os.File
	var stdinSrc io.Reader
	if _, ok := cmd.Stdin.(*os.File); cmd.Stdin != nil && !ok {
		r, w, err := os.Pipe()
		if err != nil {
			closeAll()
			return 0, fmt.Errorf("job: stdin pipe: %w", err)
		}
		childEnds = append(childEnds, r)
		stdinW, stdinSrc = w, cmd.Stdin
		cmd.Stdin = r
	}

	if err := cmd.Start(); err != nil {
		closeAll()
		if stdinW != nil {
			stdinW.Close()
		}
		return 0, fmt.Errorf("job: start: %w", err)
	}
	for _, f := range childEnds {
		f.Close()
	}
	drained.Add(len(copiers))
	for _, c := range copiers {
		go c()
	}
	if stdinW != nil {
		// Not awaited: like os/exec, this ends when src is exhausted or the
		// child closes its stdin (EPIPE).
		go func() {
			io.Copy(stdinW, stdinSrc) //nolint:errcheck
			stdinW.Close()
		}()
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
		done:   make(chan struct{}),
	}
	t.jobs[id] = j
	t.mu.Unlock()

	go t.ownJob(j, &drained)

	return id, nil
}

// ownJob is the single waiter for j.PID.  It waits on that pid only, tracks
// stop/continue for job control, and on exit marks the job done, waits for
// its output to drain, and closes j.done.
func (t *JobTable) ownJob(j *Job, drained *sync.WaitGroup) {
	for {
		var ws syscall.WaitStatus
		_, err := syscall.Wait4(j.PID, &ws, syscall.WUNTRACED|syscall.WCONTINUED, nil)
		if err == syscall.EINTR {
			continue
		}
		t.mu.Lock()
		switch {
		case err != nil:
			// ECHILD: the pid is no longer ours to wait on.  Fail closed to done.
			j.Status = JobDone
		case isStopReport(ws):
			if isContinueReport(ws) {
				j.Status = JobRunning
			} else {
				j.Status = JobStopped
			}
		default:
			j.Status = JobDone
		}
		finished := j.Status == JobDone
		t.changed.Broadcast()
		t.mu.Unlock()
		if finished {
			drained.Wait()
			close(j.done)
			return
		}
	}
}

// isStopReport and isContinueReport decode wait4 stop/continue reports for
// both kernels.  syscall.WaitStatus.Stopped/Continued are wrong on Darwin:
// they treat a SIGSTOP stop as "continued".  Both Linux and Darwin mark a
// stop/continue report with 0x7f in the low seven bits.  Linux reports a
// continue as 0xffff; Darwin reports it as a stop with signal SIGCONT.
func isStopReport(ws syscall.WaitStatus) bool { return ws&0x7f == 0x7f }

func isContinueReport(ws syscall.WaitStatus) bool {
	return ws == 0xffff || syscall.Signal((ws>>8)&0xff) == syscall.SIGCONT
}

// sameWriter reports whether a and b are the same writer, without panicking
// on incomparable dynamic types.
func sameWriter(a, b io.Writer) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
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
	var status JobStatus
	if ok {
		status = j.Status
	}
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("fg: no such job: %d", id)
	}
	if status == JobDone {
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

	// Wait for the job's owner to report it stopped or exited.  fg never
	// waits on the pid itself.
	t.mu.Lock()
	if j.Status == JobStopped {
		j.Status = JobRunning
	}
	for j.Status == JobRunning {
		t.changed.Wait()
	}
	t.mu.Unlock()

	// Reclaim the terminal for the shell.
	shellPGID := syscall.Getpgrp()
	_ = SetForegroundProcessGroup(shellPGID)

	return nil
}

// BgJob resumes a stopped job in the background (sends SIGCONT to its PGID).
func BgJob(id int) error {
	t := globalJobTable
	t.mu.Lock()
	j, ok := t.jobs[id]
	var status JobStatus
	if ok {
		status = j.Status
	}
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("bg: no such job: %d", id)
	}
	if status == JobDone {
		return fmt.Errorf("bg: job %d has already finished", id)
	}

	if err := syscall.Kill(-j.PGID, syscall.SIGCONT); err != nil {
		return fmt.Errorf("bg: SIGCONT: %w", err)
	}

	t.mu.Lock()
	if j.Status == JobStopped {
		j.Status = JobRunning
	}
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
	<-j.done // the owner goroutine is the only waiter on the pid
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
	if _, err := SaveTermios(fd); err != nil {
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
