//go:build unix

package sys

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
)

func jobStatus(t *testing.T, id int) JobStatus {
	t.Helper()
	for _, j := range Jobs() {
		if j.ID == id {
			return j.Status
		}
	}
	t.Fatalf("job %d not in table", id)
	return ""
}

func waitForStatus(t *testing.T, id int, want JobStatus) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if jobStatus(t, id) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %d status = %s, want %s", id, jobStatus(t, id), want)
}

func waitJobWithTimeout(t *testing.T, id int) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- WaitJob(id) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitJob(%d): %v", id, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("WaitJob(%d) did not return", id)
	}
}

func startJob(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	id, err := NewJob(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		GlobalJobTable().Disown(id)
	})
	return id
}

func TestJobStopContinueKill(t *testing.T) {
	withShellSignals(t)

	cmd := exec.Command("sleep", "5")
	id := startJob(t, cmd)
	pid := cmd.Process.Pid

	waitForStatus(t, id, JobRunning)

	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, id, JobStopped)

	// bg sends SIGCONT to the group.  Darwin's wait4 never reports a
	// continue, so the shell path, not the owner, marks the job running.
	if err := BgJob(id); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, id, JobRunning)

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, id, JobDone)
	waitJobWithTimeout(t, id)
}

// A job's stdout goes to a plain io.Writer; its output must be complete by
// the time WaitJob returns, without anyone calling cmd.Wait.
func TestJobOutputDrainedBeforeWaitReturns(t *testing.T) {
	withShellSignals(t)

	w := &lockedBuffer{}
	cmd := exec.Command("/bin/sh", "-c", "echo out; echo err >&2; exit 3")
	cmd.Stdout = w
	cmd.Stderr = w
	id := startJob(t, cmd)

	waitJobWithTimeout(t, id)
	if got := jobStatus(t, id); got != JobDone {
		t.Fatalf("status = %s, want done", got)
	}
	w.mu.Lock()
	got := w.buf.String()
	w.mu.Unlock()
	// One shared writer gets one shared pipe, so stream order is preserved.
	if got != "out\nerr\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestFgJobReturnsWhenJobExits(t *testing.T) {
	withShellSignals(t)
	if _, err := SaveTermios(int(os.Stdin.Fd())); err == nil {
		t.Skip("stdin is a terminal; fg would move the test's foreground group")
	}

	cmd := exec.Command("sleep", "5")
	id := startJob(t, cmd)
	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, id, JobStopped)

	done := make(chan error, 1)
	go func() { done <- FgJob(id) }()
	waitForStatus(t, id, JobRunning)
	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("FgJob: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FgJob did not return")
	}
	if got := jobStatus(t, id); got != JobDone {
		t.Fatalf("status = %s, want done", got)
	}
}

func TestNewJobRejectsContextCommand(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "true")
	if _, err := NewJob(cmd); err == nil {
		t.Fatal("NewJob accepted a command whose cancel path would signal a reaped pid")
	}
	if cmd.Process != nil {
		t.Fatal("NewJob started a command it rejected")
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
