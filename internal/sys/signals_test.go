//go:build unix

package sys

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
)

var setupSignalsOnce sync.Once

// withShellSignals installs the shell's process-wide signal handlers exactly
// once for the test binary, so every test sees the same disposition.
func withShellSignals(t *testing.T) {
	t.Helper()
	setupSignalsOnce.Do(SetupSignals)
}

// sigchldStorm starts and finishes n short children so the process receives
// a burst of SIGCHLD while another child's exit status is still unclaimed.
func sigchldStorm(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := exec.Command("/bin/sh", "-c", "exit 0").Run(); err != nil {
			t.Fatalf("storm child %d: %v", i, err)
		}
	}
}

func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("want *exec.ExitError, got %T: %v", err, err)
	}
	return ee.ExitCode()
}

// The Codex probe: the global SIGCHLD reaper must not consume the exit
// status of a child owned by an exec.Cmd.
func TestSignalsDoNotStealForeignExitStatus(t *testing.T) {
	withShellSignals(t)

	cmd := exec.Command("/bin/sh", "-c", "exit 7")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	sigchldStorm(t, 5)
	time.Sleep(50 * time.Millisecond)

	if code := exitCodeOf(t, cmd.Wait()); code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
}

func TestSignalsPreserveSignaledStatus(t *testing.T) {
	withShellSignals(t)

	cmd := exec.Command("/bin/sh", "-c", "kill -TERM $$; sleep 5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	sigchldStorm(t, 5)

	err := cmd.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("want *exec.ExitError, got %T: %v", err, err)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Fatalf("status = %v, want killed by SIGTERM", ee.ProcessState)
	}
}

func TestSignalsConcurrentForegroundExitCodes(t *testing.T) {
	withShellSignals(t)

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(code int) {
			defer wg.Done()
			cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("sleep 0.0%d; exit %d", code%10, code))
			err := cmd.Run()
			if code == 0 {
				if err != nil {
					errs <- fmt.Errorf("child %d: %v", code, err)
				}
				return
			}
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				errs <- fmt.Errorf("child %d: want *exec.ExitError, got %T: %v", code, err, err)
				return
			}
			if ee.ExitCode() != code {
				errs <- fmt.Errorf("child %d: exit code %d", code, ee.ExitCode())
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
