//go:build unix

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

const sessionSignalHelperEnv = "ADSSH_TEST_SESSION_SIGNAL_HELPER"

// TestHelperSSHSessionSignals runs only as a child of
// TestSSHSessionCommandsDieOnSIGINT. It sets signals up the way
// runSSHSession does, then runs a command the way the session runs one.
func TestHelperSSHSessionSignals(t *testing.T) {
	if os.Getenv(sessionSignalHelperEnv) != "1" {
		t.Skip("helper process")
	}
	// The listener ignores these and the ignore survives exec.
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	overlay := &sys.Session{ID: "sig-helper", User: "u"}
	if err := sys.RegisterSession(overlay); err != nil {
		fmt.Println("register:", err)
		os.Exit(2)
	}
	sys.SetupSignals()
	installSessionSignals(overlay)

	for _, sig := range []string{"INT", "QUIT"} {
		out, _ := exec.Command("/bin/sh", "-c", "kill -"+sig+" $$; echo survived-"+sig).CombinedOutput()
		fmt.Print(string(out))
	}

	ctx, cancel := context.WithCancel(context.Background())
	overlay.SetContext(ctx, cancel)
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	select {
	case <-ctx.Done():
		fmt.Println("command-cancelled")
	case <-time.After(2 * time.Second):
		fmt.Println("command-not-cancelled")
	}
	fmt.Println("session-alive")
	os.Exit(0)
}

func TestSSHSessionCommandsDieOnSIGINT(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is not available")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSSHSessionSignals$")
	cmd.Env = append(os.Environ(), sessionSignalHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	got := string(out)
	for _, sig := range []string{"INT", "QUIT"} {
		if strings.Contains(got, "survived-"+sig) {
			t.Fatalf("a session command survived SIG%s: %q", sig, got)
		}
	}
	if !strings.Contains(got, "session-alive") {
		t.Fatalf("the session process did not survive SIGINT: %q", got)
	}
	if !strings.Contains(got, "command-cancelled") {
		t.Fatalf("SIGINT did not cancel the running command: %q", got)
	}
}
