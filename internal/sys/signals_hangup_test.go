//go:build unix

package sys

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const shellSignalHelperEnv = "ADSSH_TEST_SHELL_SIGNAL_HELPER"

// TestHelperShellSignals runs only as a child of the tests below, so the
// process-wide dispositions it installs do not leak into the test binary.
func TestHelperShellSignals(t *testing.T) {
	mode := os.Getenv(shellSignalHelperEnv)
	if mode == "" {
		t.Skip("helper process")
	}
	SetupSignals()
	switch mode {
	case "sigint":
		for _, sig := range []string{"INT", "QUIT"} {
			out, _ := exec.Command("/bin/sh", "-c", "kill -"+sig+" $$; echo survived-"+sig).CombinedOutput()
			fmt.Print(string(out))
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		_ = syscall.Kill(os.Getpid(), syscall.SIGQUIT)
		time.Sleep(200 * time.Millisecond)
		fmt.Println("shell-alive")
	case "hangup-hook":
		hooked := make(chan struct{})
		OnHangup(func() { close(hooked) })
		_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
		select {
		case <-hooked:
			fmt.Println("hook-ran")
		case <-time.After(2 * time.Second):
			fmt.Println("hook-missing")
		}
		time.Sleep(200 * time.Millisecond)
		fmt.Println("listener-alive")
	case "hangup-default":
		_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
		time.Sleep(2 * time.Second)
		fmt.Println("still-running")
	case "hangup-group":
		// A child in this process group, as a mvdan background job would be.
		child := exec.Command("sleep", "30")
		if err := child.Start(); err != nil {
			fmt.Println("start:", err)
			os.Exit(1)
		}
		fmt.Printf("child=%d\n", child.Process.Pid)
		_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
		time.Sleep(2 * time.Second)
		fmt.Println("still-running")
	}
	os.Exit(0)
}

func runShellSignalHelper(t *testing.T, mode string) string {
	t.Helper()
	return runShellSignalHelperCmd(t, mode, nil)
}

func runShellSignalHelperCmd(t *testing.T, mode string, attr *syscall.SysProcAttr) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is not available")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperShellSignals$")
	cmd.Env = append(os.Environ(), shellSignalHelperEnv+"="+mode)
	cmd.SysProcAttr = attr
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper %s: %v\n%s", mode, err, out)
	}
	return string(out)
}

// The local shell must not hand an ignored SIGINT or SIGQUIT to the commands
// it runs, and must itself survive both.
func TestSignalShellCommandsDieOnSIGINT(t *testing.T) {
	out := runShellSignalHelper(t, "sigint")
	for _, sig := range []string{"INT", "QUIT"} {
		if strings.Contains(out, "survived-"+sig) {
			t.Fatalf("a command started by the shell survived SIG%s: %q", sig, out)
		}
	}
	if !strings.Contains(out, "shell-alive") {
		t.Fatalf("the shell did not survive SIGINT/SIGQUIT: %q", out)
	}
}

func TestHangupHookKeepsListenerRunning(t *testing.T) {
	out := runShellSignalHelper(t, "hangup-hook")
	if !strings.Contains(out, "hook-ran") || !strings.Contains(out, "listener-alive") {
		t.Fatalf("SIGHUP with a hook installed: %q", out)
	}
}

func TestHangupDefaultExits(t *testing.T) {
	out := runShellSignalHelper(t, "hangup-default")
	if strings.Contains(out, "still-running") {
		t.Fatalf("SIGHUP without a hook did not exit the shell: %q", out)
	}
}

// The default hangup sends SIGHUP to the shell's own process group, so a
// command left running in the background (mvdan runs `&` in this group) does
// not outlive the shell.
func TestHangupDefaultSignalsProcessGroup(t *testing.T) {
	out := runShellSignalHelperCmd(t, "hangup-group", &syscall.SysProcAttr{Setpgid: true})
	if strings.Contains(out, "still-running") {
		t.Fatalf("SIGHUP without a hook did not exit the shell: %q", out)
	}
	var pid int
	for _, line := range strings.Split(out, "\n") {
		if _, err := fmt.Sscanf(line, "child=%d", &pid); err == nil {
			break
		}
	}
	if pid <= 0 {
		t.Fatalf("helper did not report its child: %q", out)
	}
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("background child %d survived the shell's hangup", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A shell that does not lead its process group must not signal the group:
// that group belongs to whoever started it.
func TestHangupGroupSkippedWhenNotLeader(t *testing.T) {
	var signaled atomic.Int32
	prev := killGroup
	t.Cleanup(func() { killGroup = prev })
	killGroup = func(int, syscall.Signal) error { signaled.Add(1); return nil }
	if syscall.Getpgrp() == os.Getpid() {
		t.Skip("the test binary leads its own process group")
	}
	hangupProcessGroup()
	if signaled.Load() != 0 {
		t.Fatal("signaled a process group this process does not lead")
	}
}

func TestHangupHookCanBeCleared(t *testing.T) {
	prevExit := exitProcess
	prevKill := killGroup
	t.Cleanup(func() {
		exitProcess = prevExit
		killGroup = prevKill
		OnHangup(nil)
	})
	var exited atomic.Int32
	exitProcess = func(int) { exited.Add(1) }
	killGroup = func(int, syscall.Signal) error { return nil }
	var hooked atomic.Int32
	OnHangup(func() { hooked.Add(1) })
	handleHangup()
	if hooked.Load() != 1 || exited.Load() != 0 {
		t.Fatalf("hook=%d exit=%d", hooked.Load(), exited.Load())
	}
	OnHangup(nil)
	handleHangup()
	if hooked.Load() != 1 || exited.Load() != 1 {
		t.Fatalf("after clear hook=%d exit=%d", hooked.Load(), exited.Load())
	}
}

// StopAcceptingSSH closes the listener; a connection already served keeps
// working and a new one is refused.
func TestHangupStopAcceptingSSHKeepsConnections(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sshMu.Lock()
	prev := sshListener
	sshListener = l
	sshMu.Unlock()
	t.Cleanup(func() {
		sshMu.Lock()
		sshListener = prev
		sshMu.Unlock()
		_ = l.Close()
	})
	served := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		served <- c
		_, _ = bufio.NewReader(c).WriteTo(c)
	}()
	addr := l.Addr().String()
	existing, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("connection was not served")
	}

	if err := StopAcceptingSSH(); err != nil {
		t.Fatalf("StopAcceptingSSH: %v", err)
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("a new connection was accepted after StopAcceptingSSH")
	}
	_ = existing.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := existing.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(existing).ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("existing connection broke: %q %v", line, err)
	}
	if err := StopAcceptingSSH(); err == nil {
		t.Fatal("a second StopAcceptingSSH reported success")
	}
}
