package vbinui

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

const termProbeHelperEnv = "ADSSH_TERMBG_PROBE_HELPER"

// TestHelperTermProbe runs in a child under a pty: by the time it runs, every
// package init (bubbletea's included) has happened. It echoes one line.
func TestHelperTermProbe(t *testing.T) {
	if os.Getenv(termProbeHelperEnv) != "1" {
		t.Skip("helper process")
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Printf("got:%s\n", strings.TrimSpace(line))
	os.Exit(0)
}

// A terminal that never answers must see no background query at startup, and
// input typed before the program is ready must reach it.
func TestStartupSendsNoTerminalQuery(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperTermProbe$")
	cmd.Env = append(os.Environ(), termProbeHelperEnv+"=1", "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	defer func() { _ = ptmx.Close() }()
	if _, err := ptmx.Write([]byte("typed-ahead\n")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&out, ptmx)
		close(done)
	}()
	start := time.Now()
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	var exitErr error
	select {
	case exitErr = <-waitErr:
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("helper hung; output %q", out.String())
	}
	_ = ptmx.Close()
	<-done
	got := out.String()
	if exitErr != nil {
		t.Fatalf("helper failed: %v; output %q", exitErr, got)
	}
	if strings.Contains(got, "\x1b]11;?") || strings.Contains(got, "\x1b[6n") {
		t.Fatalf("startup queried the terminal: %q", got)
	}
	if !strings.Contains(got, "got:typed-ahead") {
		t.Fatalf("typed-ahead input was lost: %q", got)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("startup took %s; a terminal query timeout is the likely cause", d)
	}
}
