//go:build unix

package repl

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

const ptySignalHelperEnv = "ADSSH_TEST_PTY_SIGNAL_HELPER"

func TestHelperPTYExecSignals(t *testing.T) {
	dir := os.Getenv(ptySignalHelperEnv)
	if dir == "" {
		t.Skip("helper process")
	}
	sys.SetupSignals()
	tty := openRealTerminal(t)
	broadcaster := sys.NewOutputBroadcaster(&bytes.Buffer{})
	script := "sh -c 'test -t 1 && touch " + filepath.Join(dir, "on-pty") + "; kill -INT $$; touch " + filepath.Join(dir, "survived") + "'"
	_ = runForeground(t, tty, script, broadcaster)
	_ = os.WriteFile(filepath.Join(dir, "done"), nil, 0o600)
	os.Exit(0)
}

func TestPTYExecSignalChildDiesOnSIGINT(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is not available")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperPTYExecSignals$")
	cmd.Env = append(os.Environ(), ptySignalHelperEnv+"="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	if !exists("done") {
		t.Fatal("helper did not finish")
	}
	if !exists("on-pty") {
		t.Skip("command did not run on the PTY path in this environment")
	}
	if exists("survived") {
		t.Fatal("a PTY-path command survived SIGINT after SetupSignals")
	}
}
