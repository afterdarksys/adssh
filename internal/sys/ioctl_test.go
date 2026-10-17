package sys

import (
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const initTerminalHelperEnv = "ADSSH_TEST_INIT_TERMINAL_HELPER"

// TestHelperInitTerminal runs InitTerminal in a child process, so the test
// binary itself never changes its process group.
func TestHelperInitTerminal(t *testing.T) {
	if os.Getenv(initTerminalHelperEnv) == "" {
		t.Skip("helper process only")
	}
	if err := InitTerminal(); err != nil {
		os.Stderr.WriteString("InitTerminal: " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}

// With stdin a pipe (adssh -c from a script) there is no terminal to take,
// so that is not an error to warn about.
func TestInitTerminalWithoutTTYIsQuiet(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	for name, stdin := range map[string]io.Reader{"pipe": strings.NewReader(""), "/dev/null": devNull} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperInitTerminal$")
		cmd.Env = append(os.Environ(), initTerminalHelperEnv+"=1")
		cmd.Stdin = stdin
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("InitTerminal with stdin %s failed: %v\n%s", name, err, out)
		}
	}
}
