//go:build linux

package sys

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// After SetNonDumpable the process reports dumpable 0, so its /proc entries
// belong to root. It runs in a child so the test process is unaffected.
func TestSetNonDumpable(t *testing.T) {
	if os.Getenv("ADSSH_TEST_DUMPABLE_CHILD") == "1" {
		if err := SetNonDumpable(); err != nil {
			os.Exit(2)
		}
		v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || v != 0 {
			os.Exit(3)
		}
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestSetNonDumpable$")
	cmd.Env = append(os.Environ(), "ADSSH_TEST_DUMPABLE_CHILD=1")
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v", err)
	}
}
