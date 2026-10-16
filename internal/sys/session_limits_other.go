//go:build !unix

package sys

import (
	"fmt"
	"os"
	"os/exec"
)

// MaybeRunSessionChild refuses a --session-child re-exec on platforms that
// cannot apply the rlimit protocol. A normal process start returns.
func MaybeRunSessionChild() {
	if len(os.Args) > 1 && os.Args[1] == "--session-child" {
		fmt.Fprintf(os.Stderr, "adssh: session child: not supported\n")
		os.Exit(1)
	}
}

// PrepareChild sets a session environment when one exists. Outside go test it
// fails closed when a privilege drop or a non-zero rlimit was requested,
// because this platform cannot apply either.
func PrepareChild(cmd *exec.Cmd, session *Session) error {
	if cmd == nil {
		return fmt.Errorf("adssh: session child: nil command")
	}
	if cmd.Env == nil && session != nil {
		cmd.Env = session.Environ()
	}
	if runningUnderTest() {
		return nil
	}
	if (session != nil && session.DropPrivileges()) || sessionLimits().any() {
		return fmt.Errorf("adssh: session child: not supported")
	}
	return nil
}

// RequireResolvableSSHUser fails closed on platforms without the unix user
// lookup used to drop an SSH session.
func RequireResolvableSSHUser(name string) error {
	return fmt.Errorf("adssh: session child: not supported")
}
