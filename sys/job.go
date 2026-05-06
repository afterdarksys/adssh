package sys

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

// SetForegroundProcessGroup sets the terminal's foreground process group to pgid.
// This is critical for true POSIX job control on FreeBSD/Solaris/Linux.
func SetForegroundProcessGroup(pgid int) error {
	// We need to ignore SIGTTOU while we change the terminal process group
	// Otherwise, our shell will get suspended!
	// Currently handled safely by go os/signal for our own process, but we must make the ioctl.

	fd := int(os.Stdin.Fd())

	// Ensure we are actually attached to a terminal
	if _, err := unix.IoctlGetTermios(fd, unix.TIOCGETA); err != nil {
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
