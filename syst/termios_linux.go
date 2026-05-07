//go:build linux

package sys

import (
	"golang.org/x/sys/unix"
)

// IsCookedMode checks if the given file descriptor has ICANON enabled.
func IsCookedMode(fd uintptr) bool {
	t, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	if err == nil {
		return (t.Lflag & unix.ICANON) != 0
	}
	return false
}

// DisableISIG permanently disables the ISIG flag on a terminal.
func DisableISIG(fd uintptr) error {
	t, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	if err != nil {
		return err
	}
	t.Lflag &^= unix.ISIG
	return unix.IoctlSetTermios(int(fd), unix.TCSETS, t)
}
