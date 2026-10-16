//go:build darwin

package sys

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Threats: darwin's x/sys has no SOCK_CLOEXEC, so the pair is created
// without it and FD_CLOEXEC is set with fcntl. syscall.ForkLock is held for
// reading across socketpair and both fcntls; os/exec takes it for writing
// around fork, so a concurrent spawn cannot fork in that window and inherit
// another session's pair. A fork that does not go through the syscall
// package (cgo, a native library) does not take the lock and is not covered.
func cloexecSocketpair() ([2]int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return [2]int{}, err
	}
	for _, fd := range fds {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			_ = unix.Close(fds[0])
			_ = unix.Close(fds[1])
			return [2]int{}, err
		}
	}
	return fds, nil
}
