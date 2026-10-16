//go:build darwin

package sys

import "golang.org/x/sys/unix"

// Darwin's x/sys has no SOCK_CLOEXEC. FD_CLOEXEC is set before the caller
// starts a child. A fork between socketpair and these fcntls can inherit
// the pair.
func cloexecSocketpair() ([2]int, error) {
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
