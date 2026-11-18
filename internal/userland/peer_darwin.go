package userland

import "golang.org/x/sys/unix"

func peerUID(fd int) (uint32, error) {
	c, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return c.Uid, nil
}
