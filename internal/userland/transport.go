package userland

// Threats: both endpoints require the kernel-reported peer UID to equal the
// effective UID. Private socket directories prevent other users substituting
// endpoints. This is not a boundary against the same UID or root, and provides
// neither a filesystem sandbox nor a network transport.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/local"
)

func DefaultSocket() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".adssh", "userland", "userland.sock"), nil
}

func checkDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("userland: socket must be absolute")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("userland: socket directory must be owned by this UID and mode 0700")
	}
	return nil
}

func verifyPeer(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("userland: only Unix sockets are supported")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var uid uint32
	var credErr error
	if err := raw.Control(func(fd uintptr) { uid, credErr = peerUID(int(fd)) }); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if uid != uint32(os.Geteuid()) {
		return fmt.Errorf("userland: peer UID mismatch")
	}
	return nil
}

type checkedListener struct{ net.Listener }

func (l checkedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err = verifyPeer(c); err == nil {
			return c, nil
		}
		if err := c.Close(); err != nil {
			return nil, err
		}
	}
}

func Listen(path string) (net.Listener, error) {
	if err := checkDirectory(path); err != nil {
		return nil, err
	}
	// Never unlink an existing path, including a stale socket or symlink.
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, closeWithError(l, err)
	}
	return checkedListener{l}, nil
}

func closeWithError(c interface{ Close() error }, err error) error {
	if closeErr := c.Close(); closeErr != nil {
		return fmt.Errorf("%w (close: %v)", err, closeErr)
	}
	return err
}

func Dial(ctx context.Context, path string) (*grpc.ClientConn, error) {
	if err := checkDirectory(path); err != nil {
		return nil, err
	}
	return grpc.NewClient("passthrough:///userland", grpc.WithTransportCredentials(local.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
			if err != nil {
				return nil, err
			}
			if err := verifyPeer(c); err != nil {
				return nil, closeWithError(c, err)
			}
			return c, nil
		}), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessage), grpc.MaxCallSendMsgSize(MaxMessage)))
}
