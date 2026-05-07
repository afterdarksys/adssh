package security

import (
	"context"
	"io"
	"net"
	"os"
	"strings"

	"mvdan.cc/sh/v3/interp"
)

// VirtualOpenHandler handles shell redirections to virtual devices like /dev/tcp
func VirtualOpenHandler() interp.OpenHandlerFunc {
	defaultOpen := interp.DefaultOpenHandler()

	return func(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
		if strings.HasPrefix(path, "/dev/tcp/") {
			addr := strings.TrimPrefix(path, "/dev/tcp/")
			addr = strings.Replace(addr, "/", ":", 1) // e.g. 8.8.8.8/80 -> 8.8.8.8:80
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			return conn, nil
		}

		if strings.HasPrefix(path, "/dev/udp/") {
			addr := strings.TrimPrefix(path, "/dev/udp/")
			addr = strings.Replace(addr, "/", ":", 1)
			conn, err := net.Dial("udp", addr)
			if err != nil {
				return nil, err
			}
			return conn, nil
		}

		// Fallback to normal file opening
		return defaultOpen(ctx, path, flag, perm)
	}
}
