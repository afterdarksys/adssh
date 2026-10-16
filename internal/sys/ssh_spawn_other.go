//go:build !unix

package sys

import (
	"errors"
	"os"

	"github.com/creack/pty"
)

// OpenMonitorFD fails closed where the monitor socket cannot be inherited.
func OpenMonitorFD(fd int) (*os.File, error) {
	_ = fd
	return nil, errors.New("adssh: ssh session: not supported")
}

// SpawnSSHSession fails closed where a session process cannot be exec'd.
func SpawnSSHSession(spec SSHSessionSpec) error {
	return errors.New("adssh: ssh session: not supported")
}

// pollablePTY fails closed where the master cannot be made non-blocking.
func pollablePTY(f *os.File) (*os.File, error) {
	return nil, errors.New("adssh: ssh session: not supported")
}

// setPTYSize fails closed where the window size cannot be set.
func setPTYSize(f *os.File, ws *pty.Winsize) error {
	return errors.New("adssh: ssh session: not supported")
}
