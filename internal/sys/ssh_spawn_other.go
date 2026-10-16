//go:build !unix

package sys

import (
	"errors"
	"os"
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
