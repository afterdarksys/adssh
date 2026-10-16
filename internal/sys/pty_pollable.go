package sys

import (
	"os"

	"github.com/creack/pty"
)

// PollablePTY returns a non-blocking, poller-owned copy of a pty master and
// closes f, so Close releases a goroutine blocked in Read or Write even while
// another process holds the slave open. On error f is left open. See
// pollablePTY.
func PollablePTY(f *os.File) (*os.File, error) { return pollablePTY(f) }

// SetPTYSize sets a pty master's window size without calling Fd, which would
// put a pollable master back into blocking mode.
func SetPTYSize(f *os.File, ws *pty.Winsize) error { return setPTYSize(f, ws) }
