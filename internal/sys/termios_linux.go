//go:build linux

package sys

import (
	"golang.org/x/sys/unix"
)

// tcflag is the type of the termios flag words on linux.
type tcflag = uint32

const tcflagBits = 32

// vdisable is _POSIX_VDISABLE: a control character set to it is off.
const vdisable = 0

// IsCookedMode checks if the given file descriptor has ICANON enabled.
func IsCookedMode(fd uintptr) bool {
	t, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	if err == nil {
		return (t.Lflag & unix.ICANON) != 0
	}
	return false
}

// DisableISIG clears ISIG. The SSH session path leaves ISIG on because that
// process is its own session, so Ctrl-C reaches it. Linux uses TCGETS and
// TCSETS.
func DisableISIG(fd uintptr) error {
	t, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	if err != nil {
		return err
	}
	t.Lflag &^= unix.ISIG
	return unix.IoctlSetTermios(int(fd), unix.TCSETS, t)
}

// SaveTermios snapshots the current terminal attributes for fd.
func SaveTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TCGETS)
}

// RestoreTermios applies previously saved terminal attributes.
func RestoreTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
}

// MakeSane resets the terminal to a sensible canonical state (stty sane).
func MakeSane(fd int) error {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	saneTermios(t)
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
}

// saneTermios sets t to a sensible canonical state (stty sane): echo,
// line editing, and the standard control characters.
func saneTermios(t *unix.Termios) {
	// Input: enable break signal, CR→NL, flow control; disable NL→CR, strip
	t.Iflag |= unix.BRKINT | unix.ICRNL | unix.IMAXBEL | unix.IXON
	t.Iflag &^= unix.IGNBRK | unix.INLCR | unix.IGNCR | unix.IXOFF | unix.ISTRIP
	// Output: post-process, translate NL→CR+NL
	t.Oflag |= unix.OPOST | unix.ONLCR
	// Local: enable canonical mode, signal generation, echo
	t.Lflag |= unix.ICANON | unix.ISIG | unix.IEXTEN | unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOKE
	t.Lflag &^= unix.NOFLSH
	// Standard control characters
	t.Cc[unix.VINTR] = 3     // Ctrl+C  → SIGINT
	t.Cc[unix.VQUIT] = 28    // Ctrl+\  → SIGQUIT
	t.Cc[unix.VERASE] = 127  // DEL     → erase char
	t.Cc[unix.VKILL] = 21    // Ctrl+U  → kill line
	t.Cc[unix.VEOF] = 4      // Ctrl+D  → EOF
	t.Cc[unix.VSUSP] = 26    // Ctrl+Z  → SIGTSTP
	t.Cc[unix.VSTART] = 17   // Ctrl+Q  → resume output
	t.Cc[unix.VSTOP] = 19    // Ctrl+S  → stop output
	t.Cc[unix.VWERASE] = 23  // Ctrl+W  → erase word
	t.Cc[unix.VLNEXT] = 22   // Ctrl+V  → literal next
	t.Cc[unix.VREPRINT] = 18 // Ctrl+R → reprint line
	t.Cc[unix.VDISCARD] = 15 // Ctrl+O → discard output
	t.Cc[unix.VEOL] = vdisable
	t.Cc[unix.VEOL2] = vdisable
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
}

// GetTerminalSize returns the rows and columns of the terminal attached to fd.
func GetTerminalSize(fd int) (rows, cols int, err error) {
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0, err
	}
	return int(ws.Row), int(ws.Col), nil
}
