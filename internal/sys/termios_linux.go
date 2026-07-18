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

// SaveTermios snapshots the current terminal attributes for fd.
func SaveTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TCGETS)
}

// RestoreTermios applies previously saved terminal attributes.
func RestoreTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
}

// MakeSane resets the terminal to a sensible canonical state (equivalent to
// stty sane): enables echo, line-editing, and standard control characters.
func MakeSane(fd int) error {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	// Input: enable break signal, CR→NL, flow control; disable NL→CR, strip
	t.Iflag |= unix.BRKINT | unix.ICRNL | unix.IMAXBEL | unix.IXON
	t.Iflag &^= unix.IGNBRK | unix.INLCR | unix.IGNCR | unix.IXOFF | unix.ISTRIP
	// Output: post-process, translate NL→CR+NL
	t.Oflag |= unix.OPOST | unix.ONLCR
	// Local: enable canonical mode, signal generation, echo
	t.Lflag |= unix.ICANON | unix.ISIG | unix.IEXTEN | unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOKE
	t.Lflag &^= unix.NOFLSH
	// Standard control characters
	t.Cc[unix.VINTR] = 3    // Ctrl+C  → SIGINT
	t.Cc[unix.VQUIT] = 28   // Ctrl+\  → SIGQUIT
	t.Cc[unix.VERASE] = 127 // DEL     → erase char
	t.Cc[unix.VKILL] = 21   // Ctrl+U  → kill line
	t.Cc[unix.VEOF] = 4     // Ctrl+D  → EOF
	t.Cc[unix.VSUSP] = 26   // Ctrl+Z  → SIGTSTP
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
}

// GetTerminalSize returns the rows and columns of the terminal attached to fd.
func GetTerminalSize(fd int) (rows, cols int, err error) {
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0, err
	}
	return int(ws.Row), int(ws.Col), nil
}

// SetEcho enables or disables character echo on the terminal.
func SetEcho(fd int, on bool) error {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	if on {
		t.Lflag |= unix.ECHO | unix.ECHOE | unix.ECHOK
	} else {
		t.Lflag &^= unix.ECHO | unix.ECHOE | unix.ECHOK
	}
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
}

// SetRaw switches the terminal between raw (non-canonical) and cooked
// (canonical) mode.  Switching to raw disables echo and line-editing;
// switching back restores ICANON and ECHO.
func SetRaw(fd int, raw bool) error {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	if raw {
		t.Lflag &^= unix.ICANON | unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ISIG | unix.IEXTEN
		t.Iflag &^= unix.ICRNL | unix.IXON
		t.Cc[unix.VMIN] = 1
		t.Cc[unix.VTIME] = 0
	} else {
		t.Lflag |= unix.ICANON | unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ISIG | unix.IEXTEN
		t.Iflag |= unix.ICRNL | unix.IXON
	}
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
}

// TermiosFlags returns a human-readable list of active terminal flag strings
// for use by the stty VBIN's no-argument display.
func TermiosFlags(fd int) ([]string, error) {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	var out []string
	flag := func(set bool, name string) {
		if set {
			out = append(out, name)
		} else {
			out = append(out, "-"+name)
		}
	}
	flag(t.Lflag&unix.ICANON != 0, "icanon")
	flag(t.Lflag&unix.ECHO != 0, "echo")
	flag(t.Lflag&unix.ISIG != 0, "isig")
	flag(t.Lflag&unix.IEXTEN != 0, "iexten")
	flag(t.Iflag&unix.ICRNL != 0, "icrnl")
	flag(t.Iflag&unix.IXON != 0, "ixon")
	flag(t.Oflag&unix.OPOST != 0, "opost")
	return out, nil
}
