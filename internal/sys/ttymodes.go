//go:build linux || darwin

package sys

// Threats: stty and the SSH terminal modes change only the terminal of the
// caller's own session. stty acts on its standard input and has no -F, so it
// cannot reach another session's tty. Every stty operand is parsed before
// anything is written: one bad operand, a missing value, or a malformed -g
// string changes nothing. A -g string must have exactly the field count of
// this platform's termios and parse as hex, or it is refused. The stty
// vbin acts only on the session's controlling terminal (IsControllingTTY),
// so a redirect such as 0>/dev/pts/N cannot reach another terminal. rows and
// cols are capped at maxPTYDim, the limit the SSH path applies. The SSH modes
// come from the client's pty-req (RFC 4254 section 8) and are applied to the
// session pty before the session process starts. A truncated argument, a
// control-character value above 255, or more than maxSSHModes opcodes
// refuses the whole pty-req and applies nothing. Opcodes 160 to 255 end
// parsing, as the RFC says; unknown opcodes below 160 are skipped. Line
// speed, CS7/CS8, and parity are ignored: a pty has none.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// maxSSHModes bounds the opcodes read from one pty-req. OpenSSH sends about 60.
const maxSSHModes = 256

type ttyFlag struct {
	name  string
	word  byte // 'i', 'o', 'c', or 'l'
	mask  uint64
	sshOp uint8 // RFC 4254 opcode, 0 when the client cannot set it
}

var ttyFlags = []ttyFlag{
	{"ignbrk", 'i', unix.IGNBRK, 0},
	{"brkint", 'i', unix.BRKINT, 0},
	{"ignpar", 'i', unix.IGNPAR, ssh.IGNPAR},
	{"parmrk", 'i', unix.PARMRK, ssh.PARMRK},
	{"inpck", 'i', unix.INPCK, ssh.INPCK},
	{"istrip", 'i', unix.ISTRIP, ssh.ISTRIP},
	{"inlcr", 'i', unix.INLCR, ssh.INLCR},
	{"igncr", 'i', unix.IGNCR, ssh.IGNCR},
	{"icrnl", 'i', unix.ICRNL, ssh.ICRNL},
	{"ixon", 'i', unix.IXON, ssh.IXON},
	{"ixany", 'i', unix.IXANY, ssh.IXANY},
	{"ixoff", 'i', unix.IXOFF, ssh.IXOFF},
	{"imaxbel", 'i', unix.IMAXBEL, ssh.IMAXBEL},
	{"iutf8", 'i', unix.IUTF8, ssh.IUTF8},
	{"opost", 'o', unix.OPOST, ssh.OPOST},
	{"onlcr", 'o', unix.ONLCR, ssh.ONLCR},
	{"ocrnl", 'o', unix.OCRNL, ssh.OCRNL},
	{"onocr", 'o', unix.ONOCR, ssh.ONOCR},
	{"onlret", 'o', unix.ONLRET, ssh.ONLRET},
	{"parenb", 'c', unix.PARENB, 0},
	{"parodd", 'c', unix.PARODD, 0},
	{"cstopb", 'c', unix.CSTOPB, 0},
	{"cread", 'c', unix.CREAD, 0},
	{"hupcl", 'c', unix.HUPCL, 0},
	{"clocal", 'c', unix.CLOCAL, 0},
	{"isig", 'l', unix.ISIG, ssh.ISIG},
	{"icanon", 'l', unix.ICANON, ssh.ICANON},
	{"iexten", 'l', unix.IEXTEN, ssh.IEXTEN},
	{"echo", 'l', unix.ECHO, ssh.ECHO},
	{"echoe", 'l', unix.ECHOE, ssh.ECHOE},
	{"echok", 'l', unix.ECHOK, ssh.ECHOK},
	{"echonl", 'l', unix.ECHONL, ssh.ECHONL},
	{"noflsh", 'l', unix.NOFLSH, ssh.NOFLSH},
	{"tostop", 'l', unix.TOSTOP, ssh.TOSTOP},
	{"echoctl", 'l', unix.ECHOCTL, ssh.ECHOCTL},
	{"echoprt", 'l', unix.ECHOPRT, 0},
	{"echoke", 'l', unix.ECHOKE, ssh.ECHOKE},
	{"pendin", 'l', unix.PENDIN, ssh.PENDIN},
}

type ttyChar struct {
	name  string
	index int
	sshOp uint8
}

var ttyChars = []ttyChar{
	{"intr", unix.VINTR, ssh.VINTR},
	{"quit", unix.VQUIT, ssh.VQUIT},
	{"erase", unix.VERASE, ssh.VERASE},
	{"kill", unix.VKILL, ssh.VKILL},
	{"eof", unix.VEOF, ssh.VEOF},
	{"eol", unix.VEOL, ssh.VEOL},
	{"eol2", unix.VEOL2, ssh.VEOL2},
	{"start", unix.VSTART, ssh.VSTART},
	{"stop", unix.VSTOP, ssh.VSTOP},
	{"susp", unix.VSUSP, ssh.VSUSP},
	{"rprnt", unix.VREPRINT, ssh.VREPRINT},
	{"werase", unix.VWERASE, ssh.VWERASE},
	{"lnext", unix.VLNEXT, ssh.VLNEXT},
	{"discard", unix.VDISCARD, ssh.VDISCARD},
}

func flagWord(t *unix.Termios, w byte) *tcflag {
	switch w {
	case 'i':
		return &t.Iflag
	case 'o':
		return &t.Oflag
	case 'c':
		return &t.Cflag
	default:
		return &t.Lflag
	}
}

func setFlag(t *unix.Termios, f ttyFlag, on bool) {
	w := flagWord(t, f.word)
	if on {
		*w |= tcflag(f.mask)
	} else {
		*w &^= tcflag(f.mask)
	}
}

func lookupFlag(name string) (ttyFlag, bool) {
	for _, f := range ttyFlags {
		if f.name == name {
			return f, true
		}
	}
	return ttyFlag{}, false
}

func lookupChar(name string) (ttyChar, bool) {
	for _, c := range ttyChars {
		if c.name == name {
			return c, true
		}
	}
	return ttyChar{}, false
}

// formatCC writes a control character the way stty does: ^C, ^?, <undef>.
func formatCC(c uint8) string {
	switch {
	case c == vdisable:
		return "<undef>"
	case c == 0x7f:
		return "^?"
	case c < 0x20:
		return "^" + string(rune(c+'@'))
	case c >= 0x80:
		return fmt.Sprintf("0x%02x", c)
	}
	return string(rune(c))
}

// parseCC reads a control-character value: ^X, ^?, ^- or undef, one
// character, or a number (0x1b, 033, 27).
func parseCC(s string) (uint8, error) {
	switch {
	case s == "undef" || s == "^-":
		return vdisable, nil
	case s == "^?":
		return 0x7f, nil
	case len(s) == 2 && s[0] == '^':
		c := s[1]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c >= '@' && c <= '_' {
			return c - '@', nil
		}
	case len(s) == 1 && s[0] < 0x80:
		return s[0], nil
	}
	n, err := strconv.ParseUint(s, 0, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid character value %q", s)
	}
	return uint8(n), nil
}

func makeRawTermios(t *unix.Termios) {
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.IGNPAR | unix.PARMRK | unix.INPCK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.IXOFF | unix.IXANY | unix.IMAXBEL
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ISIG | unix.ICANON | unix.IEXTEN | unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHONL
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
}

func makeCookedTermios(t *unix.Termios) {
	t.Iflag |= unix.BRKINT | unix.ICRNL | unix.IXON
	t.Oflag |= unix.OPOST
	t.Lflag |= unix.ISIG | unix.ICANON | unix.IEXTEN | unix.ECHO | unix.ECHOE | unix.ECHOK
}

// formatSave is the stty -g form: iflag:oflag:cflag:lflag then each cc, hex.
func formatSave(t *unix.Termios) string {
	parts := []string{
		strconv.FormatUint(uint64(t.Iflag), 16),
		strconv.FormatUint(uint64(t.Oflag), 16),
		strconv.FormatUint(uint64(t.Cflag), 16),
		strconv.FormatUint(uint64(t.Lflag), 16),
	}
	for _, c := range t.Cc {
		parts = append(parts, strconv.FormatUint(uint64(c), 16))
	}
	return strings.Join(parts, ":")
}

// parseSave applies a stty -g string to t. t is unchanged on error.
func parseSave(t *unix.Termios, s string) error {
	parts := strings.Split(s, ":")
	if len(parts) != 4+len(t.Cc) {
		return errors.New("invalid saved settings: wrong field count")
	}
	var words [4]tcflag
	for i := range words {
		v, err := strconv.ParseUint(parts[i], 16, tcflagBits)
		if err != nil {
			return errors.New("invalid saved settings")
		}
		words[i] = tcflag(v)
	}
	var cc [len(t.Cc)]uint8
	for i := range cc {
		v, err := strconv.ParseUint(parts[4+i], 16, 8)
		if err != nil {
			return errors.New("invalid saved settings")
		}
		cc[i] = uint8(v)
	}
	t.Iflag, t.Oflag, t.Cflag, t.Lflag = words[0], words[1], words[2], words[3]
	t.Cc = cc
	return nil
}

func formatAll(w io.Writer, t *unix.Termios, rows, cols int) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "rows %d; columns %d;\n", rows, cols)
	for i, c := range ttyChars {
		if i > 0 {
			sb.WriteString(" ")
		}
		fmt.Fprintf(&sb, "%s = %s;", c.name, formatCC(t.Cc[c.index]))
	}
	fmt.Fprintf(&sb, " min = %d; time = %d;\n", t.Cc[unix.VMIN], t.Cc[unix.VTIME])
	for _, word := range []byte{'i', 'o', 'c', 'l'} {
		first := true
		for _, f := range ttyFlags {
			if f.word != word {
				continue
			}
			if !first {
				sb.WriteString(" ")
			}
			first = false
			if *flagWord(t, word)&tcflag(f.mask) == 0 {
				sb.WriteString("-")
			}
			sb.WriteString(f.name)
		}
		sb.WriteString("\n")
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// IsControllingTTY reports whether f is the calling process's controlling
// terminal: a terminal (termios reads) that also answers TIOCGPGRP, which
// Linux and Darwin refuse with ENOTTY on any terminal but the caller's
// controlling one. The termios check is needed because Darwin pipes answer
// TIOCGPGRP. (Comparing f with /dev/tty does not work: /dev/tty is its own
// device.)
func IsControllingTTY(f *os.File) bool {
	raw, err := f.SyscallConn()
	if err != nil {
		return false
	}
	var ioErr error
	if err := raw.Control(func(fd uintptr) {
		if _, ioErr = SaveTermios(int(fd)); ioErr != nil {
			return
		}
		_, ioErr = unix.IoctlGetInt(int(fd), unix.TIOCGPGRP)
	}); err != nil {
		return false
	}
	return ioErr == nil
}

// Stty runs stty on the terminal at fd. Every operand is parsed before the
// terminal is changed; a bad operand changes nothing.
func Stty(fd int, args []string, out io.Writer) error {
	t, err := SaveTermios(fd)
	if err != nil {
		return errors.New("stty: standard input: not a terminal")
	}
	orig := *t
	if len(args) == 0 {
		args = []string{"-a"}
	}
	var printAll, printSave, printSize, setting bool
	rows, cols := -1, -1
	value := func(i int, name string) (string, error) {
		if i >= len(args) {
			return "", fmt.Errorf("stty: missing argument to %q", name)
		}
		return args[i], nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-a", "--all":
			printAll = true
		case "-g", "--save":
			printSave = true
		case "size":
			printSize = true
		default:
			setting = true
		}
		switch {
		case a == "-a" || a == "--all", a == "-g" || a == "--save", a == "size":
		case a == "sane":
			saneTermios(t)
		case a == "raw" || a == "-cooked":
			makeRawTermios(t)
		case a == "-raw" || a == "cooked":
			makeCookedTermios(t)
		case a == "rows" || a == "cols" || a == "columns" || a == "min" || a == "time":
			i++
			v, err := value(i, a)
			if err != nil {
				return err
			}
			n, err := strconv.ParseUint(v, 10, 16)
			if err != nil || ((a == "min" || a == "time") && n > 255) || ((a == "rows" || a == "cols" || a == "columns") && (n == 0 || n > maxPTYDim)) {
				return fmt.Errorf("stty: invalid %s value %q", a, v)
			}
			switch a {
			case "rows":
				rows = int(n)
			case "cols", "columns":
				cols = int(n)
			case "min":
				t.Cc[unix.VMIN] = uint8(n)
			case "time":
				t.Cc[unix.VTIME] = uint8(n)
			}
		case strings.Contains(a, ":"):
			if err := parseSave(t, a); err != nil {
				return fmt.Errorf("stty: %v", err)
			}
		default:
			if c, ok := lookupChar(a); ok {
				i++
				v, err := value(i, a)
				if err != nil {
					return err
				}
				b, err := parseCC(v)
				if err != nil {
					return fmt.Errorf("stty: %s: %v", a, err)
				}
				t.Cc[c.index] = b
				continue
			}
			on := !strings.HasPrefix(a, "-")
			f, ok := lookupFlag(strings.TrimPrefix(a, "-"))
			if !ok {
				return fmt.Errorf("stty: invalid argument %q", a)
			}
			setFlag(t, f, on)
		}
	}
	output := printAll || printSave || printSize
	if output && setting {
		return errors.New("stty: when specifying an output style, modes may not be set")
	}
	if output && btoi(printAll)+btoi(printSave)+btoi(printSize) > 1 {
		return errors.New("stty: choose one of -a, -g, and size")
	}
	switch {
	case printSave:
		_, err := fmt.Fprintln(out, formatSave(t))
		return err
	case printSize:
		r, c, err := GetTerminalSize(fd)
		if err != nil {
			return fmt.Errorf("stty: %v", err)
		}
		_, err = fmt.Fprintf(out, "%d %d\n", r, c)
		return err
	case printAll:
		r, c, _ := GetTerminalSize(fd)
		return formatAll(out, t, r, c)
	}
	if *t != orig {
		if err := RestoreTermios(fd, t); err != nil {
			return fmt.Errorf("stty: %v", err)
		}
	}
	if rows >= 0 || cols >= 0 {
		if err := SetWinsize(fd, max(rows, 0), max(cols, 0)); err != nil {
			return fmt.Errorf("stty: %v", err)
		}
	}
	return nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SSHMode is one opcode and argument from a pty-req terminal-mode string.
type SSHMode struct {
	Op    uint8
	Value uint32
}

// ParseSSHModes decodes an RFC 4254 section 8 encoded terminal-mode string.
func ParseSSHModes(s string) ([]SSHMode, error) {
	b := []byte(s)
	var out []SSHMode
	for len(b) > 0 {
		op := b[0]
		b = b[1:]
		if op == 0 || op >= 160 {
			break
		}
		if len(b) < 4 {
			return nil, errors.New("ssh terminal modes: truncated argument")
		}
		if len(out) == maxSSHModes {
			return nil, errors.New("ssh terminal modes: too many opcodes")
		}
		m := SSHMode{Op: op, Value: binary.BigEndian.Uint32(b)}
		b = b[4:]
		if c, ok := charBySSHOp(op); ok && m.Value > 255 {
			return nil, fmt.Errorf("ssh terminal modes: %s value %d is not a byte", c.name, m.Value)
		}
		out = append(out, m)
	}
	return out, nil
}

// ApplySSHModes sets t from modes that ParseSSHModes accepted.
func ApplySSHModes(t *unix.Termios, modes []SSHMode) {
	for _, m := range modes {
		if c, ok := charBySSHOp(m.Op); ok {
			v := uint8(m.Value)
			if v == 255 {
				// OpenSSH sends 255 for a disabled character.
				v = vdisable
			}
			t.Cc[c.index] = v
			continue
		}
		if f, ok := flagBySSHOp(m.Op); ok {
			setFlag(t, f, m.Value != 0)
		}
	}
}

func charBySSHOp(op uint8) (ttyChar, bool) {
	for _, c := range ttyChars {
		if c.sshOp == op {
			return c, true
		}
	}
	return ttyChar{}, false
}

func flagBySSHOp(op uint8) (ttyFlag, bool) {
	if op == 0 {
		return ttyFlag{}, false
	}
	for _, f := range ttyFlags {
		if f.sshOp == op {
			return f, true
		}
	}
	return ttyFlag{}, false
}

// applySSHModesFile applies the client's modes to the terminal f.
func applySSHModesFile(f *os.File, modes []SSHMode) error {
	if len(modes) == 0 {
		return nil
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ioErr error
	if err := raw.Control(func(fd uintptr) {
		t, err := SaveTermios(int(fd))
		if err != nil {
			ioErr = err
			return
		}
		ApplySSHModes(t, modes)
		ioErr = RestoreTermios(int(fd), t)
	}); err != nil {
		return err
	}
	return ioErr
}
