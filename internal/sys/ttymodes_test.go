//go:build linux || darwin

package sys

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func openTTY(t *testing.T) (*os.File, int) {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty unavailable: %v", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	if err := pty.Setsize(master, &pty.Winsize{Rows: 24, Cols: 80}); err != nil {
		t.Fatal(err)
	}
	fd := int(slave.Fd())
	if err := MakeSane(fd); err != nil {
		t.Fatal(err)
	}
	return slave, fd
}

func termiosOf(t *testing.T, fd int) unix.Termios {
	t.Helper()
	tio, err := SaveTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	return *tio
}

func runStty(t *testing.T, fd int, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := Stty(fd, args, &out)
	return out.String(), err
}

func TestSttyAppliesEveryOperand(t *testing.T) {
	_, fd := openTTY(t)
	if _, err := runStty(t, fd, "-echo", "-icanon", "min", "0", "time", "5", "erase", "^H", "intr", "undef", "-ixon", "rows", "40", "cols", "120"); err != nil {
		t.Fatal(err)
	}
	tio := termiosOf(t, fd)
	if tio.Lflag&unix.ECHO != 0 || tio.Lflag&unix.ICANON != 0 || tio.Iflag&unix.IXON != 0 {
		t.Fatalf("flags not cleared: lflag %x iflag %x", tio.Lflag, tio.Iflag)
	}
	if tio.Cc[unix.VMIN] != 0 || tio.Cc[unix.VTIME] != 5 || tio.Cc[unix.VERASE] != 8 || tio.Cc[unix.VINTR] != vdisable {
		t.Fatalf("cc not set: min %d time %d erase %d intr %d", tio.Cc[unix.VMIN], tio.Cc[unix.VTIME], tio.Cc[unix.VERASE], tio.Cc[unix.VINTR])
	}
	if r, c, _ := GetTerminalSize(fd); r != 40 || c != 120 {
		t.Fatalf("size %d %d, want 40 120", r, c)
	}
	if out, _ := runStty(t, fd, "size"); out != "40 120\n" {
		t.Fatalf("size printed %q", out)
	}
}

func TestSttyBadOperandChangesNothing(t *testing.T) {
	_, fd := openTTY(t)
	before := termiosOf(t, fd)
	for _, args := range [][]string{
		{"-echo", "bogus"},
		{"-echo", "erase"},
		{"-icanon", "erase", "^1"},
		{"-echo", "min", "256"},
		{"-echo", "rows", "0"},
		{"-echo", "time", "-1"},
		{"-echo", "-F"},
		{"-echo", "-a"},
		{"-echo", "1:2:3"},
	} {
		if _, err := runStty(t, fd, args...); err == nil {
			t.Errorf("stty %v: want an error", args)
		}
		if got := termiosOf(t, fd); got != before {
			t.Fatalf("stty %v changed the terminal after an error", args)
		}
	}
}

func TestSttySaveRoundTripAndTamper(t *testing.T) {
	_, fd := openTTY(t)
	saved, err := runStty(t, fd, "-g")
	if err != nil {
		t.Fatal(err)
	}
	saved = strings.TrimSpace(saved)
	want := termiosOf(t, fd)
	if _, err := runStty(t, fd, "raw", "-echo", "erase", "^H"); err != nil {
		t.Fatal(err)
	}
	if _, err := runStty(t, fd, saved); err != nil {
		t.Fatal(err)
	}
	if got := termiosOf(t, fd); got != want {
		t.Fatal("restore from -g did not return the saved settings")
	}
	_, _ = runStty(t, fd, "-echo")
	changed := termiosOf(t, fd)
	parts := strings.Split(saved, ":")
	for name, bad := range map[string]string{
		"short":   strings.Join(parts[:len(parts)-1], ":"),
		"long":    saved + ":0",
		"not hex": strings.Replace(saved, parts[0], "zz", 1),
		"cc wide": strings.Join(append(append([]string{}, parts[:4]...), append([]string{"100"}, parts[5:]...)...), ":"),
	} {
		if _, err := runStty(t, fd, bad); err == nil {
			t.Errorf("%s -g string accepted", name)
		}
		if got := termiosOf(t, fd); got != changed {
			t.Fatalf("%s -g string changed the terminal", name)
		}
	}
}

func TestSttyAllListsSettings(t *testing.T) {
	_, fd := openTTY(t)
	out, err := runStty(t, fd, "-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"rows 24; columns 80;", "intr = ^C;", "erase = ^?;", "eol = <undef>;", "min = 1; time = 0;", " icanon", " echo", "icrnl", "opost"} {
		if !strings.Contains(out, want) {
			t.Errorf("stty -a missing %q:\n%s", want, out)
		}
	}
	if noArgs, _ := runStty(t, fd); noArgs != out {
		t.Error("stty with no operands differs from stty -a")
	}
}

func TestSttyNotATerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err := runStty(t, int(r.Fd()), "-echo"); err == nil || !strings.Contains(err.Error(), "not a terminal") {
		t.Fatalf("got %v, want not a terminal", err)
	}
}

func TestParseCC(t *testing.T) {
	for in, want := range map[string]uint8{"^C": 3, "^c": 3, "^?": 0x7f, "^@": 0, "^[": 0x1b, "x": 'x', "0x1b": 0x1b, "033": 0x1b, "27": 27, "undef": vdisable, "^-": vdisable, "^": '^'} {
		got, err := parseCC(in)
		if err != nil || got != want {
			t.Errorf("parseCC(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "^1", "256", "ab", "é"} {
		if _, err := parseCC(in); err == nil {
			t.Errorf("parseCC(%q) accepted", in)
		}
	}
}

func encodeModes(ops ...SSHMode) string {
	var b []byte
	for _, m := range ops {
		b = append(b, m.Op)
		b = binary.BigEndian.AppendUint32(b, m.Value)
	}
	return string(append(b, 0))
}

func TestParseSSHModes(t *testing.T) {
	good := encodeModes(SSHMode{ssh.VERASE, 8}, SSHMode{ssh.ECHO, 0}, SSHMode{200 - 99, 7}, SSHMode{ssh.TTY_OP_ISPEED, 38400})
	modes, err := ParseSSHModes(good)
	if err != nil || len(modes) != 4 {
		t.Fatalf("got %v %v, want 4 modes", modes, err)
	}
	// Opcode 160 and above ends parsing; what follows is not read.
	stop := string([]byte{ssh.ECHO, 0, 0, 0, 1, 160, 1, 2})
	if modes, err := ParseSSHModes(stop); err != nil || len(modes) != 1 {
		t.Fatalf("stop opcode: got %v %v", modes, err)
	}
	for name, bad := range map[string]string{
		"truncated":   string([]byte{ssh.ECHO, 0, 0}),
		"char > byte": encodeModes(SSHMode{ssh.VINTR, 256}),
		"too many":    strings.Repeat(string([]byte{ssh.ECHO, 0, 0, 0, 1}), maxSSHModes+1),
	} {
		if _, err := ParseSSHModes(bad); err == nil {
			t.Errorf("%s modes accepted", name)
		}
	}
}

func TestApplySSHModesToPTY(t *testing.T) {
	slave, fd := openTTY(t)
	modes, err := ParseSSHModes(encodeModes(
		SSHMode{ssh.VERASE, 8},
		SSHMode{ssh.VINTR, 255}, // OpenSSH: disabled
		SSHMode{ssh.ECHO, 0},
		SSHMode{ssh.ICRNL, 0},
		SSHMode{ssh.IUTF8, 1},
		SSHMode{ssh.CS8, 1},              // ignored: no parity or size on a pty
		SSHMode{ssh.TTY_OP_OSPEED, 9600}, // ignored
		SSHMode{120, 1},                  // unknown, skipped
	))
	if err != nil {
		t.Fatal(err)
	}
	before := termiosOf(t, fd)
	if err := applySSHModesFile(slave, modes); err != nil {
		t.Fatal(err)
	}
	tio := termiosOf(t, fd)
	if tio.Cc[unix.VERASE] != 8 || tio.Cc[unix.VINTR] != vdisable {
		t.Fatalf("erase %d intr %d", tio.Cc[unix.VERASE], tio.Cc[unix.VINTR])
	}
	if tio.Lflag&unix.ECHO != 0 || tio.Iflag&unix.ICRNL != 0 || tio.Iflag&unix.IUTF8 == 0 {
		t.Fatalf("flags lflag %x iflag %x", tio.Lflag, tio.Iflag)
	}
	if tio.Cflag != before.Cflag {
		t.Fatal("client modes changed cflag")
	}
}

func TestHandlePTYRequestModes(t *testing.T) {
	good := ptyPayload("xterm", 100, 30, encodeModes(SSHMode{ssh.ECHO, 0}))
	var sized, moded int
	setSize := func(*pty.Winsize) error { sized++; return nil }
	setModes := func([]SSHMode) error { moded++; return nil }

	if !handlePTYRequest(false, setSize, setModes, []byte(good)) || sized != 1 || moded != 1 {
		t.Fatalf("before shell: sized %d moded %d, want both applied", sized, moded)
	}
	// After the shell starts, a pty-req resizes but leaves termios alone.
	if !handlePTYRequest(true, setSize, setModes, []byte(good)) || sized != 2 || moded != 1 {
		t.Fatalf("after shell: sized %d moded %d, want resize only", sized, moded)
	}
	// A bad mode string refuses the request and applies nothing.
	bad := ptyPayload("xterm", 100, 30, string([]byte{ssh.ECHO, 0, 0}))
	if handlePTYRequest(false, setSize, setModes, []byte(bad)) || sized != 2 || moded != 1 {
		t.Fatalf("bad modes: sized %d moded %d, want nothing applied", sized, moded)
	}
	// A failure to set the modes refuses the request.
	if handlePTYRequest(false, setSize, func([]SSHMode) error { return os.ErrInvalid }, []byte(good)) {
		t.Fatal("setModes error accepted")
	}
}

func TestSttyOutputStyleRefusesSettingsAndCapsSize(t *testing.T) {
	_, fd := openTTY(t)
	before := termiosOf(t, fd)
	for _, args := range [][]string{{"-a", "sane"}, {"-g", "echo"}, {"size", "rows", "30"}, {"-a", "-g"}, {"rows", "1001"}, {"cols", "65535"}} {
		if _, err := runStty(t, fd, args...); err == nil {
			t.Errorf("stty %v accepted", args)
		}
	}
	if termiosOf(t, fd) != before {
		t.Fatal("a refused stty changed the terminal")
	}
	if r, c, _ := GetTerminalSize(fd); r != 24 || c != 80 {
		t.Fatalf("a refused stty resized to %d %d", r, c)
	}
	if _, err := runStty(t, fd, "rows", "1000", "cols", "1000"); err != nil {
		t.Fatalf("maxPTYDim refused: %v", err)
	}
}

func TestIsControllingTTY(t *testing.T) {
	if os.Getenv("ADSSH_TEST_CTTY_CHILD") == "1" {
		if !IsControllingTTY(os.Stdin) {
			os.Exit(3)
		}
		os.Exit(0)
	}
	slave, _ := openTTY(t)
	if IsControllingTTY(slave) {
		t.Fatal("a pty that is not this process's terminal counted as controlling")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if IsControllingTTY(r) {
		t.Fatal("a pipe counted as controlling")
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestIsControllingTTY$")
	cmd.Env = append(os.Environ(), "ADSSH_TEST_CTTY_CHILD=1")
	master, err := pty.Start(cmd) // the child gets the pty as its controlling terminal
	if err != nil {
		t.Skipf("pty unavailable: %v", err)
	}
	defer master.Close()
	go func() { _, _ = io.Copy(io.Discard, master) }()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child with the pty as its terminal: %v", err)
	}
}
