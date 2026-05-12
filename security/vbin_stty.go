package security

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"adssh/sys"

	"mvdan.cc/sh/v3/interp"
)

// sttyBinary implements the stty virtual binary.
//
// Supported operations:
//
//	stty              — print current terminal settings summary
//	stty sane         — restore a sensible canonical terminal state
//	stty size         — print "<rows> <cols>"
//	stty echo         — enable character echo
//	stty -echo        — disable character echo
//	stty raw          — switch to raw (non-canonical) mode
//	stty -raw         — switch back to cooked (canonical) mode
//	stty rows N       — set terminal row count
//	stty cols N       — set terminal column count
type sttyBinary struct{}

func (sttyBinary) Name() string        { return "stty" }
func (sttyBinary) Description() string { return "Query and set terminal line attributes" }
func (sttyBinary) Usage() string {
	return "stty [sane | size | echo | -echo | raw | -raw | rows N | cols N]"
}

func (sttyBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	fd := int(os.Stdin.Fd())

	// Verify stdin is a terminal before touching termios.
	if _, _, err := sys.GetTerminalSize(fd); err != nil {
		return fmt.Errorf("stty: not a terminal")
	}

	if len(args) < 2 {
		return sttyPrint(hc.Stdout, fd)
	}

	switch args[1] {
	case "sane":
		if err := sys.MakeSane(fd); err != nil {
			return fmt.Errorf("stty sane: %v", err)
		}
		return nil

	case "size":
		rows, cols, err := sys.GetTerminalSize(fd)
		if err != nil {
			return fmt.Errorf("stty size: %v", err)
		}
		fmt.Fprintf(hc.Stdout, "%d %d\n", rows, cols)
		return nil

	case "echo":
		if err := sys.SetEcho(fd, true); err != nil {
			return fmt.Errorf("stty echo: %v", err)
		}
		return nil

	case "-echo":
		if err := sys.SetEcho(fd, false); err != nil {
			return fmt.Errorf("stty -echo: %v", err)
		}
		return nil

	case "raw":
		if err := sys.SetRaw(fd, true); err != nil {
			return fmt.Errorf("stty raw: %v", err)
		}
		return nil

	case "-raw":
		if err := sys.SetRaw(fd, false); err != nil {
			return fmt.Errorf("stty -raw: %v", err)
		}
		return nil

	case "rows":
		if len(args) < 3 {
			return fmt.Errorf("stty rows: missing value")
		}
		var n int
		if _, err := fmt.Sscan(args[2], &n); err != nil || n <= 0 {
			return fmt.Errorf("stty rows: invalid value %q", args[2])
		}
		if err := sys.SetWinsize(fd, n, 0); err != nil {
			return fmt.Errorf("stty rows: %v", err)
		}
		return nil

	case "cols", "columns":
		if len(args) < 3 {
			return fmt.Errorf("stty cols: missing value")
		}
		var n int
		if _, err := fmt.Sscan(args[2], &n); err != nil || n <= 0 {
			return fmt.Errorf("stty cols: invalid value %q", args[2])
		}
		if err := sys.SetWinsize(fd, 0, n); err != nil {
			return fmt.Errorf("stty cols: %v", err)
		}
		return nil

	default:
		return fmt.Errorf("stty: unknown operand %q\nUsage: %s", args[1], sttyBinary{}.Usage())
	}
}

// sttyPrint writes a human-readable summary of current terminal settings.
func sttyPrint(w io.Writer, fd int) error {
	rows, cols, err := sys.GetTerminalSize(fd)
	if err != nil {
		rows, cols = 0, 0
	}
	flags, err := sys.TermiosFlags(fd)
	if err != nil {
		return fmt.Errorf("stty: %v", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "size %d %d\n", rows, cols)
	for _, f := range flags {
		fmt.Fprintln(&sb, f)
	}
	_, err = fmt.Fprint(w, sb.String())
	return err
}

func init() { Register(sttyBinary{}) }
