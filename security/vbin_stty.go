package security

import (
	"context"
	"errors"
	"os"

	"github.com/afterdarksys/adssh/internal/sys"

	"mvdan.cc/sh/v3/interp"
)

// sttyBinary implements the stty virtual binary on the command's standard
// input. Operands follow POSIX stty and may be combined:
//
//	stty                 — all settings (same as stty -a)
//	stty -a | -g | size  — all settings, a restorable string, or "<rows> <cols>"
//	stty SAVED           — restore a string printed by stty -g
//	stty sane | raw | -raw | cooked | -cooked
//	stty [-]FLAG ...     — icanon echo isig iexten icrnl ixon opost onlcr iutf8 ...
//	stty CHAR VALUE ...  — intr quit erase kill eof eol eol2 start stop susp
//	                       rprnt werase lnext discard; VALUE is ^X, ^?, undef, a
//	                       character, or a number
//	stty min N | time N | rows N | cols N
//
// Every operand is parsed before the terminal changes, so one bad operand
// changes nothing. There is no -F, and standard input must be the session's
// controlling terminal, so stty never reaches another terminal.
type sttyBinary struct{}

func (sttyBinary) Name() string        { return "stty" }
func (sttyBinary) Description() string { return "Query and set terminal line attributes" }
func (sttyBinary) Usage() string {
	return "stty [-a | -g | size | SAVED | sane | raw | -raw | [-]FLAG | CHAR VALUE | min N | time N | rows N | cols N]..."
}

func (sttyBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	// mvdan gives a file (a pipe in a pipeline) or nil for a closed stdin.
	// Neither falls back to the shell's own terminal.
	in, ok := hc.Stdin.(*os.File)
	if !ok || in == nil {
		return errors.New("stty: standard input: not a terminal")
	}
	// Only the session's own terminal: a redirect such as 0>/dev/pts/N must
	// not reach another one.
	if !sys.IsControllingTTY(in) {
		return errors.New("stty: standard input is not this session's terminal")
	}
	return sys.Stty(int(in.Fd()), args[1:], hc.Stdout)
}

func init() { Register(sttyBinary{}) }
