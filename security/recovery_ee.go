//go:build ee

// Threats: recovery is a fixed menu. It refuses to start when the audit
// chain cannot be written. It does not open a root shell. restart accepts
// only the configured agent unit, never a shell or sshd. Unknown lines and
// a missing verb are refused and the menu continues.
// Non-goals: recovery is not an allow-all and does not start sshd.

package security

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// errRecoveryRefused is the missing-verb sentinel. Lookup returns it before
// the shell runner so a wrapper cannot hide it.
var errRecoveryRefused = errors.New("recovery: refused")

// RunRecovery prints the recovery menu and dispatches one verb per line.
// A chain that is off, or a RECOVERY_OPEN record that cannot be written,
// returns 2 before in is read.
func RunRecovery(ctx context.Context, sec *Engine, sessionID string, in io.Reader, out io.Writer) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if sec == nil || !sec.ChainEnabled() {
		return 2, nil
	}
	if err := sec.LogEvent("RECOVERY_OPEN"); err != nil {
		return 2, err
	}
	if out == nil {
		out = io.Discard
	}
	if in == nil {
		return 2, nil
	}
	if _, err := fmt.Fprint(out, "network\ndisk\njournal\nrestart\nquit\n"); err != nil {
		return 2, err
	}
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		var argv []string
		switch fields[0] {
		case "quit":
			if len(fields) != 1 {
				fmt.Fprintln(out, "recovery: refused")
				continue
			}
			return 0, nil
		case "network":
			if len(fields) != 1 {
				fmt.Fprintln(out, "recovery: refused")
				continue
			}
			argv = []string{"net"}
		case "disk":
			if len(fields) != 1 {
				fmt.Fprintln(out, "recovery: refused")
				continue
			}
			argv = []string{"disk"}
		case "journal":
			if len(fields) != 1 {
				fmt.Fprintln(out, "recovery: refused")
				continue
			}
			argv = []string{"journal"}
		case "restart":
			if len(fields) != 2 || !recoveryRestartOK(fields[1]) {
				fmt.Fprintln(out, "recovery: refused")
				continue
			}
			argv = []string{"unit", "restart", fields[1]}
		default:
			fmt.Fprintln(out, "recovery: refused")
			continue
		}
		err := recoveryDispatch(ctx, sec, sessionID, argv, out)
		if err == nil {
			continue
		}
		if errors.Is(err, errRecoveryRefused) {
			fmt.Fprintln(out, "recovery: refused")
			continue
		}
		fmt.Fprintf(out, "%v\n", err)
	}
	if err := sc.Err(); err != nil {
		return 2, err
	}
	return 0, nil
}

func recoveryRestartOK(name string) bool {
	want := os.Getenv("ADSSH_AGENT_UNIT")
	if want == "" || name != want || !unitNamePattern.MatchString(name) {
		return false
	}
	switch path.Base(name) {
	case "bash", "sh", "zsh", "dash", "fish", "su", "sshd":
		return false
	default:
		return true
	}
}

func recoveryDispatch(ctx context.Context, sec *Engine, sessionID string, argv []string, out io.Writer) error {
	if out == nil {
		out = io.Discard
	}
	if len(argv) == 0 {
		return errRecoveryRefused
	}
	vb, ok := Lookup(argv[0])
	if !ok {
		return errRecoveryRefused
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("adssh-recovery-dispatch"), "adssh-recovery-dispatch")
	if err != nil {
		return err
	}
	runner, err := interp.New(
		interp.StdIO(nil, out, out),
		interp.ExecHandler(func(hctx context.Context, _ []string) error {
			hctx = WithRecover(WithSessionID(hctx, sessionID))
			return sec.DispatchVBin(hctx, vb, argv)
		}),
	)
	if err != nil {
		return err
	}
	return runner.Run(ctx, file)
}
