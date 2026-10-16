//go:build unix

package sys

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Threats: the --session-child re-exec applies the session rlimits before it
// execs a session command. It is honoured only as argv[1], so a user
// argument spelled --session-child neither triggers it nor skips the wrap;
// a command is treated as already wrapped only when its path is this binary
// and argv[1] is --session-child. Each limit sets the soft and the hard limit
// to min(requested, current hard), so the dropped user cannot raise it back;
// the hard limit is never raised. A zero limit is not applied. Before the
// exec, job-control and interrupt signals are caught so the exec resets them
// to the default: a session process ignores SIGINT, SIGQUIT, SIGTSTP,
// SIGTTIN and SIGTTOU for itself, and an ignored disposition would otherwise
// survive into every command. A signal that arrives between that point and
// the exec is dropped. Commands that are not wrapped (every limit zero)
// keep whatever disposition the caller had.

func init() {
	maybeRunSessionChild(os.Args)
}

// MaybeRunSessionChild replaces this process when it was re-exec'd to apply
// session rlimits. It is the first call in main. On unix, init also calls it
// before flag.Parse; a go test process does not pass --session-child, so
// init is a no-op there.
func MaybeRunSessionChild() {
	maybeRunSessionChild(os.Args)
}

func maybeRunSessionChild(args []string) {
	if err := runSessionChild(args); err != nil {
		fmt.Fprintf(os.Stderr, "adssh: session child: %v\n", err)
		os.Exit(1)
	}
}

// runSessionChild returns nil unless argv[1] is --session-child. Limits are
// parsed and applied before the command tail is checked. A bad key, a bad
// value, a missing "=", a missing "--", or a setrlimit error returns before
// execProcess.
func runSessionChild(args []string) error {
	if len(args) < 2 || args[1] != "--session-child" {
		return nil
	}
	rest := args[2:]
	var specs []string
	var tail []string
	seenDash := false
	for i, a := range rest {
		if a == "--" {
			seenDash = true
			tail = rest[i+1:]
			break
		}
		specs = append(specs, a)
	}
	for _, spec := range specs {
		key, val, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("missing '='")
		}
		n, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if err := applyOneLimit(key, n); err != nil {
			return err
		}
	}
	if !seenDash {
		return fmt.Errorf("missing '--'")
	}
	if len(tail) == 0 {
		return fmt.Errorf("missing command")
	}
	target := tail[0]
	argv := tail[1:]
	if len(argv) == 0 {
		argv = []string{target}
	}
	// A caught signal is reset to the default by execve; an ignored one is
	// not. Notify replaces an inherited SIG_IGN with the runtime handler.
	signal.Notify(make(chan os.Signal, 1), sessionDefaultSignals...)
	return execProcess(target, argv, os.Environ())
}

// sessionDefaultSignals are the signals a session command must receive with
// the default disposition.
var sessionDefaultSignals = []os.Signal{syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU}

func applyOneLimit(key string, value uint64) error {
	res, err := limitResource(key)
	if err != nil {
		return err
	}
	if value == 0 {
		return nil
	}
	var cur unix.Rlimit
	if err := getRlimit(res, &cur); err != nil {
		return err
	}
	limit := value
	if cur.Max != unix.RLIM_INFINITY && limit > cur.Max {
		limit = cur.Max
	}
	next := unix.Rlimit{Cur: limit, Max: limit}
	return setRlimit(res, &next)
}

func limitResource(key string) (int, error) {
	switch key {
	case "nofile":
		return unix.RLIMIT_NOFILE, nil
	case "nproc":
		return unix.RLIMIT_NPROC, nil
	case "as":
		return unix.RLIMIT_AS, nil
	case "fsize":
		return unix.RLIMIT_FSIZE, nil
	case "cpu":
		return unix.RLIMIT_CPU, nil
	default:
		return 0, fmt.Errorf("unknown limit %q", key)
	}
}

// wrapSessionLimits rewrites cmd to re-exec this binary with --session-child
// before the original argv. It does not rewrite a command that is already
// this binary with --session-child as argv[1], when every limit is zero, or
// when this process is a go test. executable failure leaves Path and Args
// unchanged.
func wrapSessionLimits(cmd *exec.Cmd) error {
	if runningUnderTest() {
		return nil
	}
	limits := sessionLimits()
	if !limits.any() {
		return nil
	}
	exe, err := executable()
	if err != nil {
		return fmt.Errorf("adssh: session child: %w", err)
	}
	if cmd.Path == exe && len(cmd.Args) > 1 && cmd.Args[1] == "--session-child" {
		return nil
	}
	args := []string{
		exe,
		"--session-child",
		fmt.Sprintf("nofile=%d", limits.nofile),
		fmt.Sprintf("nproc=%d", limits.nproc),
		fmt.Sprintf("as=%d", limits.as),
		fmt.Sprintf("fsize=%d", limits.fsize),
		fmt.Sprintf("cpu=%d", limits.cpu),
		"--",
		cmd.Path,
	}
	args = append(args, cmd.Args...)
	cmd.Path = exe
	cmd.Args = args
	return nil
}
