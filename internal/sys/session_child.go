//go:build unix

package sys

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

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

// runSessionChild returns nil when --session-child is absent. Limits are
// parsed and applied before the command tail is checked. A bad key, a bad
// value, a missing "=", a missing "--", or a setrlimit error returns before
// execProcess.
func runSessionChild(args []string) error {
	idx := -1
	for i, a := range args {
		if a == "--session-child" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	rest := args[idx+1:]
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
	return execProcess(target, argv, os.Environ())
}

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
	next := cur
	if cur.Max != unix.RLIM_INFINITY && value > cur.Max {
		next.Cur = cur.Max
	} else {
		next.Cur = value
		next.Max = cur.Max
	}
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
// before the original argv. It does not rewrite when a limit is already being
// applied, when every limit is zero, or when this process is a go test.
// executable failure leaves Path and Args unchanged.
func wrapSessionLimits(cmd *exec.Cmd) error {
	if runningUnderTest() {
		return nil
	}
	for _, a := range cmd.Args {
		if a == "--session-child" {
			return nil
		}
	}
	limits := sessionLimits()
	if !limits.any() {
		return nil
	}
	exe, err := executable()
	if err != nil {
		return fmt.Errorf("adssh: session child: %w", err)
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
