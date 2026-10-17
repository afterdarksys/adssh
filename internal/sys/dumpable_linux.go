//go:build linux

package sys

import "golang.org/x/sys/unix"

// SetNonDumpable clears this process's dumpable flag. /proc/<pid> then
// belongs to root, so another process with the same uid can neither read
// its environment nor ptrace it. It lasts until this process execs another
// program, so a command the session runs is not covered.
func SetNonDumpable() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
