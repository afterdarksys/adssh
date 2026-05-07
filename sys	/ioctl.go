package sys

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

var ShellPgid int

func InitTerminal() error {
	// Put shell in its own process group
	ShellPgid = os.Getpid()
	if err := syscall.Setpgid(ShellPgid, ShellPgid); err != nil {
		return err
	}

	// Grab control of the terminal
	// Make sure the shell is the foreground process
	if err := unix.IoctlSetPointerInt(int(os.Stdin.Fd()), unix.TIOCSPGRP, ShellPgid); err != nil {
		return err
	}

	return nil
}
