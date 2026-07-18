package sys

import (
	"fmt"
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

// SetWinsize applies rows and/or cols to the terminal window size.
// Pass 0 for a dimension to leave it unchanged.
func SetWinsize(fd, rows, cols int) error {
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		return fmt.Errorf("SetWinsize: %w", err)
	}
	if rows > 0 {
		ws.Row = uint16(rows)
	}
	if cols > 0 {
		ws.Col = uint16(cols)
	}
	return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, ws)
}
