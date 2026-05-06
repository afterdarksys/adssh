package sys

import (
	"os/signal"
	"syscall"
)

// SetupSignals initializes the signal handlers for the shell
func SetupSignals() {
	// Ignore these signals so the shell doesn't exit when you press Ctrl+C or Ctrl+\
	// The child process will receive them if it's the foreground process group.
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
}
