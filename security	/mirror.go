package security

import (
	"adssh/sys"
	"context"
	"fmt"
	"io"
	"mvdan.cc/sh/v3/interp"
)

func runMirrorCommand(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)

	if len(args) < 2 {
		return fmt.Errorf("usage: mirror <list|view|console> [session_id]")
	}

	command := args[1]

	if command == "list" {
		sessions := sys.ListSessions()
		fmt.Fprintln(hc.Stdout, "Active Sessions:")
		for _, s := range sessions {
			fmt.Fprintf(hc.Stdout, "  - %s\n", s)
		}
		return nil
	}

	if len(args) < 3 {
		return fmt.Errorf("usage: mirror %s <session_id>", command)
	}

	targetID := args[2]
	session := sys.GetSession(targetID)
	if session == nil {
		return fmt.Errorf("session not found: %s", targetID)
	}

	// We are attaching to a session.
	// To exit, we rely on context cancellation (e.g. Ctrl+C which cancels the Runner context).

	if command == "view" {
		fmt.Fprintf(hc.Stdout, "Attached to session %s (View Only). Press Ctrl+C to exit.\r\n", targetID)

		session.Out.AddListener(hc.Stdout)
		defer session.Out.RemoveListener(hc.Stdout)

		<-ctx.Done()
		fmt.Fprintf(hc.Stdout, "\r\nDetached from session %s\r\n", targetID)
		return nil
	}

	if command == "console" {
		fmt.Fprintf(hc.Stdout, "Attached to session %s (Console). Press Ctrl+C to exit.\r\n", targetID)

		session.Out.AddListener(hc.Stdout)
		defer session.Out.RemoveListener(hc.Stdout)

		// Forward Stdin to the target PTY Master
		// Run this in a goroutine
		go func() {
			io.Copy(session.PTYMaster, hc.Stdin)
		}()

		<-ctx.Done()
		fmt.Fprintf(hc.Stdout, "\r\nDetached from session %s\r\n", targetID)
		return nil
	}

	return fmt.Errorf("unknown mirror command: %s", command)
}
