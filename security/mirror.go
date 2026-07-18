package security

import (
	"context"
	"fmt"
	"github.com/afterdarksys/adssh/internal/sys"
	"io"

	"mvdan.cc/sh/v3/interp"
)

// mirror — live session viewer and console

type mirrorBinary struct{}

func (mirrorBinary) Name() string { return "mirror" }
func (mirrorBinary) Description() string {
	return "Session mirroring — view or take console of an active shell session"
}
func (mirrorBinary) Usage() string { return "mirror <list|view|console> [session_id]" }

func (mirrorBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)

	if len(args) < 2 {
		return fmt.Errorf("mirror: %s", mirrorBinary{}.Usage())
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
		return fmt.Errorf("mirror: usage: mirror %s <session_id>", command)
	}

	targetID := args[2]
	session := sys.GetSession(targetID)
	if session == nil {
		return fmt.Errorf("mirror: session not found: %s", targetID)
	}

	switch command {
	case "view":
		fmt.Fprintf(hc.Stdout, "Attached to session %s (View Only). Press Ctrl+C to exit.\r\n", targetID)
		session.Out.AddListener(hc.Stdout)
		defer session.Out.RemoveListener(hc.Stdout)
		<-ctx.Done()
		fmt.Fprintf(hc.Stdout, "\r\nDetached from session %s\r\n", targetID)
		return nil

	case "console":
		fmt.Fprintf(hc.Stdout, "Attached to session %s (Console). Press Ctrl+C to exit.\r\n", targetID)
		session.Out.AddListener(hc.Stdout)
		defer session.Out.RemoveListener(hc.Stdout)
		go func() { _, _ = io.Copy(session.PTYMaster, hc.Stdin) }() // best-effort: stream ends on session close
		<-ctx.Done()
		fmt.Fprintf(hc.Stdout, "\r\nDetached from session %s\r\n", targetID)
		return nil

	default:
		return fmt.Errorf("mirror: unknown command: %s", command)
	}
}

func init() { Register(mirrorBinary{}) }
