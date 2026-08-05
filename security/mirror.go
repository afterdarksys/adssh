package security

import (
	"context"
	"fmt"
	"github.com/afterdarksys/adssh/internal/sys"
	"io"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"
)

// mirror — live session viewer and console

type mirrorBinary struct{}

func (mirrorBinary) Name() string { return "mirror" }
func (mirrorBinary) Description() string {
	return "Session mirroring — view or take console of an active shell session"
}
func (mirrorBinary) Usage() string { return "mirror <list|view|console|kill> [session_id]" }

func (mirrorBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)

	if len(args) < 2 {
		return fmt.Errorf("mirror: %s", mirrorBinary{}.Usage())
	}

	command := args[1]

	if command == "list" {
		sessions := sys.ListSessionInfo()
		fmt.Fprintln(hc.Stdout, "Active Sessions:")
		for _, s := range sessions {
			fmt.Fprintf(hc.Stdout, "  - %s user=%s age=%s idle=%s",
				s.ID,
				emptyDash(s.User),
				formatSessionDuration(time.Since(s.CreatedAt)),
				formatSessionDuration(time.Since(s.LastActive)),
			)
			if len(s.Principals) > 0 {
				fmt.Fprintf(hc.Stdout, " principals=%s", strings.Join(s.Principals, ","))
			}
			if s.CurrentCommand != "" {
				fmt.Fprintf(hc.Stdout, " command=%q", RedactSensitiveText(s.CurrentCommand))
			}
			if s.Recording != "" {
				fmt.Fprintf(hc.Stdout, " recording=%q", s.Recording)
			}
			if s.Elevation != nil {
				fmt.Fprintf(hc.Stdout, " elevation=%s expires=%s",
					s.Elevation.Role,
					s.Elevation.ExpiresAt.UTC().Format(time.RFC3339),
				)
			}
			if s.Terminated {
				fmt.Fprint(hc.Stdout, " terminated=true")
			}
			fmt.Fprintln(hc.Stdout)
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
	case "kill":
		session.Terminate()
		engineFromContext(ctx).LogEvent(fmt.Sprintf("MIRROR_KILL: session=%s", targetID))
		fmt.Fprintf(hc.Stdout, "Terminated session %s\r\n", targetID)
		return nil

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

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func formatSessionDuration(duration time.Duration) string {
	if duration < 0 {
		duration = 0
	}
	if duration < time.Second {
		return "0s"
	}
	return duration.Truncate(time.Second).String()
}

func init() { Register(mirrorBinary{}) }
