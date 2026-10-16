package security

import (
	"context"
	"fmt"
	"github.com/afterdarksys/adssh/internal/sys"
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
func (mirrorBinary) Usage() string {
	return "mirror <list|view|console|kill> [session_id] | mirror share --with <user> --for <duration> [--console] | mirror unshare [--with <user>]"
}

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

	switch command {
	case "share":
		grantee, duration, console, err := parseMirrorShareArgs(args[2:])
		if err != nil {
			return err
		}
		sessionID := SessionIDFromContext(ctx)
		if err := engineFromContext(ctx).shareMirror(sessionID, grantee, duration, console); err != nil {
			return err
		}
		fmt.Fprintf(hc.Stdout, "Shared session %s with %s (%s) for %s\n", sessionID, grantee, mirrorMode(console), duration)
		return nil
	case "unshare":
		grantee := ""
		switch {
		case len(args) == 2:
		case len(args) == 4 && args[2] == "--with":
			grantee = args[3]
		default:
			return fmt.Errorf("mirror: usage: mirror unshare [--with <user>]")
		}
		n, err := engineFromContext(ctx).unshareMirror(SessionIDFromContext(ctx), grantee)
		if err != nil {
			return err
		}
		fmt.Fprintf(hc.Stdout, "Revoked %d mirror grant(s)\n", n)
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
		if err := engineFromContext(ctx).LogEvent(fmt.Sprintf("MIRROR_KILL: session=%s", targetID)); err != nil {
			return fmt.Errorf("mirror: kill not recorded, session left running: %w", err)
		}
		session.Terminate()
		fmt.Fprintf(hc.Stdout, "Terminated session %s\r\n", targetID)
		return nil

	case "view", "console":
		return engineFromContext(ctx).mirrorAttach(ctx, SessionIDFromContext(ctx), targetID, command == "console", hc.Stdout, hc.Stdin)

	default:
		return fmt.Errorf("mirror: unknown command: %s", command)
	}
}

// parseMirrorShareArgs parses --with <user> --for <duration> [--console].
func parseMirrorShareArgs(args []string) (string, time.Duration, bool, error) {
	usage := fmt.Errorf("mirror: usage: mirror share --with <user> --for <duration> [--console]")
	var grantee, forValue string
	console := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--with", "--for":
			if i+1 >= len(args) {
				return "", 0, false, usage
			}
			if args[i] == "--with" {
				grantee = args[i+1]
			} else {
				forValue = args[i+1]
			}
			i++
		case "--console":
			console = true
		default:
			return "", 0, false, fmt.Errorf("mirror share: unknown argument %q", args[i])
		}
	}
	if grantee == "" || forValue == "" {
		return "", 0, false, usage
	}
	duration, err := time.ParseDuration(forValue)
	if err != nil {
		return "", 0, false, fmt.Errorf("mirror share: invalid --for %q", forValue)
	}
	return grantee, duration, console, nil
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
