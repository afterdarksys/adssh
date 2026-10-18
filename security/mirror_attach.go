package security

// Attaching to a session with mirror view/console (core). A user may attach
// to their own session in every build. Attaching to another user's session,
// by privileged supervision or a mirror share grant, is enterprise
// (mirror_share_ee.go) and plugs in through mirrorPeerAccess.

import (
	"context"
	"fmt"
	"io"

	"github.com/afterdarksys/adssh/internal/sys"
)

// mirrorPeerAccess decides an attach to a session the caller does not own.
// It returns how access was granted ("privileged", "grant") or a refusal.
// The core build refuses every such attach.
var mirrorPeerAccess = func(pctx, target PolicyContext, targetID string, console bool) (string, error) {
	return "", fmt.Errorf("mirror: %s may attach only to their own sessions; supervising or sharing another user's session is part of the adssh enterprise build", pctx.User)
}

func mirrorMode(console bool) string {
	if console {
		return "console"
	}
	return "view"
}

// mirrorAccess decides whether the caller may attach to targetID and how.
func (e *Engine) mirrorAccess(callerSessionID, targetID string, console bool) (caller string, via string, err error) {
	if sys.GetSession(targetID) == nil {
		return "", "", fmt.Errorf("mirror: session not found: %s", targetID)
	}
	pctx := e.buildPolicyContext("mirror", nil, callerSessionID)
	if pctx.IdentityUnknown || pctx.User == "" {
		return "", "", fmt.Errorf("mirror: session identity unknown")
	}
	if pctx.Agent != nil {
		return pctx.User, "", fmt.Errorf("mirror: agent sessions cannot attach")
	}
	target := e.buildPolicyContext("mirror", nil, targetID)
	if !target.IdentityUnknown && target.User != "" && target.User == pctx.User {
		return pctx.User, "owner", nil
	}
	via, err = mirrorPeerAccess(pctx, target, targetID, console)
	return pctx.User, via, err
}

// mirrorAuthorize is mirrorAccess with the refusal audited.
func (e *Engine) mirrorAuthorize(callerSessionID, targetID string, console bool) error {
	_, err := e.mirrorAuthorizeVia(callerSessionID, targetID, console)
	return err
}

func (e *Engine) mirrorAuthorizeVia(callerSessionID, targetID string, console bool) (string, error) {
	caller, via, err := e.mirrorAccess(callerSessionID, targetID, console)
	if err != nil {
		if auditErr := e.LogEvent(fmt.Sprintf("MIRROR_DENIED: session=%s user=%s mode=%s reason=%q",
			targetID, emptyDash(caller), mirrorMode(console), err.Error())); auditErr != nil {
			return "", fmt.Errorf("%v (audit: %v)", err, auditErr)
		}
		return "", err
	}
	if err := e.LogEvent(fmt.Sprintf("MIRROR_ATTACH: session=%s user=%s mode=%s via=%s",
		targetID, caller, mirrorMode(console), via)); err != nil {
		return "", fmt.Errorf("mirror: audit log failed: %w", err)
	}
	return via, nil
}

// mirrorAttach authorizes and then streams targetID's output to out until
// ctx ends. With console, stdin is copied to the session's terminal.
func (e *Engine) mirrorAttach(ctx context.Context, callerSessionID, targetID string, console bool, out io.Writer, in io.Reader) error {
	if _, err := e.mirrorAuthorizeVia(callerSessionID, targetID, console); err != nil {
		return err
	}
	session := sys.GetSession(targetID)
	if session == nil {
		return fmt.Errorf("mirror: session not found: %s", targetID)
	}
	if err := mirrorStreamable(session, console, in); err != nil {
		return err
	}
	label := "View Only"
	if console {
		label = "Console"
	}
	fmt.Fprintf(out, "Attached to session %s (%s). Press Ctrl+C to exit.\r\n", targetID, label)
	mirrorStream(ctx, session, console, out, in)
	fmt.Fprintf(out, "\r\nDetached from session %s\r\n", targetID)
	return nil
}

// mirrorStreamable reports why session cannot be streamed, or nil.
func mirrorStreamable(session *sys.Session, console bool, in io.Reader) error {
	if session.Out == nil {
		return fmt.Errorf("mirror: session %s has no output stream", session.ID)
	}
	if console && (session.PTYMaster == nil || in == nil) {
		return fmt.Errorf("mirror: session %s has no terminal", session.ID)
	}
	return nil
}

// mirrorStream copies session output to out and, with console, in to the
// session's terminal, until ctx ends. mirror view/console and the admin
// attach endpoint both stream through here; the session recording sees
// console input as the terminal echoes it, as for any other keystroke.
func mirrorStream(ctx context.Context, session *sys.Session, console bool, out io.Writer, in io.Reader) {
	session.Out.AddListener(out)
	defer session.Out.RemoveListener(out)
	if console {
		go func() { _, _ = io.Copy(session.PTYMaster, in) }() // best-effort: stream ends on session close
	}
	<-ctx.Done()
}
