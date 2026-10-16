package security

import (
	"context"
	"fmt"
	"slices"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
)

// grant — temporary role escalation
//
// Threats: request and drop change the session's principals under the
// session lock. A session whose identity is bound on the engine (an SSH
// login) keeps its bound groups for policy; grant does not add to them.
// Over an SSH Run only drop is accepted (sshListenerRuns).

type grantBinary struct{}

func (grantBinary) Name() string { return "grant" }
func (grantBinary) Description() string {
	return "Role escalation — request or drop a temporary role for the current session"
}
func (grantBinary) Usage() string { return "grant <request|drop> <role>" }

func (grantBinary) Run(ctx context.Context, args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("grant: %s", grantBinary{}.Usage())
	}

	action := args[1]
	role := args[2]
	sessionID := SessionIDFromContext(ctx)

	session := sys.GetSession(sessionID)
	if session == nil {
		return fmt.Errorf("grant: requires an active SSH session")
	}
	if session.ManagedAgent() != nil {
		return fmt.Errorf("grant: agents cannot grant roles")
	}
	if IsPrivilegedRole(role) {
		return fmt.Errorf("grant: role %q is not assumable; use elevate after an admin-audience import", role)
	}

	switch action {
	case "request":
		if slices.Contains(session.PrincipalList(), role) {
			fmt.Fprintf(interp.HandlerCtx(ctx).Stdout, "grant: role '%s' is already active\n", role)
			return nil
		}
		// Record before the change; a failed write leaves the role unassumed.
		if err := engineFromContext(ctx).LogCommand("GRANT", fmt.Sprintf("User %s requested and assumed role %s", session.User, role)); err != nil {
			return fmt.Errorf("grant: audit: %w", err)
		}
		if !session.AddPrincipal(role) {
			fmt.Fprintf(interp.HandlerCtx(ctx).Stdout, "grant: role '%s' is already active\n", role)
			return nil
		}
		fmt.Fprintf(interp.HandlerCtx(ctx).Stdout, "grant: successfully assumed role '%s'\n", role)
		return nil

	case "drop":
		if !slices.Contains(session.PrincipalList(), role) {
			return fmt.Errorf("grant: you do not currently hold role '%s'", role)
		}
		if err := engineFromContext(ctx).LogCommand("GRANT", fmt.Sprintf("User %s dropped role %s", session.User, role)); err != nil {
			return fmt.Errorf("grant: audit: %w", err)
		}
		if !session.RemovePrincipal(role) {
			return fmt.Errorf("grant: you do not currently hold role '%s'", role)
		}
		fmt.Fprintf(interp.HandlerCtx(ctx).Stdout, "grant: successfully dropped role '%s'\n", role)
		return nil

	default:
		return fmt.Errorf("grant: unsupported action '%s'", action)
	}
}

func init() { Register(grantBinary{}) }
