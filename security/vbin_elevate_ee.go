//go:build ee

package security

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
)

type elevateBinary struct{}

func (elevateBinary) Name() string { return "elevate" }
func (elevateBinary) Description() string {
	return "Time-boxed break-glass elevation for the current session"
}
func (elevateBinary) Usage() string {
	return `elevate request <role> --for duration --reason text
elevate status
elevate drop

The process uid does not change. os-root, adssh-admin, and gridops are
session elevation claims. They require an admin-audience import first.`
}

func (elevateBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) < 2 {
		return fmt.Errorf("elevate: usage: %s", elevateBinary{}.Usage())
	}
	sessionID := SessionIDFromContext(ctx)
	session := sys.GetSession(sessionID)
	if session == nil {
		return fmt.Errorf("elevate: requires an active registered session")
	}
	if session.ManagedAgent() != nil {
		return fmt.Errorf("elevate: agents cannot elevate")
	}

	switch args[1] {
	case "request":
		role, ttl, reason, err := parseElevationRequest(args[2:])
		if err != nil {
			return err
		}
		if IsPrivilegedRole(role) {
			provider, eligible := session.OIDC()
			if provider != OIDCProviderAdmin || !containsRole(eligible, role) {
				return fmt.Errorf("elevate: role %q requires an admin-audience capability", role)
			}
		}
		expiresAt := time.Now().UTC().Add(ttl)
		// Audit first. An elevation the chain does not record must not exist.
		if err := engineFromContext(ctx).LogEvent(fmt.Sprintf("ELEVATE_REQUEST: session=%s user=%s role=%s ttl=%s reason=%q expires_at=%s",
			sessionID, session.User, role, ttl, reason, expiresAt.Format(time.RFC3339))); err != nil {
			return fmt.Errorf("elevate: audit failed; elevation not granted: %w", err)
		}
		session.ActivateElevation(role, reason, expiresAt)
		fmt.Fprintf(hc.Stdout, "elevate: role=%s expires_at=%s reason=%q\n", role, expiresAt.Format(time.RFC3339), reason)
		return nil

	case "status":
		elevation := session.ActiveElevation()
		if elevation == nil {
			fmt.Fprintln(hc.Stdout, "elevate: no active elevation")
			return nil
		}
		fmt.Fprintf(hc.Stdout, "elevate: role=%s expires_at=%s remaining=%s reason=%q\n",
			elevation.Role,
			elevation.ExpiresAt.UTC().Format(time.RFC3339),
			time.Until(elevation.ExpiresAt).Truncate(time.Second),
			elevation.Reason,
		)
		return nil

	case "drop":
		dropped := session.DropElevation()
		if dropped == nil {
			fmt.Fprintln(hc.Stdout, "elevate: no active elevation")
			return nil
		}
		// The drop happens first: losing privilege must not wait on the audit
		// sink. A failed audit is still reported.
		if err := engineFromContext(ctx).LogEvent(fmt.Sprintf("ELEVATE_DROP: session=%s user=%s role=%s reason=%q",
			sessionID, session.User, dropped.Role, dropped.Reason)); err != nil {
			return fmt.Errorf("elevate: dropped role=%s but audit failed: %w", dropped.Role, err)
		}
		fmt.Fprintf(hc.Stdout, "elevate: dropped role=%s\n", dropped.Role)
		return nil

	default:
		return fmt.Errorf("elevate: unsupported action %q", args[1])
	}
}

func parseElevationRequest(args []string) (string, time.Duration, string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", 0, "", fmt.Errorf("elevate: request requires a role")
	}
	role := args[0]
	ttl := 10 * time.Minute
	reason := ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--for":
			if i+1 >= len(args) {
				return "", 0, "", fmt.Errorf("elevate: --for requires a duration")
			}
			i++
			parsed, err := time.ParseDuration(args[i])
			if err != nil || parsed <= 0 || parsed > 24*time.Hour {
				return "", 0, "", fmt.Errorf("elevate: --for must be a positive duration no greater than 24h")
			}
			ttl = parsed
		case "--reason":
			if i+1 >= len(args) {
				return "", 0, "", fmt.Errorf("elevate: --reason requires text")
			}
			i++
			reason = args[i]
		default:
			return "", 0, "", fmt.Errorf("elevate: unknown option %q", args[i])
		}
	}
	if strings.TrimSpace(reason) == "" {
		return "", 0, "", fmt.Errorf("elevate: --reason is required")
	}
	if !validEnvironmentName(strings.ReplaceAll(role, "-", "_")) {
		return "", 0, "", fmt.Errorf("elevate: invalid role %q", role)
	}
	return role, ttl, reason, nil
}

func init() { Register(elevateBinary{}) }
