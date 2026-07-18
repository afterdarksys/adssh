package security

import (
	"context"
	"fmt"

	"github.com/afterdarksys/adssh/sys"
)

// grant — temporary role escalation

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

	switch action {
	case "request":
		for _, p := range session.Principals {
			if p == role {
				fmt.Printf("grant: role '%s' is already active\n", role)
				return nil
			}
		}
		session.Principals = append(session.Principals, role)
		LogCommand("GRANT", fmt.Sprintf("User %s requested and assumed role %s", session.User, role))
		fmt.Printf("grant: successfully assumed role '%s'\n", role)
		return nil

	case "drop":
		found := false
		newPrincipals := session.Principals[:0]
		for _, p := range session.Principals {
			if p == role {
				found = true
				continue
			}
			newPrincipals = append(newPrincipals, p)
		}
		if !found {
			return fmt.Errorf("grant: you do not currently hold role '%s'", role)
		}
		session.Principals = newPrincipals
		LogCommand("GRANT", fmt.Sprintf("User %s dropped role %s", session.User, role))
		fmt.Printf("grant: successfully dropped role '%s'\n", role)
		return nil

	default:
		return fmt.Errorf("grant: unsupported action '%s'", action)
	}
}

func init() { Register(grantBinary{}) }
