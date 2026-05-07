package security

import (
	"context"
	"fmt"

	"adssh/sys"
)

// RunGrant acts as the virtual binary for "grant".
// Usage: grant [request|drop] <role>
func RunGrant(ctx context.Context, args []string, sessionID string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: grant [request|drop] <role>")
	}

	action := args[1]
	role := args[2]

	session := sys.GetSession(sessionID)
	if session == nil {
		return fmt.Errorf("adssh: grant requires an active SSH session")
	}

	switch action {
	case "request":
		// Check if the user is ALREADY allowed to assume this role via a Rego policy or entitlements.
		// For the prototype, we assume if you can execute "grant request <role>", you are authorized.
		// A full implementation would check a specific `grant_allowance` policy.
		
		// Prevent duplicates
		for _, p := range session.Principals {
			if p == role {
				fmt.Printf("grant: role '%s' is already active\n", role)
				return nil
			}
		}

		// Append the new role (temporary escalation)
		session.Principals = append(session.Principals, role)
		LogCommand("GRANT", fmt.Sprintf("User %s requested and assumed role %s", session.User, role))
		fmt.Printf("grant: successfully assumed role '%s'\n", role)
		return nil

	case "drop":
		found := false
		var newPrincipals []string
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
		return fmt.Errorf("unsupported grant action: %s", action)
	}
}
