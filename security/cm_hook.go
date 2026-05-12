package security

import "fmt"

// CMSessionCheck checks whether the current command requires a CM ticket
// and whether one is validly set. Returns an error message if blocked.
// If not in strict mode and no pattern matches, returns nil (no-op).
func CMSessionCheck(cmd string, args []string) error {
	if !CMRequiredForCommand(cmd) {
		return nil
	}
	ticket, _ := GetActiveCMTicket()
	if ticket == nil {
		if CMStrictMode() {
			return fmt.Errorf("cm: command %q requires an active change ticket (run: cm set <ticket-id>)", cmd)
		}
		return nil // warn but don't block if not strict
	}
	if !IsTicketValid(ticket) {
		return fmt.Errorf("cm: ticket %s is not valid (state: %s)", ticket.ID, ticket.State)
	}
	return nil
}

// CMCurrentTicketID returns the active ticket ID or "" for embedding in audit entries.
func CMCurrentTicketID() string {
	_, id := GetActiveCMTicket()
	return id
}
