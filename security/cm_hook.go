package security

import "fmt"

// CMSessionCheck checks whether the current command requires a CM ticket
// and whether one is validly set. Returns an error message if blocked.
// If not in strict mode and no pattern matches, returns nil (no-op).
func (e *Engine) CMSessionCheck(cmd string, args []string) error {
	return e.CMSessionCheckForSession("", cmd, args)
}

// CMSessionCheckForSession validates only the ticket associated with sessionID.
func (e *Engine) CMSessionCheckForSession(sessionID, cmd string, args []string) error {
	if !CMRequiredForCommand(cmd) {
		return nil
	}
	ticket, _ := e.GetActiveCMTicketForSession(sessionID)
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

// CMSessionCheck checks whether the current command requires a CM ticket.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func CMSessionCheck(cmd string, args []string) error {
	return defaultEngine.CMSessionCheck(cmd, args)
}

// CMCurrentTicketID returns the active ticket ID or "" for embedding in audit entries.
func (e *Engine) CMCurrentTicketID() string {
	_, id := e.GetActiveCMTicket()
	return id
}
