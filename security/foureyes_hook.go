package security

import (
	"context"
	"strings"
)

// CheckFourEyes checks whether cmd+args requires dual approval.
// Returns nil if allowed to proceed, error if denied/timed out.
// If globals is nil or no rules match, returns nil immediately (no-op).
func (e *Engine) CheckFourEyes(cmd string, args []string, globals interface{}) error {
	return e.CheckFourEyesForSession(cmd, args, "")
}

// CheckFourEyesForSession attributes any pending approval request to the
// authenticated session rather than the process OS account.
func (e *Engine) CheckFourEyesForSession(cmd string, args []string, sessionID string) error {
	return e.CheckFourEyesForSessionContext(context.Background(), cmd, args, sessionID)
}

// CheckFourEyesForSessionContext is CheckFourEyesForSession whose approval
// wait ends when ctx is done.
func (e *Engine) CheckFourEyesForSessionContext(ctx context.Context, cmd string, args []string, sessionID string) error {
	fullCmd := strings.Join(args, " ")
	rule, matched := e.MatchesFourEyes(fullCmd)
	if !matched {
		return nil
	}
	return e.RequestApprovalForSessionContext(ctx, fullCmd, *rule, sessionID)
}

// CheckFourEyes checks whether cmd+args requires dual approval.
//
// Deprecated: use Engine methods; retained for the binary until the engine facade lands.
func CheckFourEyes(cmd string, args []string, globals interface{}) error {
	return defaultEngine.CheckFourEyes(cmd, args, globals)
}
