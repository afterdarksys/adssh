package security

import (
	"strings"
)

// CheckFourEyes checks whether cmd+args requires dual approval.
// Returns nil if allowed to proceed, error if denied/timed out.
// If globals is nil or no rules match, returns nil immediately (no-op).
func CheckFourEyes(cmd string, args []string, globals interface{}) error {
	fullCmd := strings.Join(args, " ")
	rule, matched := MatchesFourEyes(fullCmd)
	if !matched {
		return nil
	}
	return RequestApproval(fullCmd, *rule)
}
