//go:build ee

package security

import (
	"context"
	"fmt"
	"strings"
)

// enterpriseApprovalGate is the change-management and four-eyes gate of the
// enterprise build (ee/LICENSE). Core calls it through ApprovalGate.
type enterpriseApprovalGate struct{}

func init() {
	if err := SetApprovalGate(enterpriseApprovalGate{}); err != nil {
		panic(err)
	}
}

func (enterpriseApprovalGate) Check(ctx context.Context, e *Engine, sessionID string, args []string) error {
	if err := e.CMSessionCheckForSession(sessionID, args[0], args[1:]); err != nil {
		return err
	}
	return e.CheckFourEyesForSessionContext(ctx, strings.Join(args, " "), args, sessionID)
}

func (enterpriseApprovalGate) Explain(e *Engine, sessionID string, args []string) []ExplanationStage {
	cm := ExplanationStage{Name: "change_management", Status: "not_required"}
	if e.CMRequiredForSession(sessionID, args[0]) {
		ticket, id := e.GetActiveCMTicketForSession(sessionID)
		switch {
		case ticket == nil && CMStrictMode():
			cm = ExplanationStage{Name: "change_management", Status: "denied", Reason: "an active approved change ticket is required"}
		case ticket == nil:
			cm = ExplanationStage{Name: "change_management", Status: "warning", Reason: "no active ticket; strict mode is disabled"}
		case !IsTicketValid(ticket):
			cm = ExplanationStage{Name: "change_management", Status: "denied", Reason: fmt.Sprintf("ticket %s is not valid (state: %s)", id, ticket.State)}
		default:
			cm = ExplanationStage{Name: "change_management", Status: "allowed", Reason: "ticket " + id}
		}
	}
	return []ExplanationStage{cm, explainFourEyes(e, args, "")}
}

func (enterpriseApprovalGate) NotifyPolicyDenial(command, requiredRole string) {
	_ = sendApprovalNotice(approvalNotice{
		Event:            "policy_denied",
		Kind:             command,
		Command:          command,
		RequiredApprover: requiredRole,
		Fingerprint:      fingerprintSecret(command),
	})
}
