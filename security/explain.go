package security

import (
	"fmt"
	"strings"
)

type ExplanationStage struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type CommandExplanation struct {
	Outcome      string   `json:"outcome"`
	User         string   `json:"user,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	SessionID    string   `json:"session_id,omitempty"`
	RequiredRole string   `json:"required_role,omitempty"`
	// Rule and RequiredEntitlement come from the policy decision.
	Rule                string `json:"rule,omitempty"`
	RequiredEntitlement string `json:"required_entitlement,omitempty"`
	// HeldEntitlements are the RBAC entries this session holds. Needed are
	// the entitlements that would allow the command when policy or RBAC
	// denied it: the policy's required_entitlement, then the RBAC entries
	// that list the command.
	HeldEntitlements   []string           `json:"held_entitlements,omitempty"`
	NeededEntitlements []string           `json:"needed_entitlements,omitempty"`
	Command            string             `json:"command"`
	Args               []string           `json:"args,omitempty"`
	Stages             []ExplanationStage `json:"stages"`
	NextSteps          []string           `json:"next_steps,omitempty"`
}

// ExplainCommand evaluates every governance stage without executing the
// command, creating approval requests, or writing command audit entries.
func (e *Engine) ExplainCommand(sessionID string, args []string) (CommandExplanation, error) {
	if len(args) == 0 || args[0] == "" {
		return CommandExplanation{}, fmt.Errorf("why: command is required")
	}
	pctx := e.buildPolicyContext(args[0], args[1:], sessionID)
	// The gate classifies capabilities before policy; do the same so a
	// capability-scoped policy explains what it would decide.
	pctx.Capabilities = ClassifyCapabilities(args[0])
	explanation := CommandExplanation{
		Outcome:   "allowed",
		User:      pctx.User,
		Groups:    append([]string(nil), pctx.Groups...),
		SessionID: sessionID,
		Command:   args[0],
		Args:      append([]string(nil), args[1:]...),
	}
	deny := func(name, reason string) {
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: name, Status: "denied", Reason: reason})
		explanation.Outcome = "denied"
	}

	if pctx.IdentityUnknown {
		deny("identity", "session identity unknown")
	}
	decision, err := e.EvaluatePolicyDecision(pctx)
	explanation.RequiredRole = decision.RequiredRole
	explanation.Rule = decision.Rule
	explanation.RequiredEntitlement = decision.RequiredEntitlement
	reason := decision.DenyReason
	switch {
	case err != nil:
		deny("policy", err.Error())
	case !decision.Allowed:
		if decision.RequiredEntitlement != "" {
			explanation.NeededEntitlements = append(explanation.NeededEntitlements, decision.RequiredEntitlement)
		}
		if reason == "" {
			reason = "policy returned allow=false"
		}
		deny("policy", reason)
	default:
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "policy", Status: "allowed", Reason: reason})
	}

	if !e.hasEntitlements() {
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "entitlements", Status: "not_configured"})
	} else {
		explanation.HeldEntitlements = e.EntitlementsHeld(pctx.User, pctx.Groups)
		if e.IsAuthorized(pctx.User, pctx.Groups, args[0]) {
			explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "entitlements", Status: "allowed"})
		} else {
			explanation.NeededEntitlements = append(explanation.NeededEntitlements, e.EntitlementsGranting(args[0])...)
			deny("entitlements", fmt.Sprintf("%q is not in the effective command allow-list", args[0]))
		}
	}
	explanation.NeededEntitlements = compactStrings(explanation.NeededEntitlements)
	if len(explanation.NeededEntitlements) == 0 {
		explanation.NeededEntitlements = nil
	}

	for _, stage := range currentApprovalGate().Explain(e, sessionID, args) {
		explanation.Stages = append(explanation.Stages, stage)
		switch stage.Status {
		case "denied":
			explanation.Outcome = "denied"
		case "approval_required":
			if explanation.Outcome != "denied" {
				explanation.Outcome = "approval_required"
			}
		}
	}

	if !e.restricted {
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "restricted_mode", Status: "disabled"})
	} else if strings.Contains(args[0], "/") {
		deny("restricted_mode", "command names cannot contain '/' in restricted mode")
	} else if args[0] == "cd" || args[0] == "export" {
		deny("restricted_mode", args[0]+" is not allowed in restricted mode")
	} else {
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "restricted_mode", Status: "allowed"})
	}
	explanation.NextSteps = suggestNextSteps(explanation)
	return explanation, nil
}

func suggestNextSteps(explanation CommandExplanation) []string {
	steps := make([]string, 0, 4)
	for _, stage := range explanation.Stages {
		switch stage.Name {
		case "policy":
			if stage.Status == "denied" {
				role := explanation.RequiredRole
				if role == "" {
					role = "<role>"
				}
				steps = append(steps, fmt.Sprintf(`request the required role with: elevate request %s --for 10m --reason "<ticket/reason>"`, role))
				if explanation.RequiredEntitlement != "" {
					steps = append(steps, fmt.Sprintf("or ask an administrator for the %s entitlement", explanation.RequiredEntitlement))
				}
			}
		case "entitlements":
			if stage.Status == "denied" {
				steps = append(steps, "ask an administrator to add this command to your RBAC entitlement")
			}
		case "change_management":
			if stage.Status == "denied" {
				steps = append(steps, "attach an approved change ticket with: cm set <ticket-id>")
			}
		case "four_eyes":
			if stage.Status == "approval_required" {
				steps = append(steps, "open or check approvals with: 4eyes pending")
			}
		case "restricted_mode":
			if stage.Status == "denied" {
				steps = append(steps, "retry with an allowed command name or start a non-restricted session")
			}
		}
	}
	return compactStrings(steps)
}

func compactStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
