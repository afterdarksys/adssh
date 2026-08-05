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
	Outcome   string             `json:"outcome"`
	User      string             `json:"user,omitempty"`
	Groups    []string           `json:"groups,omitempty"`
	SessionID string             `json:"session_id,omitempty"`
	Command   string             `json:"command"`
	Args      []string           `json:"args,omitempty"`
	Stages    []ExplanationStage `json:"stages"`
	NextSteps []string           `json:"next_steps,omitempty"`
}

// ExplainCommand evaluates every governance stage without executing the
// command, creating approval requests, or writing command audit entries.
func (e *Engine) ExplainCommand(sessionID string, args []string) (CommandExplanation, error) {
	if len(args) == 0 || args[0] == "" {
		return CommandExplanation{}, fmt.Errorf("why: command is required")
	}
	pctx := BuildPolicyContext(args[0], args[1:], sessionID)
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

	allowed, reason, err := e.EvaluatePolicy(pctx)
	switch {
	case err != nil:
		deny("policy", err.Error())
	case !allowed:
		if reason == "" {
			reason = "policy returned allow=false"
		}
		deny("policy", reason)
	default:
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "policy", Status: "allowed", Reason: reason})
	}

	if !e.hasEntitlements() {
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "entitlements", Status: "not_configured"})
	} else if e.IsAuthorized(pctx.User, pctx.Groups, args[0]) {
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "entitlements", Status: "allowed"})
	} else {
		deny("entitlements", fmt.Sprintf("%q is not in the effective command allow-list", args[0]))
	}

	if !CMRequiredForCommand(args[0]) {
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "change_management", Status: "not_required"})
	} else if ticket, id := e.GetActiveCMTicketForSession(sessionID); ticket == nil {
		if CMStrictMode() {
			deny("change_management", "an active approved change ticket is required")
		} else {
			explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "change_management", Status: "warning", Reason: "no active ticket; strict mode is disabled"})
		}
	} else if !IsTicketValid(ticket) {
		deny("change_management", fmt.Sprintf("ticket %s is not valid (state: %s)", id, ticket.State))
	} else {
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "change_management", Status: "allowed", Reason: "ticket " + id})
	}

	fullCommand := strings.Join(args, " ")
	if rule, matched := e.MatchesFourEyes(fullCommand); matched {
		reason := fmt.Sprintf("matches rule %q", rule.Pattern)
		if rule.Approver != "" {
			reason += "; approver=" + rule.Approver
		}
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "four_eyes", Status: "approval_required", Reason: reason})
		if explanation.Outcome != "denied" {
			explanation.Outcome = "approval_required"
		}
	} else {
		explanation.Stages = append(explanation.Stages, ExplanationStage{Name: "four_eyes", Status: "not_required"})
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
				steps = append(steps, `request the required role with: elevate request <role> --for 10m --reason "<ticket/reason>"`)
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
