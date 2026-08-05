package security

import (
	"fmt"
	"net"
)

type GatewayPolicyRequest struct {
	SessionID  string
	User       string
	Groups     []string
	Action     string
	Listen     string
	Name       string
	TargetHost string
	TargetPort uint32
}

func NewGatewayClaim(action, listen, name, target string) (*GatewayClaim, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("gateway: invalid target address %q", target)
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("gateway: target host and port are required")
	}
	return &GatewayClaim{
		Action:     action,
		Listen:     listen,
		Name:       name,
		Target:     net.JoinHostPort(host, port),
		TargetHost: host,
		TargetPort: port,
	}, nil
}

func (e *Engine) AuthorizeGateway(req GatewayPolicyRequest) error {
	target := net.JoinHostPort(req.TargetHost, fmt.Sprintf("%d", req.TargetPort))
	claim, err := NewGatewayClaim(req.Action, req.Listen, req.Name, target)
	if err != nil {
		return err
	}
	pctx := BuildPolicyContext("gateway", []string{req.Action, claim.Target}, req.SessionID)
	if req.User != "" {
		pctx.User = req.User
	}
	if req.Groups != nil {
		pctx.Groups = append([]string(nil), req.Groups...)
	}
	pctx.Gateway = claim
	cmd := fmt.Sprintf("gateway %s %s", req.Action, claim.Target)
	e.LogCommand("GATEWAY", cmd)
	allowed, reason, policyErr := e.EvaluatePolicy(pctx)
	if policyErr != nil {
		e.rememberDeniedCommand(req.SessionID, []string{"gateway", req.Action, claim.Target})
		return fmt.Errorf("adssh: gateway policy evaluation error: %v", policyErr)
	}
	if !allowed {
		e.LogPolicyDecision(pctx.User, cmd, false, reason)
		e.rememberDeniedCommand(req.SessionID, []string{"gateway", req.Action, claim.Target})
		if reason != "" {
			return fmt.Errorf("adssh: gateway access denied: %s", reason)
		}
		return fmt.Errorf("adssh: gateway access denied for %s", claim.Target)
	}
	e.LogPolicyDecision(pctx.User, cmd, true, "")
	if e.hasEntitlements() && !e.IsAuthorized(pctx.User, pctx.Groups, "gateway") {
		e.LogPolicyDecision(pctx.User, cmd, false, "not permitted by entitlements")
		return fmt.Errorf("adssh: gateway access denied by entitlements")
	}
	return nil
}
