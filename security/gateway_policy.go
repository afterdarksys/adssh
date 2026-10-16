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
	// TargetIP is the address TargetHost resolved to and the one that will
	// be dialed. Empty when the caller did not resolve. It reaches policy as
	// input.gateway.target_ip in the same decision as target_host.
	TargetIP   string
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
	if req.TargetIP != "" {
		ip := net.ParseIP(req.TargetIP)
		if ip == nil {
			return fmt.Errorf("gateway: invalid target address")
		}
		claim.TargetIP = ip.String()
	}
	pctx := e.buildPolicyContext("gateway", []string{req.Action, claim.Target}, req.SessionID)
	if req.User != "" {
		pctx.User = req.User
		pctx.IdentityUnknown = false
	}
	if req.Groups != nil {
		pctx.Groups = append([]string(nil), req.Groups...)
	}
	pctx.Gateway = claim
	cmd := fmt.Sprintf("gateway %s %s", req.Action, claim.Target)
	if claim.TargetIP != "" {
		cmd += " ip=" + claim.TargetIP
	}
	if err := e.LogCommand("GATEWAY", cmd); err != nil {
		return fmt.Errorf("adssh: audit log failed: %w", err)
	}
	if pctx.IdentityUnknown {
		e.rememberDeniedCommand(req.SessionID, []string{"gateway", req.Action, claim.Target})
		auditErr := e.LogPolicyDecision("", cmd, false, "adssh: session identity unknown")
		return joinDeny("adssh: gateway access denied: session identity unknown", auditErr)
	}
	allowed, reason, policyErr := e.EvaluatePolicy(pctx)
	if policyErr != nil {
		e.rememberDeniedCommand(req.SessionID, []string{"gateway", req.Action, claim.Target})
		return fmt.Errorf("adssh: gateway policy evaluation error: %v", policyErr)
	}
	if !allowed {
		auditErr := e.LogPolicyDecision(pctx.User, cmd, false, reason)
		e.rememberDeniedCommand(req.SessionID, []string{"gateway", req.Action, claim.Target})
		msg := fmt.Sprintf("adssh: gateway access denied for %s", claim.Target)
		if reason != "" {
			msg = fmt.Sprintf("adssh: gateway access denied: %s", reason)
		}
		return joinDeny(msg, auditErr)
	}
	if err := e.LogPolicyDecision(pctx.User, cmd, true, ""); err != nil {
		return fmt.Errorf("adssh: audit log failed: %w", err)
	}
	if e.hasEntitlements() && !e.IsAuthorized(pctx.User, pctx.Groups, "gateway") {
		auditErr := e.LogPolicyDecision(pctx.User, cmd, false, "not permitted by entitlements")
		return joinDeny("adssh: gateway access denied by entitlements", auditErr)
	}
	return nil
}
