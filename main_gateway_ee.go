//go:build ee

package main

import (
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"
)

// directTCPIPAuthorizer gates SSH direct-tcpip through gateway policy
// (enterprise: gateway_policy_ee.go).
func directTCPIPAuthorizer(sec *security.Engine) sys.GatewayAuthorizer {
	return func(req sys.GatewayAuthRequest) error {
		return sec.AuthorizeGateway(directTCPIPPolicyRequest(req))
	}
}

// directTCPIPPolicyRequest maps a listener direct-tcpip check to one gateway
// policy decision: the requested name and the address it resolved to are
// both in the input.
func directTCPIPPolicyRequest(req sys.GatewayAuthRequest) security.GatewayPolicyRequest {
	return security.GatewayPolicyRequest{
		SessionID:  req.SessionID,
		User:       req.User,
		Groups:     req.Principals,
		Action:     "direct-tcpip",
		TargetHost: req.TargetHost,
		TargetIP:   req.TargetIP,
		TargetPort: req.TargetPort,
	}
}
