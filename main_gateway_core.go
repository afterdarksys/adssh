//go:build !ee

package main

import (
	"github.com/afterdarksys/adssh/internal/sys"
	"github.com/afterdarksys/adssh/security"
)

// directTCPIPAuthorizer is nil in the core build: governed gateways are
// enterprise, and the SSH listener refuses every direct-tcpip channel when it
// has no authorizer ("gateway forwarding is disabled").
func directTCPIPAuthorizer(*security.Engine) sys.GatewayAuthorizer { return nil }
