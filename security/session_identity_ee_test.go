//go:build ee

package security

import (
	"strings"
	"testing"
)

func TestAuthorizeGatewayUnknownSessionDenied(t *testing.T) {
	eng, err := NewEngine(EngineConfig{PolicySource: []byte("package adssh\nauthz := {\"allow\": true}\n")})
	if err != nil {
		t.Fatal(err)
	}
	err = eng.AuthorizeGateway(GatewayPolicyRequest{SessionID: "bogus-gw", Action: "connect", TargetHost: "127.0.0.1", TargetPort: 22})
	if err == nil || !strings.Contains(err.Error(), "session identity unknown") {
		t.Fatalf("gateway for unknown session authorized: %v", err)
	}
	// An explicit caller-supplied user (the SSH listener path) still works.
	if err := eng.AuthorizeGateway(GatewayPolicyRequest{SessionID: "bogus-gw", User: "alice", Action: "connect", TargetHost: "127.0.0.1", TargetPort: 22}); err != nil {
		t.Fatalf("gateway with explicit user: %v", err)
	}
}
