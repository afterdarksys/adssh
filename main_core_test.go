//go:build !ee

package main

import "testing"

// Without the enterprise gateway policy the SSH listener gets no direct-tcpip
// authorizer, and internal/sys refuses every forward ("gateway forwarding is
// disabled", TestDirectTCPIPNilAuthorizerRefuses in internal/sys).
func TestCoreRefusesDirectTCPIP(t *testing.T) {
	if directTCPIPAuthorizer(nil) != nil {
		t.Fatal("SECURITY: the core build installs a direct-tcpip authorizer")
	}
}

// sah/1 is enterprise; the core build refuses it without reading a frame.
func TestCoreRefusesSAH(t *testing.T) {
	if code := sahDisabled(); code != 2 {
		t.Fatalf("sahDisabled = %d, want 2", code)
	}
	if code := runSAH(nil, "core-sah"); code != 2 {
		t.Fatalf("runSAH = %d, want 2", code)
	}
}
