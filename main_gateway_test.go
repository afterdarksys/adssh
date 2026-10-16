package main

import (
	"errors"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestGatewayDirectTCPIPPolicyRequestCarriesTargetIP(t *testing.T) {
	got := directTCPIPPolicyRequest(sys.GatewayAuthRequest{
		SessionID:  "s1",
		User:       "alice",
		Principals: []string{"ops"},
		TargetHost: "db.internal",
		TargetIP:   "10.0.0.7",
		TargetPort: 5432,
	})
	if got.Action != "direct-tcpip" || got.TargetHost != "db.internal" || got.TargetIP != "10.0.0.7" ||
		got.TargetPort != 5432 || got.User != "alice" || got.SessionID != "s1" || len(got.Groups) != 1 {
		t.Fatalf("policy request = %+v", got)
	}
}

// Without a running SSH listener the hangup action reports and returns; it
// must not exit the process.
func TestHangupListenerActionWithoutListenerReturns(t *testing.T) {
	listenerHangup()
}

func TestHangupHookFollowsStarlarkEnableDisable(t *testing.T) {
	prev := onHangup
	t.Cleanup(func() { onHangup = prev })
	var installed []bool
	onHangup = func(fn func()) { installed = append(installed, fn != nil) }

	if err := enableSSHWithHangup(func() error { return errors.New("bind failed") }); err == nil {
		t.Fatal("enable error was swallowed")
	}
	if len(installed) != 0 {
		t.Fatal("hangup hook installed although the listener did not start")
	}
	if err := enableSSHWithHangup(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := disableSSHClearHangup(func() error { return errors.New("not running") }); err == nil {
		t.Fatal("disable error was swallowed")
	}
	if err := disableSSHClearHangup(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(installed) != 2 || !installed[0] || installed[1] {
		t.Fatalf("hook changes = %v, want [installed cleared]", installed)
	}
}
