//go:build ee

package security

import (
	"strings"
	"testing"
	"time"

	"go.starlark.net/starlark"
)

// E.1: a four-eyes rule matching the command blocks it through the interceptor
// (times out) and the command never reaches exec.
func TestGateNeg_FourEyes_BlocksThroughInterceptor(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	t.Setenv("HOME", t.TempDir())

	// TTL=1; RequestApproval's poll loop makes this ~2s wall-clock.
	if err := AddFourEyesRule("neg4eyes*", "", 1); err != nil {
		t.Fatalf("AddFourEyesRule: %v", err)
	}

	start := time.Now()
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "neg4eyes-cmd")
	elapsed := time.Since(start)

	if runErr == nil || !strings.Contains(runErr.Error(), "timed out") {
		t.Fatalf("expected four-eyes timeout error blocking the command, got: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("SECURITY: four-eyes-gated command reached exec instead of being blocked: %v", rec.calls)
	}
	if elapsed < time.Second {
		t.Errorf("four-eyes gate returned too fast (%v) — did it actually wait for approval?", elapsed)
	}
}

// E.2: CM strict mode + a CM-required pattern + no active ticket blocks the
// command through the interceptor.
func TestGateNeg_CMStrict_NoTicket_BlocksThroughInterceptor(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	ClearActiveCMTicket()
	t.Cleanup(ClearActiveCMTicket)

	t.Setenv("ADSSH_CM_STRICT", "1")
	setDefaultCMPatterns(t, "negcmstrict*")

	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "negcmstrict-cmd")
	if runErr == nil || !strings.Contains(runErr.Error(), "requires an active change ticket") {
		t.Fatalf("expected CM strict block for missing ticket, got: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("SECURITY: CM-required command reached exec with no ticket in strict mode: %v", rec.calls)
	}
}

// E.3: a CM ticket in a non-approved state, and a ticket whose approval window
// has already closed, are both blocked through the interceptor.
func TestGateNeg_CMInvalidTicket_BlocksThroughInterceptor(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	t.Cleanup(ClearActiveCMTicket)

	setDefaultCMPatterns(t, "negcmticket*")

	// Non-approved (open) ticket => blocked regardless of strict mode.
	SetActiveCMTicket(&CMTicket{ID: "CHG-OPEN", State: "open"}, "CHG-OPEN")
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "negcmticket-cmd")
	if runErr == nil || !strings.Contains(runErr.Error(), "not valid") {
		t.Fatalf("expected block for open-state ticket, got: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Errorf("SECURITY: command with an open (unapproved) CM ticket reached exec: %v", rec.calls)
	}

	// Approved but the end window is in the past => expired => blocked.
	SetActiveCMTicket(&CMTicket{
		ID:        "CHG-EXP",
		State:     "approved",
		EndWindow: time.Now().Add(-time.Hour),
	}, "CHG-EXP")
	_, _, runErr2, rec2 := runShell(t, false, starlark.StringDict{}, "negcmticket-cmd")
	if runErr2 == nil || !strings.Contains(runErr2.Error(), "not valid") {
		t.Fatalf("expected block for expired ticket window, got: %v", runErr2)
	}
	if len(rec2.calls) != 0 {
		t.Errorf("SECURITY: command with an expired CM ticket window reached exec: %v", rec2.calls)
	}
}
