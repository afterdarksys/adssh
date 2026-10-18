package security

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// A rules file that cannot be parsed refuses every command in both builds.
// Before the split, MatchesFourEyes read it as "no rules" and the command ran
// without a second approver.
func TestApprovalGateCorruptRulesFileFailsClosed(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(FourEyesDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(FourEyesDir(), "rules"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "anything-at-all")
	if runErr == nil || !strings.HasPrefix(runErr.Error(), "foureyes:") {
		t.Fatalf("corrupt rules file: want a foureyes refusal, got %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("SECURITY: command reached exec with an unreadable rules file: %v", rec.calls)
	}

	explanation, err := defaultEngine.ExplainCommand("", []string{"anything-at-all"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.Outcome != "denied" {
		t.Fatalf("why with an unreadable rules file: outcome %q, want denied", explanation.Outcome)
	}
}

func TestSetApprovalGateRejectsNilAndSecondGate(t *testing.T) {
	if err := SetApprovalGate(nil); err == nil {
		t.Fatal("SetApprovalGate(nil) succeeded")
	}
	installed := currentApprovalGate()
	if _, core := installed.(coreApprovalGate); core {
		// Core build: install one, then a second must fail.
		t.Cleanup(func() {
			approvalGateMu.Lock()
			approvalGate = nil
			approvalGateMu.Unlock()
		})
		if err := SetApprovalGate(recordingGate{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := SetApprovalGate(recordingGate{}); err == nil {
		t.Fatal("a second SetApprovalGate replaced the installed gate")
	}
}

type recordingGate struct{ refuse bool }

func (g recordingGate) Check(context.Context, *Engine, string, []string) error {
	if g.refuse {
		return errRecordingGate
	}
	return nil
}
func (recordingGate) Explain(*Engine, string, []string) []ExplanationStage { return nil }
func (recordingGate) NotifyPolicyDenial(string, string)                    {}

var errRecordingGate = errors.New("foureyes: refused by the test gate")
