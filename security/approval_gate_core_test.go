//go:build !ee

package security

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// The core build has no way to approve a four-eyes request, so a command that
// matches a rule is refused, never run.
func TestCoreGateRefusesFourEyesMatch(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	t.Setenv("HOME", t.TempDir())
	writeFourEyesRules(t, defaultEngine, FourEyesRule{Pattern: "corefe *", Approver: "bob", TTL: 60})

	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "corefe --now")
	if runErr == nil || !strings.HasPrefix(runErr.Error(), "foureyes:") || !strings.Contains(runErr.Error(), "enterprise") {
		t.Fatalf("want a foureyes enterprise refusal, got %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("SECURITY: four-eyes command ran in the core build: %v", rec.calls)
	}

	// A command the rule does not match still runs.
	_, _, runErr, rec = runShell(t, false, starlark.StringDict{}, "otherfe --now")
	if runErr != nil || len(rec.calls) != 1 {
		t.Fatalf("unmatched command: err=%v calls=%v", runErr, rec.calls)
	}

	explanation, err := defaultEngine.ExplainCommand("", []string{"corefe", "--now"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.Outcome != "denied" {
		t.Fatalf("why for a four-eyes command in core: outcome %q, want denied", explanation.Outcome)
	}
}

// Strict change management cannot be satisfied without the enterprise cm
// command, so a covered command is refused; non-strict only warns, as in the
// enterprise build.
func TestCoreGateStrictChangeManagement(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	t.Setenv("HOME", t.TempDir())
	setDefaultCMPatterns(t, "corecm*")

	t.Setenv("ADSSH_CM_STRICT", "1")
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "corecm-deploy")
	if runErr == nil || !strings.HasPrefix(runErr.Error(), "cm:") || !strings.Contains(runErr.Error(), "requires an active change ticket") {
		t.Fatalf("strict CM: want a cm refusal, got %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("SECURITY: strict-CM command ran in the core build: %v", rec.calls)
	}

	t.Setenv("ADSSH_CM_STRICT", "")
	_, _, runErr, rec = runShell(t, false, starlark.StringDict{}, "corecm-deploy")
	if runErr != nil || len(rec.calls) != 1 {
		t.Fatalf("non-strict CM: err=%v calls=%v", runErr, rec.calls)
	}
}

// An installed gate replaces the core gate and is consulted by the
// interceptor.
func TestCoreInstalledGateIsConsulted(t *testing.T) {
	resetPolicy()
	t.Cleanup(resetPolicy)
	t.Setenv("HOME", t.TempDir())
	t.Cleanup(func() {
		approvalGateMu.Lock()
		approvalGate = nil
		approvalGateMu.Unlock()
	})
	if err := SetApprovalGate(recordingGate{refuse: true}); err != nil {
		t.Fatal(err)
	}
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "gated-cmd")
	if !errors.Is(runErr, errRecordingGate) {
		t.Fatalf("installed gate not consulted: %v", runErr)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("SECURITY: command ran past a refusing gate: %v", rec.calls)
	}
}

// Enterprise command names stay reserved in the core build: they never fall
// through to a PATH executable of the same name.
func TestCoreEnterpriseNamesAreStubs(t *testing.T) {
	for _, b := range enterpriseOnlyBinaries {
		vb, ok := Lookup(b.name)
		if !ok {
			t.Fatalf("%s is not registered in the core build", b.name)
		}
		err := vb.Run(context.Background(), []string{b.name, "anything"})
		if err == nil || !strings.Contains(err.Error(), "enterprise") {
			t.Fatalf("%s stub: %v", b.name, err)
		}
	}
	_, _, runErr, rec := runShell(t, false, starlark.StringDict{}, "lease vault secret/x")
	if runErr == nil || len(rec.calls) != 0 {
		t.Fatalf("lease in core: err=%v calls=%v", runErr, rec.calls)
	}
}

// A core refusal is recorded in the audit chain with the command name only.
func TestCoreGateRefusalIsAudited(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	writeFourEyesRules(t, eng, FourEyesRule{Pattern: "corefe *"})
	err := eng.AuthorizeCommand([]string{"corefe", "--secret-arg"}, "")
	if err == nil || !strings.HasPrefix(err.Error(), "foureyes:") {
		t.Fatalf("want a foureyes refusal, got %v", err)
	}
	data, readErr := os.ReadFile(chain)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var refusal string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "APPROVAL_REFUSED") {
			refusal = line
		}
	}
	if !strings.Contains(refusal, `gate=core kind=foureyes session=- command=\"corefe\"`) {
		t.Fatalf("refusal not audited:\n%s", data)
	}
	if strings.Contains(refusal, "--secret-arg") {
		t.Fatalf("refusal audit carries arguments: %s", refusal)
	}
}
