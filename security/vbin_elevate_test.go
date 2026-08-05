package security

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func runElevateVBin(t *testing.T, eng *Engine, sessionID string, args []string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(WithSessionID(ctx, sessionID), elevateBinary{}, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("elevate-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &runbookTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

func TestElevateRequestAddsPolicyVisibleClaimAndAudits(t *testing.T) {
	session := &sys.Session{ID: "elevate-policy", User: "alice", Principals: []string{"ops"}}
	sys.RegisterSession(session)
	defer sys.UnregisterSession(session.ID)

	dir := t.TempDir()
	chainPath := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{
		PolicySource: []byte(`
package adssh.authz
default allow = false
default deny_reason = "requires prod-admin break-glass"
allow {
  input.command == "deploy"
  input.elevation.role == "prod-admin"
  input.elevation.reason != ""
}
`),
		ChainPath:    chainPath,
		ChainKeyPath: filepath.Join(dir, "audit.key"),
		SessionID:    "elevate-policy",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := eng.gateCommand(false, []string{"deploy"}, session.ID); err == nil {
		t.Fatal("deploy unexpectedly allowed before elevation")
	}
	output, err := runElevateVBin(t, eng, session.ID, []string{"elevate", "request", "prod-admin", "--for", "10m", "--reason", "incident INC-1042"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "role=prod-admin") {
		t.Fatalf("request output = %q", output)
	}
	if err := eng.gateCommand(false, []string{"deploy"}, session.ID); err != nil {
		t.Fatalf("deploy denied after elevation: %v", err)
	}
	pctx := BuildPolicyContext("deploy", nil, session.ID)
	if pctx.Elevation == nil || pctx.Elevation.Role != "prod-admin" || pctx.Elevation.Reason != "incident INC-1042" {
		t.Fatalf("policy elevation claim = %#v", pctx.Elevation)
	}
	if !containsString(pctx.Groups, "prod-admin") {
		t.Fatalf("groups missing elevated role: %#v", pctx.Groups)
	}
	chain, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chain), "ELEVATE_REQUEST") || !strings.Contains(string(chain), "prod-admin") {
		t.Fatalf("elevation was not audited: %s", chain)
	}
}

func TestElevationExpiresAndDropClearsIt(t *testing.T) {
	session := &sys.Session{ID: "elevate-expire", User: "alice"}
	sys.RegisterSession(session)
	defer sys.UnregisterSession(session.ID)

	session.ActivateElevation("prod-admin", "test", time.Now().Add(-time.Second))
	if elevation := session.ActiveElevation(); elevation != nil {
		t.Fatalf("expired elevation still active: %#v", elevation)
	}

	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runElevateVBin(t, eng, session.ID, []string{"elevate", "request", "prod-admin", "--for", "1m", "--reason", "test"}); err != nil {
		t.Fatal(err)
	}
	status, err := runElevateVBin(t, eng, session.ID, []string{"elevate", "status"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "role=prod-admin") {
		t.Fatalf("status output = %q", status)
	}
	drop, err := runElevateVBin(t, eng, session.ID, []string{"elevate", "drop"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(drop, "dropped role=prod-admin") {
		t.Fatalf("drop output = %q", drop)
	}
	if elevation := session.ActiveElevation(); elevation != nil {
		t.Fatalf("drop left elevation active: %#v", elevation)
	}
}

func TestElevateRequiresReason(t *testing.T) {
	_, _, _, err := parseElevationRequest([]string{"prod-admin", "--for", "1m"})
	if err == nil || !strings.Contains(err.Error(), "--reason is required") {
		t.Fatalf("expected reason error, got %v", err)
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
