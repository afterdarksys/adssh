package security

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// runSessionVBin runs vb in sessionID and returns stdout and the error,
// with any stderr folded into the error.
func runSessionVBin(t *testing.T, eng *Engine, vb VirtualBinary, sessionID string, args []string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	runner, err := interp.New(
		interp.StdIO(nil, &out, &errOut),
		interp.ExecHandler(func(ctx context.Context, _ []string) error {
			return eng.DispatchVBin(WithSessionID(ctx, sessionID), vb, args)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	file, err := syntax.NewParser().Parse(strings.NewReader("vbin-test"), "")
	if err != nil {
		t.Fatal(err)
	}
	runErr := runner.Run(context.Background(), file)
	if runErr == nil && errOut.Len() > 0 {
		runErr = &runbookTestError{message: strings.TrimSpace(errOut.String())}
	}
	return out.String(), runErr
}

const whoamiTestPolicy = `package adssh.authz

import future.keywords.in

default allow = false
default rule = "default_deny"

allow { input.command in {"ls", "whoami", "why"} }
rule = "read_only" { input.command in {"ls", "whoami", "why"} }

allow { "net" in input.capabilities }
rule = "net_ok" { "net" in input.capabilities }

required_entitlement = "cloud-write" { "cloud" in input.capabilities }
deny_reason = "cloud needs cloud-write" { "cloud" in input.capabilities }
rule = "cloud_gate" { "cloud" in input.capabilities }
`

func whoamiEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "entitlements.yaml")
	if err := os.WriteFile(path, []byte("groups:\n  ops: [ls, uptime, starlark.net.dial, starlark.aws.ec2]\nusers:\n  alice: [whoami]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(EngineConfig{RequirePolicy: true, PolicySource: []byte(whoamiTestPolicy), EntitlementsPath: path})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestWhoamiPlainPrintsOnlyUsername(t *testing.T) {
	eng := whoamiEngine(t)
	session := &sys.Session{ID: "whoami-bare", User: "alice", Principals: []string{"ops"}}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	session.ActivateElevation("k8s-ops", "INC-0", time.Now().Add(10*time.Minute))

	out, err := runSessionVBin(t, eng, whoamiBinary{}, session.ID, []string{"whoami"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "alice\n" {
		t.Fatalf("plain whoami = %q, want %q", out, "alice\n")
	}
}

func TestWhoamiVerboseReportsSessionIdentity(t *testing.T) {
	eng := whoamiEngine(t)
	session := &sys.Session{ID: "whoami-plain", User: "alice", Principals: []string{"ops"}}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	session.SetIdentitySource(sys.IdentitySourceOIDCVerified)
	session.ActivateElevation("k8s-ops", "INC-1", time.Now().Add(10*time.Minute))

	out, err := runSessionVBin(t, eng, whoamiBinary{}, session.ID, []string{"whoami", "-v"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"alice", "whoami-plain", "ops", "oidc-verified", "k8s-ops", "INC-1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("whoami missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "policy") {
		t.Fatalf("whoami -v must not evaluate policy:\n%s", out)
	}
}

func TestWhoamiCapsJSON(t *testing.T) {
	eng := whoamiEngine(t)
	session := &sys.Session{ID: "whoami-caps", User: "alice", Principals: []string{"ops"}}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	expires := time.Now().Add(10 * time.Minute)
	session.ActivateElevation("k8s-ops", "INC-2", expires)

	out, err := runSessionVBin(t, eng, whoamiBinary{}, session.ID, []string{"whoami", "--caps", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	var report WhoamiReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if report.User != "alice" || report.SessionID != "whoami-caps" || report.IdentitySource != "login" {
		t.Fatalf("identity = %#v", report)
	}
	if report.Elevation == nil || report.Elevation.Role != "k8s-ops" || report.Elevation.ExpiresAt != expires.UTC().Format(time.RFC3339) {
		t.Fatalf("elevation = %#v", report.Elevation)
	}
	caps := report.Caps
	if caps == nil {
		t.Fatal("caps missing")
	}
	if !slices.Equal(caps.Entitlements, []string{"group:ops", "user:alice"}) {
		t.Fatalf("entitlements = %v", caps.Entitlements)
	}
	if !slices.Equal(caps.EntitledCommands, []string{"ls", "starlark.aws.ec2", "starlark.net.dial", "uptime", "whoami"}) {
		t.Fatalf("entitled commands = %v", caps.EntitledCommands)
	}
	if !slices.Contains(caps.CapabilityGroupsAllowed, CapNet) || slices.Contains(caps.CapabilityGroupsAllowed, CapCloud) {
		t.Fatalf("capability groups allowed = %v", caps.CapabilityGroupsAllowed)
	}
	if !slices.Contains(caps.CapabilityGroupsDenied, CapCloud) {
		t.Fatalf("capability groups denied = %v", caps.CapabilityGroupsDenied)
	}
	var sawLS, sawCloud bool
	for _, probe := range caps.Probes {
		switch {
		case probe.Command == "ls":
			sawLS = probe.Outcome == "allowed" && probe.Rule == "read_only"
		case probe.Capability == CapCloud:
			sawCloud = probe.Outcome == "denied" && probe.Rule == "cloud_gate" && probe.RequiredEntitlement == "cloud-write"
		}
	}
	if !sawLS || !sawCloud {
		t.Fatalf("probes missing ls/cloud detail: %#v", caps.Probes)
	}
}

func TestWhoamiCapsHasNoSideEffects(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	chainPath := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{
		RequirePolicy: true,
		PolicySource:  []byte(whoamiTestPolicy),
		AuditLogPath:  auditPath,
		ChainPath:     chainPath,
		ChainKeyPath:  filepath.Join(dir, "audit.key"),
		SessionID:     "whoami-audit",
		FourEyesDir:   filepath.Join(dir, "4eyes"),
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFourEyesRules(t, eng, FourEyesRule{Pattern: "rm *", Approver: "bob", TTL: 60})
	session := &sys.Session{ID: "whoami-noside", User: "alice"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	before, _ := os.ReadFile(auditPath)
	beforeChain, _ := os.ReadFile(chainPath)

	if _, err := runSessionVBin(t, eng, whoamiBinary{}, session.ID, []string{"whoami", "--caps"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(auditPath)
	afterChain, _ := os.ReadFile(chainPath)
	if !bytes.Equal(before, after) || !bytes.Equal(beforeChain, afterChain) {
		t.Fatalf("whoami --caps wrote audit records:\n%s", after)
	}
	if _, err := os.Stat(filepath.Join(dir, "4eyes", "pending")); !os.IsNotExist(err) {
		t.Fatalf("whoami --caps created a four-eyes request: %v", err)
	}
	if _, ok := eng.LastDenial(session.ID); ok {
		t.Fatal("whoami --caps recorded a denial")
	}
}

func TestWhoamiDoesNotLeakAnotherSession(t *testing.T) {
	eng := whoamiEngine(t)
	mine := &sys.Session{ID: "whoami-mine", User: "alice", Principals: []string{"ops"}}
	theirs := &sys.Session{ID: "whoami-theirs", User: "mallory", Principals: []string{"secret-team"}}
	if err := sys.RegisterSession(mine); err != nil {
		t.Fatal(err)
	}
	if err := sys.RegisterSession(theirs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(mine.ID); sys.UnregisterSession(theirs.ID) })
	theirs.ActivateElevation("adssh-admin", "their-reason", time.Now().Add(time.Hour))

	out, err := runSessionVBin(t, eng, whoamiBinary{}, mine.ID, []string{"whoami", "--caps", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"mallory", "secret-team", "whoami-theirs", "their-reason", "adssh-admin"} {
		if strings.Contains(out, leak) {
			t.Fatalf("whoami leaked %q:\n%s", leak, out)
		}
	}
	// whoami takes no session argument; a stray one is refused.
	if _, err := runSessionVBin(t, eng, whoamiBinary{}, mine.ID, []string{"whoami", "whoami-theirs"}); err == nil {
		t.Fatal("whoami accepted a session argument")
	}
}

func TestWhoamiUnknownSessionFails(t *testing.T) {
	eng := whoamiEngine(t)
	if _, err := runSessionVBin(t, eng, whoamiBinary{}, "whoami-nobody", []string{"whoami"}); err == nil {
		t.Fatal("whoami for an unknown session succeeded")
	}
}

func TestWhoamiBoundIdentity(t *testing.T) {
	eng := whoamiEngine(t)
	if err := eng.BindSessionIdentity("whoami-bound", "carol", []string{"dev"}); err != nil {
		t.Fatal(err)
	}
	report, err := eng.Whoami("whoami-bound", false)
	if err != nil {
		t.Fatal(err)
	}
	if report.User != "carol" || report.IdentitySource != "bound" || !slices.Equal(report.Principals, []string{"dev"}) || report.Caps != nil {
		t.Fatalf("report = %#v", report)
	}
}
