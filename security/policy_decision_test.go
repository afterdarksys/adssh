package security

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/afterdarksys/adssh/internal/sys"
)

func newPolicyEngine(t *testing.T, src string) *Engine {
	t.Helper()
	eng, err := NewEngine(EngineConfig{RequirePolicy: true, PolicySource: []byte(src)})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

const explainedTestPolicy = `package adssh.authz

default allow = false
default deny_reason = ""
default rule = ""
default required_role = ""
default required_entitlement = ""

allow {
	input.command == "ls"
}

deny_reason = "kubectl needs the k8s-write entitlement" {
	input.command == "kubectl"
}

rule = "k8s_write" {
	input.command == "kubectl"
}

required_role = "k8s-ops" {
	input.command == "kubectl"
}

required_entitlement = "k8s-write" {
	input.command == "kubectl"
}
`

func TestPolicyDecisionCarriesRuleAndEntitlement(t *testing.T) {
	eng := newPolicyEngine(t, explainedTestPolicy)
	d, err := eng.EvaluatePolicyDecision(PolicyContext{User: "alice", Command: "kubectl", Args: []string{"apply"}})
	if err != nil {
		t.Fatal(err)
	}
	want := PolicyDecision{
		Allowed:             false,
		DenyReason:          "kubectl needs the k8s-write entitlement",
		RequiredRole:        "k8s-ops",
		Rule:                "k8s_write",
		RequiredEntitlement: "k8s-write",
	}
	if d != want {
		t.Fatalf("decision = %#v, want %#v", d, want)
	}
	allowed, err := eng.EvaluatePolicyDecision(PolicyContext{User: "alice", Command: "ls"})
	if err != nil || !allowed.Allowed || allowed.Rule != "" || allowed.RequiredEntitlement != "" {
		t.Fatalf("ls decision = %#v, %v", allowed, err)
	}
}

func TestPolicyDecisionNonStringFieldsDeny(t *testing.T) {
	cases := map[string]string{
		"rule number":            `rule := 7`,
		"rule object":            `rule := {"name": "x"}`,
		"entitlement number":     `required_entitlement := 1`,
		"entitlement array":      `required_entitlement := ["a", "b"]`,
		"entitlement bool":       `required_entitlement := true`,
		"rule set (partial set)": `rule[x] { x := "a" }`,
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			eng := newPolicyEngine(t, "package adssh.authz\n\ndefault allow = true\n\n"+extra+"\n")
			d, err := eng.EvaluatePolicyDecision(PolicyContext{User: "alice", Command: "ls"})
			if err != nil {
				t.Fatalf("non-string field must deny, not error: %v", err)
			}
			if d.Allowed {
				t.Fatalf("non-string field allowed: %#v", d)
			}
			if !strings.Contains(d.DenyReason, "non-string") {
				t.Fatalf("deny reason = %q", d.DenyReason)
			}
			// The three-value public API agrees.
			ok, _, err := eng.EvaluatePolicy(PolicyContext{User: "alice", Command: "ls"})
			if err != nil || ok {
				t.Fatalf("EvaluatePolicy = %v, %v; want deny", ok, err)
			}
		})
	}
}

func TestPolicyDecisionOldPoliciesUnchanged(t *testing.T) {
	cases := []struct {
		src     string
		allowed bool
		reason  string
		role    string
	}{
		{"package adssh.authz\ndefault allow = true\ndefault deny_reason = \"\"\n", true, "", ""},
		{"package adssh.authz\ndefault allow = false\ndefault deny_reason = \"frozen\"\nrequired_role := \"ops\"\n", false, "frozen", "ops"},
		{"package adssh.authz\ndefault allow = false\nmetadata := {\"required_role\": \"netops\"}\n", false, "", "netops"},
		{"package adssh.authz\nallow := \"yes\"\n", false, "policy: non-boolean allow", ""},
		{"package adssh.authz\ndeny_reason := \"x\"\n", false, "x", ""},
	}
	for _, tc := range cases {
		eng := newPolicyEngine(t, tc.src)
		d, err := eng.EvaluatePolicyDecision(PolicyContext{User: "alice", Command: "ls"})
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed != tc.allowed || d.DenyReason != tc.reason || d.RequiredRole != tc.role || d.Rule != "" || d.RequiredEntitlement != "" {
			t.Fatalf("%q: decision = %#v", tc.src, d)
		}
		allowed, reason, err := eng.EvaluatePolicy(PolicyContext{User: "alice", Command: "ls"})
		if err != nil || allowed != tc.allowed || reason != tc.reason {
			t.Fatalf("%q: EvaluatePolicy = %v %q %v", tc.src, allowed, reason, err)
		}
	}
}

func TestPolicyDecisionNoPolicyAllows(t *testing.T) {
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	d, err := eng.EvaluatePolicyDecision(PolicyContext{Command: "ls"})
	if err != nil || !d.Allowed {
		t.Fatalf("no policy: %#v %v", d, err)
	}
}

func TestPolicyDecisionExplainSurfacesRuleAndEntitlement(t *testing.T) {
	eng := newPolicyEngine(t, explainedTestPolicy)
	if err := sys.RegisterSession(&sys.Session{ID: "explain-rule", User: "alice", Principals: []string{"ops"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession("explain-rule") })

	explanation, err := eng.ExplainCommand("explain-rule", []string{"kubectl", "apply"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.Outcome != "denied" || explanation.Rule != "k8s_write" || explanation.RequiredEntitlement != "k8s-write" || explanation.RequiredRole != "k8s-ops" {
		t.Fatalf("explanation = %#v", explanation)
	}
	if !slices.Contains(explanation.NeededEntitlements, "k8s-write") {
		t.Fatalf("needed entitlements = %v", explanation.NeededEntitlements)
	}
	var printed strings.Builder
	printCommandExplanation(&printed, explanation)
	for _, want := range []string{"rule", "k8s_write", "required_entitlement", "k8s-write"} {
		if !strings.Contains(printed.String(), want) {
			t.Fatalf("printed explanation missing %q:\n%s", want, printed.String())
		}
	}
	if !slices.ContainsFunc(explanation.NextSteps, func(s string) bool { return strings.Contains(s, "k8s-write") }) {
		t.Fatalf("next steps do not name the entitlement: %v", explanation.NextSteps)
	}
}

func TestPolicyDecisionDeniedCommandRecordsRuleForLastDenial(t *testing.T) {
	eng := newPolicyEngine(t, explainedTestPolicy)
	if err := sys.RegisterSession(&sys.Session{ID: "denial-rule", User: "alice"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession("denial-rule") })
	eng.rememberDeniedCommand("denial-rule", []string{"kubectl", "delete"})
	explanation, ok := eng.LastDenial("denial-rule")
	if !ok || explanation.Rule != "k8s_write" || explanation.RequiredEntitlement != "k8s-write" {
		t.Fatalf("last denial = %#v %v", explanation, ok)
	}
}

func TestExplainEntitlementsHeldAndNeeded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "entitlements.yaml")
	if err := os.WriteFile(path, []byte(`groups:
  ops: [ls, uptime]
  dba: [psql]
  admins: ["*"]
users:
  alice: [whoami]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(EngineConfig{EntitlementsPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.RegisterSession(&sys.Session{ID: "explain-ent", User: "alice", Principals: []string{"ops"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession("explain-ent") })

	explanation, err := eng.ExplainCommand("explain-ent", []string{"psql"})
	if err != nil {
		t.Fatal(err)
	}
	if explanation.Outcome != "denied" {
		t.Fatalf("outcome = %q", explanation.Outcome)
	}
	if !slices.Equal(explanation.HeldEntitlements, []string{"group:ops", "user:alice"}) {
		t.Fatalf("held = %v", explanation.HeldEntitlements)
	}
	if !slices.Equal(explanation.NeededEntitlements, []string{"group:admins", "group:dba"}) {
		t.Fatalf("needed = %v", explanation.NeededEntitlements)
	}

	allowed, err := eng.ExplainCommand("explain-ent", []string{"ls"})
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Outcome != "allowed" || len(allowed.NeededEntitlements) != 0 {
		t.Fatalf("allowed explanation = %#v", allowed)
	}
}

func TestPolicyDecisionAuditLineCarriesRuleAndEntitlement(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	chainPath := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{
		AuditLogPath: auditPath,
		ChainPath:    chainPath,
		ChainKeyPath: filepath.Join(dir, "audit.key"),
		SessionID:    "audit-rule",
	})
	if err != nil {
		t.Fatal(err)
	}
	d := PolicyDecision{Allowed: false, DenyReason: "frozen", Rule: "k8s_write", RequiredEntitlement: "k8s-write"}
	if err := eng.LogPolicyDecisionDetail("alice", "kubectl apply", d); err != nil {
		t.Fatal(err)
	}
	if err := eng.LogPolicyDecision("bob", "ls", true, ""); err != nil {
		t.Fatal(err)
	}
	flat, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(flat)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit lines = %q", flat)
	}
	if !strings.Contains(lines[0], `rule="k8s_write" required_entitlement="k8s-write"`) {
		t.Fatalf("detail line = %q", lines[0])
	}
	// A decision without the new fields writes the old line byte for byte.
	if !strings.HasSuffix(lines[1], `[POLICY] user=bob command=ls allowed=true reason=""`) {
		t.Fatalf("legacy line changed: %q", lines[1])
	}
	chain, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chain), "rule=k8s_write") || !strings.Contains(string(chain), "required_entitlement=k8s-write") {
		t.Fatalf("chain entry lacks rule/entitlement: %s", chain)
	}
	if ok, bad, err := eng.VerifyChain(chainPath); !ok || err != nil {
		t.Fatalf("chain no longer verifies: seq=%d err=%v", bad, err)
	}
}

func TestPolicyExampleExplainedReturnsAllFields(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "policy", "examples", "explained.rego"))
	if err != nil {
		t.Fatal(err)
	}
	eng := newPolicyEngine(t, string(data))
	d, err := eng.EvaluatePolicyDecision(PolicyContext{User: "alice", Groups: []string{"dev"}, Command: "kubectl", Args: []string{"delete", "pod", "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed || d.DenyReason == "" || d.Rule == "" || d.RequiredRole == "" || d.RequiredEntitlement == "" {
		t.Fatalf("example decision missing a field: %#v", d)
	}
	ok, err := eng.EvaluatePolicyDecision(PolicyContext{User: "alice", Groups: []string{"dev"}, Command: "ls"})
	if err != nil || !ok.Allowed {
		t.Fatalf("example should allow ls: %#v %v", ok, err)
	}
}
