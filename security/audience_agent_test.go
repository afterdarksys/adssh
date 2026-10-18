package security

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

// audienceFor returns the audience pinOIDCProviders configured for provider.
func audienceFor(t *testing.T, provider string) string {
	t.Helper()
	key := "ADSSH_OIDC_LOGIN_AUDIENCE"
	if provider == OIDCProviderAdmin {
		key = "ADSSH_OIDC_ADMIN_AUDIENCE"
	}
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("%s not pinned", key)
	}
	return value
}

func oidcClaims(issuer, audience, user string, groups []string, exp int64) map[string]any {
	return map[string]any{
		"iss":    issuer,
		"aud":    audience,
		"email":  user,
		"groups": groups,
		"exp":    exp,
	}
}

func unsignedJWT(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"typ": "JWT", "alg": alg, "kid": "kid"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func assertOIDCUnset(t *testing.T, session *sys.Session) {
	t.Helper()
	provider, eligible := session.OIDC()
	if provider != "" || len(eligible) != 0 {
		t.Fatalf("oidc mutated: provider set=%t eligible=%d", provider != "", len(eligible))
	}
}

func TestAgentGateAllowlistAndExpiredLease(t *testing.T) {
	eng := policyEngine(t, allowAllPolicy)
	live := &sys.Session{ID: testID(t, "live"), User: "agent"}
	if err := sys.RegisterSession(live); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(live.ID) })
	live.BindManagedAgent(&sys.ManagedAgent{
		ID:        "live-agent",
		Worktree:  "wt",
		Allow:     []string{"bash"},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	for _, command := range []string{"bash", "grid", "flight", "grant", "elevate"} {
		err := eng.gateCommand(false, []string{command}, live.ID)
		equalErr(t, err, "adssh: agent cannot run "+strconvQuote(command))
	}
	if err := eng.gateCommand(false, []string{"repo"}, live.ID); err != nil {
		t.Fatal(err)
	}

	expired := &sys.Session{ID: testID(t, "expired"), User: "agent"}
	if err := sys.RegisterSession(expired); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(expired.ID) })
	expired.BindManagedAgent(&sys.ManagedAgent{
		ID:        "expired-agent",
		Worktree:  "wt",
		Allow:     []string{"repo"},
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	equalErr(t, eng.gateCommand(false, []string{"repo"}, expired.ID), "adssh: agent lease expired")
}

func strconvQuote(value string) string {
	return `"` + value + `"`
}

func TestCloudClaimWinsOverExtraAgent(t *testing.T) {
	cloud := policyEngine(t, "package adssh.authz\ndefault allow = false\nallow { input.agent.kind == \"cloud\" }\n")
	instrument := policyEngine(t, "package adssh.authz\ndefault allow = false\nallow { input.agent.kind == \"instrument\" }\n")
	extra := PolicyContextExtra{Agent: &AgentClaim{ID: "inst", Kind: "instrument", Risk: "worktree"}}

	session := &sys.Session{ID: testID(t, "cloud"), User: "agent"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	session.BindManagedAgent(&sys.ManagedAgent{
		ID:        "cloud-agent",
		Worktree:  "wt",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err := cloud.gateCommandWithExtra(false, []string{"repo"}, session.ID, extra); err != nil {
		t.Fatal(err)
	}
	err := instrument.gateCommandWithExtra(false, []string{"repo"}, session.ID, extra)
	if err == nil || !strings.Contains(err.Error(), "adssh: access denied") || strings.Contains(err.Error(), "agent cannot run") {
		t.Fatalf("instrument deny = %v", err)
	}

	plain := &sys.Session{ID: testID(t, "plain"), User: "alice"}
	if err := sys.RegisterSession(plain); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(plain.ID) })
	if err := instrument.gateCommandWithExtra(false, []string{"repo"}, plain.ID, extra); err != nil {
		t.Fatal(err)
	}
}
