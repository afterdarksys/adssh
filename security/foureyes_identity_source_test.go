package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

func TestFourEyesRequestRefusedFromAssertedIdentity(t *testing.T) {
	eng, _, _ := chainEngine(t)

	// alice renamed her session to carol; carol must not be able to request.
	renamed := &sys.Session{ID: "fe-req-renamed", User: "alice"}
	registerTestSession(t, renamed)
	renamed.SetIdentity("carol", nil)
	device := &sys.Session{ID: "fe-req-device", User: "alice"}
	registerTestSession(t, device)
	device.SetIdentity("carol", nil)
	device.SetIdentitySource(sys.IdentitySourceDeviceLogin)
	for _, s := range []*sys.Session{renamed, device} {
		_, _, err := eng.createFourEyesPending("rm -rf /srv", FourEyesRule{}, s.ID)
		if err == nil || !strings.Contains(err.Error(), "cannot request approval") {
			t.Fatalf("session %s request err = %v", s.ID, err)
		}
		if err := eng.RequestApprovalForSession("rm -rf /srv", FourEyesRule{TTL: 1}, s.ID); err == nil {
			t.Fatalf("session %s RequestApprovalForSession succeeded", s.ID)
		}
	}
	entries, err := os.ReadDir(eng.fourEyesPendingDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("refused requests left %d pending files", len(entries))
	}

	registered := &sys.Session{ID: "fe-req-registered", User: "alice"}
	registerTestSession(t, registered)
	pending, _, err := eng.createFourEyesPending("rm -rf /srv", FourEyesRule{}, registered.ID)
	if err != nil || pending.Requester != "alice" {
		t.Fatalf("registered request = %+v %v", pending, err)
	}
	verified := &sys.Session{ID: "fe-req-verified", User: "before"}
	registerTestSession(t, verified)
	verified.SetIdentity("dave", nil)
	verified.SetIdentitySource(sys.IdentitySourceOIDCVerified)
	pending, _, err = eng.createFourEyesPending("rm -rf /srv", FourEyesRule{}, verified.ID)
	if err != nil || pending.Requester != "dave" {
		t.Fatalf("verified request = %+v %v", pending, err)
	}
}

func TestFourEyesOIDCImportCanApproveDeviceLoginCannot(t *testing.T) {
	// OIDC provider with a pinned JWKS.
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []oidcJWK{rsaJWK("kid", &private.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	oidcServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(oidcServer.Close)
	issuer := "https://issuer.example"
	pinOIDCProviders(t, issuer, oidcServer)

	// Device-login control plane.
	var base string
	cpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "dc",
				"verification_url": base + "/oauth/device/verify?code=u",
				"expires_in":       600,
				"interval":         1,
			})
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "opaque-bearer", "token_type": "Bearer", "expires_in": 3600})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cpServer.Close)
	base = cpServer.URL
	pinControlPlane(t, cpServer)

	eng, chain, _ := chainEngine(t)

	// A device-login session renamed to bob cannot approve or deny.
	device := &sys.Session{ID: "fe-e2e-device", User: "mallory"}
	registerTestSession(t, device)
	ctx := WithSessionID(context.WithValue(context.Background(), engineCtxKey, eng), device.ID)
	if _, err := DeviceLogin(ctx, DeviceLoginRequest{
		URL:       cpServer.URL,
		Username:  "bob",
		TokenFile: filepath.Join(t.TempDir(), "device.token"),
		Timeout:   5 * time.Second,
	}); err != nil {
		t.Fatalf("device login: %v", err)
	}
	if got := device.IdentitySource(); got != sys.IdentitySourceDeviceLogin {
		t.Fatalf("device login source = %q", got)
	}
	pendingPath := seedPending(t, eng, "req-e2e", "alice", "bob")
	for _, verb := range []string{"approve", "deny"} {
		if _, err := runFourEyesVBin(t, eng, device.ID, []string{"4eyes", verb, "req-e2e"}); err == nil {
			t.Fatalf("device-login identity could %s", verb)
		}
	}
	if _, err := os.Stat(pendingPath); err != nil {
		t.Fatalf("device-login attempt changed the request: %v", err)
	}

	// A verified OIDC import as bob can approve.
	imported := &sys.Session{ID: "fe-e2e-oidc", User: "before"}
	registerTestSession(t, imported)
	future := time.Now().Add(time.Hour).Unix()
	if _, err := runVBin(t, eng, imported.ID, []string{
		"identity", "oidc", "import",
		"--token", signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audienceFor(t, OIDCProviderLogin), "bob", nil, future)),
		"--provider", OIDCProviderLogin,
		"--user-claim", "email",
	}); err != nil {
		t.Fatalf("oidc import: %v", err)
	}
	if got := imported.IdentitySource(); got != sys.IdentitySourceOIDCVerified || imported.Info().User != "bob" {
		t.Fatalf("import source=%q user=%q", got, imported.Info().User)
	}
	if _, err := runFourEyesVBin(t, eng, imported.ID, []string{"4eyes", "approve", "req-e2e"}); err != nil {
		t.Fatalf("verified identity refused: %v", err)
	}
	ledger, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ledger), "FOUREYES_DECISION request=req-e2e approver=bob decision=approve surface=shell") {
		t.Fatalf("chain missing decision:\n%s", ledger)
	}
}
