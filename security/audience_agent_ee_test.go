//go:build ee

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

func TestGrantRefusesGridOps(t *testing.T) {
	session := &sys.Session{ID: "grant-gridops", User: "alice"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	err := grantBinary{}.Run(WithSessionID(context.Background(), session.ID), []string{"grant", "request", "gridops"})
	if err == nil || !strings.Contains(err.Error(), `grant: role "gridops" is not assumable`) {
		t.Fatalf("grant error = %v", err)
	}
}

func TestAdminAudienceElevateGridOpsNotOSRootAndUIDUnchanged(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []oidcJWK{rsaJWK("kid", &private.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(server.Close)
	pinOIDCProviders(t, "https://issuer.example", server)

	session := &sys.Session{ID: "oidc-admin", User: "alice"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	audience := audienceFor(t, OIDCProviderAdmin)
	issuer := "https://issuer.example"
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import",
		"--token", signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audience, "alice@example.com", []string{"gridops", "ops"}, time.Now().Add(time.Hour).Unix())),
		"--provider", OIDCProviderAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, eligible := session.OIDC()
	if provider != OIDCProviderAdmin {
		t.Fatalf("provider = %q", provider)
	}
	if len(eligible) != 1 || eligible[0] != RoleGridOps {
		t.Fatalf("eligible = %#v", eligible)
	}
	if len(session.Principals) != 1 || session.Principals[0] != "ops" {
		t.Fatalf("principals = %#v", session.Principals)
	}

	uid := os.Getuid()
	_, err = runVBin(t, eng, session.ID, []string{"elevate", "request", "os-root", "--for", "10m", "--reason", "grid"})
	equalErr(t, err, `elevate: role "os-root" requires an admin-audience capability`)
	if os.Getuid() != uid {
		t.Fatal("uid changed")
	}
	if _, err := runVBin(t, eng, session.ID, []string{"elevate", "request", "gridops", "--for", "10m", "--reason", "grid"}); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != uid {
		t.Fatal("uid changed")
	}
	elevation := session.ActiveElevation()
	if elevation == nil || elevation.Role != RoleGridOps {
		t.Fatal("gridops elevation missing")
	}
}

func TestOIDCRejectsWrongAudienceExpiredTamperedNoneAndOpaque(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []oidcJWK{rsaJWK("kid", &private.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(server.Close)
	pinOIDCProviders(t, "https://issuer.example", server)

	session := &sys.Session{ID: "oidc-reject", User: "before"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://issuer.example"
	audience := audienceFor(t, OIDCProviderLogin)
	future := time.Now().Add(time.Hour).Unix()

	_, err = runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import",
		"--token", signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audience+"-other", "alice@example.com", []string{"ops"}, future)),
		"--provider", OIDCProviderLogin,
	})
	equalErr(t, err, "identity oidc import: audience mismatch")
	assertOIDCUnset(t, session)

	_, err = runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import",
		"--token", signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audience, "alice@example.com", []string{"ops"}, time.Now().Add(-time.Hour).Unix())),
		"--provider", OIDCProviderLogin,
	})
	equalErr(t, err, "identity oidc import: token is expired")
	assertOIDCUnset(t, session)

	tampered := signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audience, "alice@example.com", []string{"ops"}, future))
	parts := strings.Split(tampered, ".")
	if len(parts) != 3 {
		t.Fatal("signed token was not a jwt")
	}
	tampered = parts[0] + "." + parts[1] + ".AAAA"
	_, err = runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import",
		"--token", tampered,
		"--provider", OIDCProviderLogin,
	})
	equalErr(t, err, "identity oidc import: signature verification failed")
	assertOIDCUnset(t, session)

	_, err = runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import",
		"--token", unsignedJWT(t, "none", oidcClaims(issuer, audience, "alice@example.com", nil, future)),
		"--provider", OIDCProviderLogin,
	})
	equalErr(t, err, `identity oidc import: unsupported signing algorithm "none"`)
	assertOIDCUnset(t, session)

	_, err = runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import", "--token", "dvc_opaque_bearer_value",
	})
	equalErr(t, err, "identity oidc import: token must be a JWT")
	assertOIDCUnset(t, session)

	_, err = runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import",
		"--token", signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audience, "alice@example.com", nil, future)),
		"--provider", OIDCProviderLogin, "--jwks-url", server.URL,
	})
	equalErr(t, err, `identity oidc import: unknown option "--jwks-url"`)
	assertOIDCUnset(t, session)
}

func TestLoginAudienceDoesNotGrantPrivilegedRoles(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []oidcJWK{rsaJWK("kid", &private.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(server.Close)
	pinOIDCProviders(t, "https://issuer.example", server)

	session := &sys.Session{ID: "oidc-login", User: "before"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	audience := audienceFor(t, OIDCProviderLogin)
	issuer := "https://issuer.example"
	_, err = runVBin(t, nil, session.ID, []string{
		"identity", "oidc", "import",
		"--token", signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audience, "alice@example.com", []string{"ops", "os-root", "gridops"}, time.Now().Add(time.Hour).Unix())),
		"--provider", OIDCProviderLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, eligible := session.OIDC()
	if provider != OIDCProviderLogin {
		t.Fatalf("provider = %q", provider)
	}
	if len(eligible) != 0 {
		t.Fatalf("eligible = %#v", eligible)
	}
	if len(session.Principals) != 1 || session.Principals[0] != "ops" {
		t.Fatalf("principals = %#v", session.Principals)
	}
}

func TestOIDCImportChainStoresFingerprintOnly(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []oidcJWK{rsaJWK("kid", &private.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(server.Close)
	pinOIDCProviders(t, "https://issuer.example", server)

	session := &sys.Session{ID: "oidc-chain", User: "alice"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "audit.chain")
	eng, err := NewEngine(EngineConfig{
		ChainPath:    chainPath,
		ChainKeyPath: filepath.Join(dir, "audit.key"),
		SessionID:    session.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	audience := audienceFor(t, OIDCProviderLogin)
	issuer := "https://issuer.example"
	token := signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audience, "alice@example.com", []string{"ops"}, time.Now().Add(time.Hour).Unix()))
	_, err = runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import",
		"--token", token,
		"--provider", OIDCProviderLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(chain)
	fingerprint := fingerprintSecret(token)
	if !strings.Contains(text, fingerprint) || strings.Contains(text, token) || strings.Contains(text, "[REDACTED]") {
		t.Fatal("chain missed fingerprint or stored the token")
	}
	if !strings.Contains(text, session.ID) {
		t.Fatal("chain missed session id")
	}
}

func TestIdentityStatusJSONOmitsToken(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []oidcJWK{rsaJWK("kid", &private.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(server.Close)
	pinOIDCProviders(t, "https://issuer.example", server)

	session := &sys.Session{ID: "status-login", User: "before"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	audience := audienceFor(t, OIDCProviderLogin)
	issuer := "https://issuer.example"
	eng, err := NewEngine(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import",
		"--token", signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audience, "alice@example.com", []string{"ops"}, time.Now().Add(time.Hour).Unix())),
		"--provider", OIDCProviderLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	output, err := runVBin(t, eng, session.ID, []string{"identity", "status", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "token") {
		t.Fatal("identity status json contained token")
	}
	if !strings.Contains(output, `"oidc_provider":"login"`) || !strings.Contains(output, `"principals":["ops"]`) {
		t.Fatal("identity status json missed provider or principals")
	}
}
