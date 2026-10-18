//go:build ee

package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

// jwksTLSServer serves one RSA key as kid "kid" over TLS.
func jwksTLSServer(t *testing.T, public *rsa.PublicKey) *httptest.Server {
	t.Helper()
	jwks, err := json.Marshal(oidcJWKSet{Keys: []oidcJWK{rsaJWK("kid", public)}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestOIDCAdminImportRejectsCallerJWKSProbe(t *testing.T) {
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(oidcJWKSet{Keys: []oidcJWK{rsaJWK("kid", &attacker.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	dialed := false
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dialed = true
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(plain.Close)
	session := &sys.Session{ID: "oidc-probe", User: "alice"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	t.Setenv("ADSSH_OIDC_LOGIN_AUDIENCE", "login-audience")
	t.Setenv("ADSSH_OIDC_ADMIN_AUDIENCE", "admin-audience")
	audience := audienceFor(t, OIDCProviderAdmin)
	token := signedOIDCTestToken(t, attacker, "kid", map[string]any{
		"aud": audience, "email": "alice@example.com", "groups": []string{"os-root", "adssh-admin"},
	})

	// The exact probe: caller-named plaintext JWKS and issuer.
	_, err = runVBin(t, nil, session.ID, []string{
		"identity", "oidc", "import", "--token", token, "--provider", OIDCProviderAdmin,
		"--jwks-url", plain.URL, "--issuer", plain.URL,
	})
	equalErr(t, err, `identity oidc import: unknown option "--jwks-url"`)
	assertOIDCUnset(t, session)
	_, err = runVBin(t, nil, session.ID, []string{
		"identity", "oidc", "import", "--token", token, "--provider", OIDCProviderAdmin, "--audience", audience,
	})
	equalErr(t, err, `identity oidc import: unknown option "--audience"`)
	assertOIDCUnset(t, session)

	// No operator config: fail closed.
	t.Setenv("ADSSH_OIDC_ADMIN_ISSUER", "")
	t.Setenv("ADSSH_OIDC_ADMIN_JWKS_URL", "")
	_, err = runVBin(t, nil, session.ID, []string{
		"identity", "oidc", "import", "--token", token, "--provider", OIDCProviderAdmin,
	})
	equalErr(t, err, "identity oidc import: oidc provider not configured: set ADSSH_OIDC_ADMIN_ISSUER, ADSSH_OIDC_ADMIN_JWKS_URL and ADSSH_OIDC_ADMIN_AUDIENCE")
	assertOIDCUnset(t, session)

	// The default provider fails closed too; the login config does not leak into admin.
	t.Setenv("ADSSH_OIDC_ISSUER", "")
	t.Setenv("ADSSH_OIDC_JWKS_URL", "")
	_, err = runVBin(t, nil, session.ID, []string{"identity", "oidc", "import", "--token", token})
	equalErr(t, err, "identity oidc import: oidc provider not configured: set ADSSH_OIDC_ISSUER, ADSSH_OIDC_JWKS_URL and ADSSH_OIDC_LOGIN_AUDIENCE")
	t.Setenv("ADSSH_OIDC_ISSUER", "https://issuer.example")
	t.Setenv("ADSSH_OIDC_JWKS_URL", "https://issuer.example/jwks")
	_, err = runVBin(t, nil, session.ID, []string{
		"identity", "oidc", "import", "--token", token, "--provider", OIDCProviderAdmin,
	})
	equalErr(t, err, "identity oidc import: oidc provider not configured: set ADSSH_OIDC_ADMIN_ISSUER, ADSSH_OIDC_ADMIN_JWKS_URL and ADSSH_OIDC_ADMIN_AUDIENCE")

	// Operator pinned a plaintext JWKS URL: refused before any dial.
	t.Setenv("ADSSH_OIDC_ADMIN_ISSUER", "https://issuer.example")
	t.Setenv("ADSSH_OIDC_ADMIN_JWKS_URL", plain.URL)
	_, err = runVBin(t, nil, session.ID, []string{
		"identity", "oidc", "import", "--token", token, "--provider", OIDCProviderAdmin,
	})
	equalErr(t, err, "identity oidc import: fetch jwks: url_rejected")
	if dialed {
		t.Fatal("plaintext JWKS was fetched")
	}
	assertOIDCUnset(t, session)
	if session.Info().User != "alice" {
		t.Fatalf("user changed to %q", session.Info().User)
	}
}

func TestOIDCImportRejectsUntrustedOriginAndRedirect(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	trusted := jwksTLSServer(t, &private.PublicKey)
	// httptest servers share one built-in certificate, so the untrusted server
	// gets its own freshly generated one that is not in the pool.
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(oidcJWKSet{Keys: []oidcJWK{rsaJWK("kid", &private.PublicKey)}})
	}))
	untrusted.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedLoopbackCert(t)}}
	untrusted.StartTLS()
	t.Cleanup(untrusted.Close)
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, trusted.URL, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	pinOIDCProviders(t, "https://issuer.example", trusted)
	trustCallbackTLSServer(t, redirect)
	audience := audienceFor(t, OIDCProviderAdmin)
	t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", "")
	token := signedOIDCTestToken(t, private, "kid", oidcClaims("https://issuer.example", audience, "alice@example.com", nil, time.Now().Add(time.Hour).Unix()))
	opts := oidcImportOptions{Token: token, Provider: OIDCProviderAdmin, UserClaim: "email", GroupClaim: "groups"}

	// Certificate not in the trusted pool.
	t.Setenv("ADSSH_OIDC_ADMIN_JWKS_URL", untrusted.URL)
	if _, _, _, err := parseOIDCIdentity(context.Background(), opts); err == nil || err.Error() != "identity oidc import: fetch jwks: request failed" {
		t.Fatalf("untrusted origin: %v", err)
	}
	// Redirect is refused even to the trusted host.
	t.Setenv("ADSSH_OIDC_ADMIN_JWKS_URL", redirect.URL)
	if _, _, _, err := parseOIDCIdentity(context.Background(), opts); err == nil || err.Error() != "identity oidc import: fetch jwks: redirect_denied" {
		t.Fatalf("redirect: %v", err)
	}
	// Private host refused before a dial.
	t.Setenv("ADSSH_OIDC_ADMIN_JWKS_URL", "https://10.1.2.3/jwks")
	if _, _, _, err := parseOIDCIdentity(context.Background(), opts); err == nil || err.Error() != "identity oidc import: fetch jwks: url_rejected: host 10.1.2.3 is a private address; set ADSSH_CALLBACK_ALLOW_PRIVATE=1 to allow it" {
		t.Fatalf("private host: %v", err)
	}
	// Control: the trusted pin works.
	t.Setenv("ADSSH_OIDC_ADMIN_JWKS_URL", trusted.URL)
	if _, user, _, err := parseOIDCIdentity(context.Background(), opts); err != nil || user != "alice@example.com" {
		t.Fatalf("trusted: %q %v", user, err)
	}
}

func TestOIDCImportRejectsOversizedJWKS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[],"pad":"`))
		_, _ = w.Write([]byte(strings.Repeat("a", oidcResponseLimit+10)))
		_, _ = w.Write([]byte(`"}`))
	}))
	t.Cleanup(server.Close)
	pinOIDCProviders(t, "https://issuer.example", server)
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := signedOIDCTestToken(t, private, "kid", oidcClaims("https://issuer.example", "login-audience", "a@example.com", nil, time.Now().Add(time.Hour).Unix()))
	_, _, _, err = parseOIDCIdentity(context.Background(), oidcImportOptions{Token: token, UserClaim: "email"})
	if err == nil || err.Error() != "identity oidc import: fetch jwks: response too large" {
		t.Fatalf("oversized: %v", err)
	}
}

func TestOIDCImportClaimChecks(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := jwksTLSServer(t, &private.PublicKey)
	issuer := "https://issuer.example"
	pinOIDCProviders(t, issuer, server)
	now := time.Now()
	audience := audienceFor(t, OIDCProviderAdmin)
	base := func() map[string]any {
		return map[string]any{"iss": issuer, "aud": audience, "email": "alice@example.com",
			"groups": []string{"os-root"}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"missing-exp", func(c map[string]any) { delete(c, "exp") }, "identity oidc import: token has no exp"},
		{"missing-iss", func(c map[string]any) { delete(c, "iss") }, "identity oidc import: issuer mismatch"},
		{"wrong-iss", func(c map[string]any) { c["iss"] = "https://evil.example" }, "identity oidc import: issuer mismatch"},
		{"expired", func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }, "identity oidc import: token is expired"},
		{"exp-too-far", func(c map[string]any) {
			delete(c, "iat")
			c["exp"] = now.Add(25 * time.Hour).Unix()
		}, "identity oidc import: token lifetime exceeds 24h"},
		{"exp-minus-iat-too-long", func(c map[string]any) {
			c["iat"] = now.Add(-2 * time.Hour).Unix()
			c["exp"] = now.Add(23 * time.Hour).Unix()
		}, "identity oidc import: token lifetime exceeds 24h"},
		{"nbf-future", func(c map[string]any) { c["nbf"] = now.Add(10 * time.Minute).Unix() }, "identity oidc import: token is not yet valid"},
		{"iat-future", func(c map[string]any) { c["iat"] = now.Add(10 * time.Minute).Unix() }, "identity oidc import: token is not yet valid"},
		{"nbf-string", func(c map[string]any) { c["nbf"] = "soon" }, "identity oidc import: token nbf is invalid"},
		{"wrong-aud", func(c map[string]any) { c["aud"] = "other" }, "identity oidc import: audience mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := base()
			tc.mutate(claims)
			session := &sys.Session{ID: "oidc-claims-" + tc.name, User: "alice"}
			if err := sys.RegisterSession(session); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { sys.UnregisterSession(session.ID) })
			_, err := runVBin(t, nil, session.ID, []string{
				"identity", "oidc", "import", "--token", signedOIDCTestToken(t, private, "kid", claims),
				"--provider", OIDCProviderAdmin,
			})
			equalErr(t, err, tc.want)
			assertOIDCUnset(t, session)
		})
	}
}

func TestOIDCAdminImportValidTokenOverPinnedTLS(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := jwksTLSServer(t, &private.PublicKey)
	issuer := "https://admin-issuer.example"
	trustCallbackTLSServer(t, server)
	t.Setenv("ADSSH_OIDC_ADMIN_ISSUER", issuer)
	t.Setenv("ADSSH_OIDC_ADMIN_JWKS_URL", server.URL)
	t.Setenv("ADSSH_OIDC_LOGIN_AUDIENCE", "login-audience")
	t.Setenv("ADSSH_OIDC_ADMIN_AUDIENCE", "admin-audience")
	audience := audienceFor(t, OIDCProviderAdmin)
	session := &sys.Session{ID: "oidc-admin-valid", User: "alice"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	eng, err := NewEngine(EngineConfig{AuditLogPath: auditPath})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token := signedOIDCTestToken(t, private, "kid", map[string]any{
		"iss": issuer, "aud": audience, "email": "alice@example.com", "groups": []string{"gridops", "ops"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if _, err := runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import", "--token", token, "--provider", OIDCProviderAdmin,
	}); err != nil {
		t.Fatal(err)
	}
	provider, eligible := session.OIDC()
	if provider != OIDCProviderAdmin || len(eligible) != 1 || eligible[0] != RoleGridOps {
		t.Fatalf("provider=%q eligible=%v", provider, eligible)
	}
	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), token) || !strings.Contains(string(audit), fingerprintSecret(token)) {
		t.Fatal("audit stored the token or missed its fingerprint")
	}
}

func deviceHappyServer(t *testing.T, access string) *httptest.Server {
	t.Helper()
	var base string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if r.URL.Path == "/oauth/device" {
			writeDeviceStart(w, base)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 3600})
	}))
	base = server.URL
	t.Cleanup(server.Close)
	return server
}

func noDialClient(t *testing.T) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("dialed %s", r.URL)
		return nil, net.ErrClosed
	})}
}

func TestDeviceLoginUnpinnedFailsClosed(t *testing.T) {
	t.Setenv("ADSSH_CONTROLPLANE_URL", "")
	ctx := deviceSession(t, "device-unpinned")
	_, err := DeviceLogin(ctx, DeviceLoginRequest{
		URL: "https://alice-controlled.example", Username: "bob",
		TokenFile: filepath.Join(t.TempDir(), "t"), Client: noDialClient(t),
	})
	if err == nil || err.Error() != "control plane not configured: set ADSSH_CONTROLPLANE_URL to the https origin of the control plane" {
		t.Fatalf("unpinned: %v", err)
	}
	if got := sys.GetSession("device-unpinned").Info().User; got != "alice" {
		t.Fatalf("user changed to %q", got)
	}
}

func TestDeviceLoginURLMustEqualPin(t *testing.T) {
	server := deviceHappyServer(t, "pin-secret")
	pinControlPlane(t, server)
	ctx := deviceSession(t, "device-mismatch")
	for _, raw := range []string{
		"https://alice-controlled.example",
		server.URL + "/oauth",
		server.URL + "?x=1",
		strings.Replace(server.URL, "https://", "http://", 1),
	} {
		_, err := DeviceLogin(ctx, DeviceLoginRequest{
			URL: raw, Username: "bob", TokenFile: filepath.Join(t.TempDir(), "t"), Client: noDialClient(t),
		})
		if err == nil || err.Error() != "url_rejected" {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	if got := sys.GetSession("device-mismatch").Info().User; got != "alice" {
		t.Fatalf("user changed to %q", got)
	}
}

func TestDeviceLoginPinnedTLSSetsUser(t *testing.T) {
	server := deviceHappyServer(t, "pin-secret")
	pinControlPlane(t, server)
	ctx := deviceSession(t, "device-pinned")
	for _, raw := range []string{"", server.URL, server.URL + "/"} {
		tokenPath := filepath.Join(t.TempDir(), "device.token")
		if _, err := DeviceLogin(ctx, DeviceLoginRequest{URL: raw, Username: "bob", TokenFile: tokenPath}); err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if got := sys.GetSession("device-pinned").Info().User; got != "bob" {
			t.Fatalf("user %q", got)
		}
	}
}

func TestControlPlanePinRejectsBadConfig(t *testing.T) {
	t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", "")
	for _, raw := range []string{
		"http://controlplane.example",
		"http://127.0.0.1:8443",
		"https://127.0.0.1/oauth",
		"https://127.0.0.1/?q=1",
		"https://127.0.0.1#frag",
		"https://user:pw@127.0.0.1",
		"ftp://127.0.0.1",
		"https://192.168.1.10",
	} {
		t.Setenv("ADSSH_CONTROLPLANE_URL", raw)
		_, err := controlPlaneOrigin()
		if err == nil || !strings.HasPrefix(err.Error(), "url_rejected: ADSSH_CONTROLPLANE_URL") {
			t.Fatalf("%s: %v", raw, err)
		}
		var dErr deviceLoginError
		if !errors.As(err, &dErr) || dErr.code != "url_rejected" {
			t.Fatalf("%s: code lost: %v", raw, err)
		}
	}
	t.Setenv("ADSSH_CONTROLPLANE_URL", "https://192.168.1.10")
	if _, err := controlPlaneOrigin(); err == nil || err.Error() != "url_rejected: ADSSH_CONTROLPLANE_URL host 192.168.1.10 is a private address; set ADSSH_CALLBACK_ALLOW_PRIVATE=1 to allow it" {
		t.Fatalf("private control plane: %v", err)
	}
	t.Setenv("ADSSH_CONTROLPLANE_URL", "https://127.0.0.1:9443/")
	origin, err := controlPlaneOrigin()
	if err != nil || origin.String() != "https://127.0.0.1:9443" {
		t.Fatalf("origin %v %v", origin, err)
	}
}

func TestDeviceTokenWriteKeepsParentModeAndReplaces(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	server := deviceHappyServer(t, "first-secret")
	pinControlPlane(t, server)
	ctx := deviceSession(t, "device-token-file")
	tokenPath := filepath.Join(parent, "device.token")
	if _, err := DeviceLogin(ctx, DeviceLoginRequest{Username: "bob", TokenFile: tokenPath}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("parent mode changed to %o", info.Mode().Perm())
	}
	second := deviceHappyServer(t, "second-secret")
	pinControlPlane(t, second)
	result, err := DeviceLogin(ctx, DeviceLoginRequest{Username: "bob", TokenFile: tokenPath})
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	stored, err := os.ReadFile(tokenPath)
	if err != nil || string(stored) != "second-secret" || result.Fingerprint != fingerprintSecret("second-secret") {
		t.Fatalf("token not replaced: %v", err)
	}
	fi, err := os.Stat(tokenPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token mode %v %v", fi, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatalf("leftover temp files: %v %v", entries, err)
	}
}

func TestDeviceTokenWriteCreatesMissingParent0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new", "adssh")
	if err := writeDeviceToken(filepath.Join(dir, "device.token"), []byte("s")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("created dir mode %v %v", info, err)
	}
}

func TestDeviceTokenWriteRefusesSymlinkAndNonRegular(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "device.token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeDeviceToken(link, []byte("secret")); err == nil {
		t.Fatal("symlink destination accepted")
	}
	if data, _ := os.ReadFile(target); string(data) != "keep" {
		t.Fatal("symlink target overwritten")
	}
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeDeviceToken(sub, []byte("secret")); err == nil {
		t.Fatal("directory destination accepted")
	}
	server := deviceHappyServer(t, "symlink-secret")
	pinControlPlane(t, server)
	ctx := deviceSession(t, "device-symlink")
	if _, err := DeviceLogin(ctx, DeviceLoginRequest{Username: "bob", TokenFile: link}); err == nil || err.Error() != "token_file_rejected" {
		t.Fatalf("login through symlink: %v", err)
	}
}

func TestDeviceLoginAuditFailureLeavesIdentity(t *testing.T) {
	server := deviceHappyServer(t, "audit-secret")
	pinControlPlane(t, server)
	eng, err := NewEngine(EngineConfig{AuditLogPath: filepath.Join(t.TempDir(), "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	sessionID := "device-audit-fail"
	session := &sys.Session{ID: sessionID, User: "alice", Principals: []string{"ops"}}
	session.SetOIDC(OIDCProviderLogin, nil)
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(sessionID) })
	ctx := WithSessionID(context.WithValue(context.Background(), engineCtxKey, eng), sessionID)
	failAuditSync(t)
	tokenPath := filepath.Join(t.TempDir(), "device.token")
	_, err = DeviceLogin(ctx, DeviceLoginRequest{Username: "bob", TokenFile: tokenPath})
	if err == nil || err.Error() != "audit_failed" {
		t.Fatalf("audit failure: %v", err)
	}
	info := sys.GetSession(sessionID).Info()
	if info.User != "alice" || len(info.Principals) != 1 || info.OIDCProvider != OIDCProviderLogin {
		t.Fatalf("identity changed: %+v", info)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("bearer left behind: %v", err)
	}
}

func TestOIDCImportAuditFailureLeavesIdentity(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := jwksTLSServer(t, &private.PublicKey)
	issuer := "https://issuer.example"
	pinOIDCProviders(t, issuer, server)
	audience := audienceFor(t, OIDCProviderAdmin)
	eng, err := NewEngine(EngineConfig{AuditLogPath: filepath.Join(t.TempDir(), "audit.log")})
	if err != nil {
		t.Fatal(err)
	}
	session := &sys.Session{ID: "oidc-audit-fail", User: "alice"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })
	token := signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audience, "bob@example.com", []string{"gridops", "ops"}, time.Now().Add(time.Hour).Unix()))
	failAuditSync(t)
	_, err = runVBin(t, eng, session.ID, []string{
		"identity", "oidc", "import", "--token", token, "--provider", OIDCProviderAdmin,
	})
	equalErr(t, err, "identity oidc import: audit write failed")
	assertOIDCUnset(t, session)
	if info := session.Info(); info.User != "alice" || len(info.Principals) != 0 {
		t.Fatalf("identity changed: %+v", info)
	}
}

func TestOIDCCrossAudienceReplayRejected(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := jwksTLSServer(t, &private.PublicKey)
	issuer := "https://issuer.example"
	pinOIDCProviders(t, issuer, server)
	exp := time.Now().Add(time.Hour).Unix()
	loginToken := signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audienceFor(t, OIDCProviderLogin), "bob@example.com", []string{"os-root", "gridops"}, exp))
	adminToken := signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, audienceFor(t, OIDCProviderAdmin), "bob@example.com", []string{"gridops"}, exp))
	otherAppToken := signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, "some-other-app", "bob@example.com", []string{"os-root", "gridops"}, exp))
	bothClaims := oidcClaims(issuer, "", "bob@example.com", []string{"gridops"}, exp)
	bothClaims["aud"] = []string{audienceFor(t, OIDCProviderAdmin), audienceFor(t, OIDCProviderLogin)}
	bothToken := signedOIDCTestToken(t, private, "kid", bothClaims)
	cases := []struct {
		name     string
		token    string
		provider []string
	}{
		{"login-token-to-admin", loginToken, []string{"--provider", OIDCProviderAdmin}},
		{"admin-token-to-login", adminToken, []string{"--provider", OIDCProviderLogin}},
		{"admin-token-to-default", adminToken, nil},
		{"other-app-to-admin", otherAppToken, []string{"--provider", OIDCProviderAdmin}},
		{"other-app-to-login", otherAppToken, []string{"--provider", OIDCProviderLogin}},
		{"both-audiences-to-admin", bothToken, []string{"--provider", OIDCProviderAdmin}},
		{"both-audiences-to-login", bothToken, []string{"--provider", OIDCProviderLogin}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := &sys.Session{ID: "oidc-cross-" + tc.name, User: "alice"}
			if err := sys.RegisterSession(session); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { sys.UnregisterSession(session.ID) })
			args := append([]string{"identity", "oidc", "import", "--token", tc.token}, tc.provider...)
			_, err := runVBin(t, nil, session.ID, args)
			equalErr(t, err, "identity oidc import: audience mismatch")
			assertOIDCUnset(t, session)
			if session.Info().User != "alice" {
				t.Fatalf("user changed to %q", session.Info().User)
			}
		})
	}
	// Controls: each token imports under its own provider.
	for _, tc := range []struct {
		token    string
		provider string
	}{{loginToken, OIDCProviderLogin}, {adminToken, OIDCProviderAdmin}} {
		session := &sys.Session{ID: "oidc-cross-ok-" + tc.provider, User: "alice"}
		if err := sys.RegisterSession(session); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sys.UnregisterSession(session.ID) })
		if _, err := runVBin(t, nil, session.ID, []string{"identity", "oidc", "import", "--token", tc.token, "--provider", tc.provider}); err != nil {
			t.Fatalf("%s: %v", tc.provider, err)
		}
	}
}

func TestOIDCAudienceConfigFailsClosed(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := jwksTLSServer(t, &private.PublicKey)
	issuer := "https://issuer.example"
	pinOIDCProviders(t, issuer, server)
	token := signedOIDCTestToken(t, private, "kid", oidcClaims(issuer, "login-audience", "bob@example.com", nil, time.Now().Add(time.Hour).Unix()))
	session := &sys.Session{ID: "oidc-aud-config", User: "alice"}
	if err := sys.RegisterSession(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(session.ID) })

	t.Setenv("ADSSH_OIDC_LOGIN_AUDIENCE", "")
	for _, provider := range [][]string{nil, {"--provider", OIDCProviderLogin}} {
		_, err := runVBin(t, nil, session.ID, append([]string{"identity", "oidc", "import", "--token", token}, provider...))
		equalErr(t, err, "identity oidc import: oidc provider not configured: set ADSSH_OIDC_ISSUER, ADSSH_OIDC_JWKS_URL and ADSSH_OIDC_LOGIN_AUDIENCE")
	}
	t.Setenv("ADSSH_OIDC_LOGIN_AUDIENCE", "login-audience")
	t.Setenv("ADSSH_OIDC_ADMIN_AUDIENCE", "")
	_, err = runVBin(t, nil, session.ID, []string{"identity", "oidc", "import", "--token", token, "--provider", OIDCProviderAdmin})
	equalErr(t, err, "identity oidc import: oidc provider not configured: set ADSSH_OIDC_ADMIN_ISSUER, ADSSH_OIDC_ADMIN_JWKS_URL and ADSSH_OIDC_ADMIN_AUDIENCE")
	t.Setenv("ADSSH_OIDC_ADMIN_AUDIENCE", "login-audience")
	_, err = runVBin(t, nil, session.ID, []string{"identity", "oidc", "import", "--token", token, "--provider", OIDCProviderAdmin})
	equalErr(t, err, "identity oidc import: login and admin audiences must differ")
	assertOIDCUnset(t, session)
	if session.Info().User != "alice" {
		t.Fatalf("user changed to %q", session.Info().User)
	}
}
