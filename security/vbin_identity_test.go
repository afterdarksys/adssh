package security

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestParseOIDCIdentity(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := jwksTLSServer(t, &private.PublicKey)
	pinOIDCProviders(t, "https://issuer.example", server)
	token := signedOIDCTestToken(t, private, "kid", map[string]any{
		"iss":    "https://issuer.example",
		"aud":    []string{"login-audience"},
		"email":  "alice@example.com",
		"groups": []string{"ops", "prod-admin"},
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	_, user, groups, err := parseOIDCIdentity(context.Background(), oidcImportOptions{
		Token:      token,
		UserClaim:  "email",
		GroupClaim: "groups",
	})
	if err != nil {
		t.Fatalf("parseOIDCIdentity returned error: %v", err)
	}
	if user != "alice@example.com" {
		t.Fatalf("user = %q", user)
	}
	if len(groups) != 2 || groups[0] != "ops" || groups[1] != "prod-admin" {
		t.Fatalf("groups = %#v", groups)
	}
}

func TestParseOIDCIdentityRejectsUnsignedDefaultProvider(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := jwksTLSServer(t, &private.PublicKey)
	pinOIDCProviders(t, "https://issuer.example", server)
	payload, err := json.Marshal(map[string]any{
		"iss":   "https://issuer.example",
		"aud":   "login-audience",
		"email": "bob@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"kid"}`))
	token := header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	_, _, _, err = parseOIDCIdentity(context.Background(), oidcImportOptions{
		Token: token, UserClaim: "email", GroupClaim: "groups",
	})
	if err == nil || err.Error() != "identity oidc import: signature verification failed" {
		t.Fatalf("unsigned default-provider token: %v", err)
	}
}

func TestVerifyOIDCTokenSignatureFromJWKS(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := signedOIDCTestToken(t, private, "kid-1", map[string]any{
		"iss":    "https://issuer.example",
		"aud":    "adssh",
		"email":  "alice@example.com",
		"groups": []string{"ops"},
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	jwks := oidcJWKSet{Keys: []oidcJWK{rsaJWK("kid-1", &private.PublicKey)}}
	publicKey, err := selectOIDCRSAKey(jwks, "kid-1", "RS256")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("jwks public key did not verify signed token: %v", err)
	}
}

func TestParseOIDCIdentityUsesConfiguredJWKSOverTLS(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var fetched int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		fetched++
		_ = json.NewEncoder(w).Encode(oidcJWKSet{Keys: []oidcJWK{rsaJWK("kid-1", &private.PublicKey)}})
	}))
	t.Cleanup(server.Close)
	trustCallbackTLSServer(t, server)
	issuer := "https://issuer.example"
	t.Setenv("ADSSH_OIDC_ISSUER", issuer)
	t.Setenv("ADSSH_OIDC_JWKS_URL", server.URL+"/jwks")
	t.Setenv("ADSSH_OIDC_LOGIN_AUDIENCE", "adssh")
	t.Setenv("ADSSH_OIDC_ADMIN_AUDIENCE", "adssh-admin")
	token := signedOIDCTestToken(t, private, "kid-1", map[string]any{
		"iss":    issuer,
		"aud":    []string{"adssh"},
		"email":  "alice@example.com",
		"groups": []string{"ops", "prod-admin"},
		"iat":    time.Now().Unix(),
		"nbf":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Hour).Unix(),
	})

	_, user, groups, err := parseOIDCIdentity(context.Background(), oidcImportOptions{
		Token:      token,
		UserClaim:  "email",
		GroupClaim: "groups",
	})
	if err != nil {
		t.Fatalf("parseOIDCIdentity over pinned TLS JWKS returned error: %v", err)
	}
	if user != "alice@example.com" || len(groups) != 2 || fetched != 1 {
		t.Fatalf("user=%q groups=%#v fetched=%d", user, groups, fetched)
	}
}

func signedOIDCTestToken(t *testing.T, private *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"typ": "JWT", "alg": "RS256", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func rsaJWK(kid string, public *rsa.PublicKey) oidcJWK {
	e := big.NewInt(int64(public.E)).Bytes()
	return oidcJWK{
		KeyType:   "RSA",
		KeyID:     kid,
		Algorithm: "RS256",
		Use:       "sig",
		N:         base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(e),
	}
}

func TestIssueSSHCertificate(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca")
	userPath := filepath.Join(dir, "user.pub")
	certPath := filepath.Join(dir, "user-cert.pub")

	ca, err := sshKeygenRSA()
	if err != nil {
		t.Fatal(err)
	}
	user, err := sshKeygenRSA()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, ssh.MarshalAuthorizedKey(user.Public), 0o644); err != nil {
		t.Fatal(err)
	}

	cert, err := issueSSHCertificate(sshIssueOptions{
		CAPath:     caPath,
		PubPath:    userPath,
		OutPath:    certPath,
		Principals: []string{"alice", "ops"},
		TTL:        time.Minute,
	})
	if err != nil {
		t.Fatalf("issueSSHCertificate returned error: %v", err)
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("cert type = %d", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 2 || cert.ValidPrincipals[0] != "alice" || cert.ValidPrincipals[1] != "ops" {
		t.Fatalf("principals = %#v", cert.ValidPrincipals)
	}
	if cert.SignatureKey == nil || string(cert.SignatureKey.Marshal()) != string(ca.Public.Marshal()) {
		t.Fatal("certificate was not signed by generated CA")
	}
}
