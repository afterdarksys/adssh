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
	payload, err := json.Marshal(map[string]any{
		"iss":    "https://issuer.example",
		"aud":    []string{"adssh"},
		"email":  "alice@example.com",
		"groups": []string{"ops", "prod-admin"},
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	token := "header." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	_, user, groups, err := parseOIDCIdentity(context.Background(), oidcImportOptions{
		Token:      token,
		Issuer:     "https://issuer.example",
		Audience:   "adssh",
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

func TestParseOIDCIdentityDiscoversJWKS(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"jwks_uri": issuer + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(oidcJWKSet{Keys: []oidcJWK{rsaJWK("kid-1", &private.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	token := signedOIDCTestToken(t, private, "kid-1", map[string]any{
		"iss":    issuer,
		"aud":    []string{"adssh"},
		"email":  "alice@example.com",
		"groups": []string{"ops", "prod-admin"},
		"exp":    time.Now().Add(time.Hour).Unix(),
	})

	_, user, groups, err := parseOIDCIdentity(context.Background(), oidcImportOptions{
		Token:      token,
		Issuer:     issuer,
		Audience:   "adssh",
		UserClaim:  "email",
		GroupClaim: "groups",
		Discover:   true,
	})
	if err != nil {
		t.Fatalf("parseOIDCIdentity with discovery returned error: %v", err)
	}
	if user != "alice@example.com" || len(groups) != 2 {
		t.Fatalf("user=%q groups=%#v", user, groups)
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
