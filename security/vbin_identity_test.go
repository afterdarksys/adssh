package security

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
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
	_, user, groups, err := parseOIDCIdentity(oidcImportOptions{
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
