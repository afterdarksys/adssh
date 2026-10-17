package sys

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func writeRevoked(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "revoked")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRevocationRefusesKeysCertsSerialsKeyIDsAndCAs(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	ca, user, raw := newEd25519Signer(t), newEd25519Signer(t), newEd25519Signer(t)
	keys := authorizedKeySet{
		userKeys:    map[string][]string{string(raw.PublicKey().Marshal()): {"alice"}},
		authorities: map[string]bool{string(ca.PublicKey().Marshal()): true},
	}
	cert := &ssh.Certificate{Key: user.PublicKey(), CertType: ssh.UserCert, Serial: 77, KeyId: "alice@laptop",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Minute).Unix())}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	conn := testConnMetadata{user: "alice"}
	login := func(path string, key ssh.PublicKey) error {
		_, err := publicKeyCallback(keys, SSHServerOptions{RevokedKeysPath: path})(conn, key)
		return err
	}
	clean := writeRevoked(t, "# nothing revoked\n\n")
	if login(clean, raw.PublicKey()) != nil || login(clean, cert) != nil {
		t.Fatal("unrevoked key or certificate refused")
	}
	for name, entry := range map[string]string{
		"raw key":  ssh.FingerprintSHA256(raw.PublicKey()),
		"cert key": ssh.FingerprintSHA256(user.PublicKey()),
		"CA":       ssh.FingerprintSHA256(ca.PublicKey()),
		"serial":   "serial:77",
		"key id":   "keyid:alice@laptop",
	} {
		p := writeRevoked(t, entry+"\n")
		key := ssh.PublicKey(cert)
		if name == "raw key" {
			key = raw.PublicKey()
		}
		if err := login(p, key); err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Errorf("%s revocation not enforced: %v", name, err)
		}
	}
}

func TestRevocationFailsClosed(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	raw := newEd25519Signer(t)
	keys := authorizedKeySet{userKeys: map[string][]string{string(raw.PublicKey().Marshal()): {"alice"}}, authorities: map[string]bool{}}
	for name, path := range map[string]string{
		"missing":    filepath.Join(t.TempDir(), "nope"),
		"malformed":  writeRevoked(t, "SHA256:ok\nnot an entry\n"),
		"bad serial": writeRevoked(t, "serial:abc\n"),
		"directory":  t.TempDir(),
	} {
		if _, err := publicKeyCallback(keys, SSHServerOptions{RevokedKeysPath: path})(testConnMetadata{user: "alice"}, raw.PublicKey()); err == nil {
			t.Errorf("%s revocation file let a login through", name)
		}
	}
}

func TestRevocationReloadsWhenFileChanges(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	raw := newEd25519Signer(t)
	keys := authorizedKeySet{userKeys: map[string][]string{string(raw.PublicKey().Marshal()): {"alice"}}, authorities: map[string]bool{}}
	p := writeRevoked(t, "# empty\n")
	cb := publicKeyCallback(keys, SSHServerOptions{RevokedKeysPath: p})
	if _, err := cb(testConnMetadata{user: "alice"}, raw.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(ssh.FingerprintSHA256(raw.PublicKey())+"\n# revoked now, longer file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cb(testConnMetadata{user: "alice"}, raw.PublicKey()); err == nil {
		t.Fatal("revocation added while running was not picked up")
	}
}
