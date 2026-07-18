package sys

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type testConnMetadata struct{ user string }

func (m testConnMetadata) User() string          { return m.user }
func (m testConnMetadata) SessionID() []byte     { return []byte("test") }
func (m testConnMetadata) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (m testConnMetadata) ServerVersion() []byte { return []byte("SSH-2.0-adssh") }
func (m testConnMetadata) RemoteAddr() net.Addr  { return &net.TCPAddr{} }
func (m testConnMetadata) LocalAddr() net.Addr   { return &net.TCPAddr{} }

func newEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestPublicKeyCallbackValidatesCertificatesAndSeparatesCAKeys(t *testing.T) {
	caSigner := newEd25519Signer(t)
	userSigner := newEd25519Signer(t)
	directSigner := newEd25519Signer(t)

	authorizedKeysPath := filepath.Join(t.TempDir(), "authorized_keys")
	contents := append([]byte("cert-authority "), ssh.MarshalAuthorizedKey(caSigner.PublicKey())...)
	contents = append(contents, ssh.MarshalAuthorizedKey(directSigner.PublicKey())...)
	if err := os.WriteFile(authorizedKeysPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := loadAuthorizedKeys(authorizedKeysPath)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	callback := publicKeyCallback(keys)
	conn := testConnMetadata{user: "alice"}

	valid := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Minute).Unix()),
	}
	if err := valid.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	if _, err := callback(conn, valid); err != nil {
		t.Fatalf("valid user certificate rejected: %v", err)
	}

	forged := *valid
	forged.Signature = nil
	if _, err := callback(conn, &forged); err == nil {
		t.Fatal("certificate with missing CA signature was accepted")
	}

	wrongPrincipal := *valid
	wrongPrincipal.ValidPrincipals = []string{"bob"}
	if err := wrongPrincipal.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert wrong principal: %v", err)
	}
	if _, err := callback(conn, &wrongPrincipal); err == nil {
		t.Fatal("certificate for a different login principal was accepted")
	}

	if _, err := callback(conn, directSigner.PublicKey()); err != nil {
		t.Fatalf("directly authorized user key rejected: %v", err)
	}
	if _, err := callback(conn, caSigner.PublicKey()); err == nil {
		t.Fatal("certificate-authority key was also accepted as a direct user key")
	}
}
