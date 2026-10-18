package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

// trustCallbackTLSServer adds an httptest TLS server's certificate to the
// callback client's root pool for the duration of the test.
func trustCallbackTLSServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	prev := callbackTLSRoots.Swap(pool)
	t.Cleanup(func() { callbackTLSRoots.Store(prev) })
}

func selfSignedLoopbackCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "untrusted"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// pinOIDCProviders configures the default, login, and admin providers to the
// given issuer and a TLS JWKS server the callback client trusts.
func pinOIDCProviders(t *testing.T, issuer string, server *httptest.Server) {
	t.Helper()
	trustCallbackTLSServer(t, server)
	t.Setenv("ADSSH_OIDC_ISSUER", issuer)
	t.Setenv("ADSSH_OIDC_JWKS_URL", server.URL)
	t.Setenv("ADSSH_OIDC_ADMIN_ISSUER", issuer)
	t.Setenv("ADSSH_OIDC_ADMIN_JWKS_URL", server.URL)
	t.Setenv("ADSSH_OIDC_LOGIN_AUDIENCE", "login-audience")
	t.Setenv("ADSSH_OIDC_ADMIN_AUDIENCE", "admin-audience")
}

func pinControlPlane(t *testing.T, server *httptest.Server) {
	t.Helper()
	trustCallbackTLSServer(t, server)
	t.Setenv("ADSSH_CONTROLPLANE_URL", server.URL)
}

// --- P0: OIDC import trusts only operator-pinned issuer and JWKS ---

// --- P1: device login origin is pinned by ADSSH_CONTROLPLANE_URL ---

func deviceSession(t *testing.T, id string) context.Context {
	t.Helper()
	if err := sys.RegisterSession(&sys.Session{ID: id, User: "alice"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.UnregisterSession(id) })
	return WithSessionID(context.Background(), id)
}

// --- P2: token file write ---

// --- P3: callback IP ranges ---

func TestCallbackIPBlocksPrivateRanges(t *testing.T) {
	t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", "")
	private := []string{"10.0.0.1", "172.16.5.4", "192.168.1.1", "100.64.0.1", "100.127.255.254", "fc00::1", "fd12:3456::1", "::ffff:10.0.0.1"}
	always := []string{"169.254.169.254", "169.254.1.1", "fe80::1", "fd00:ec2::254", "0.0.0.0", "::", "224.0.0.1"}
	public := []string{"8.8.8.8", "100.128.0.1", "2001:4860:4860::8888", "172.32.0.1"}
	for _, raw := range append(append([]string{}, private...), always...) {
		if !callbackIPBlocked(net.ParseIP(raw)) {
			t.Fatalf("%s allowed", raw)
		}
	}
	for _, raw := range public {
		if callbackIPBlocked(net.ParseIP(raw)) {
			t.Fatalf("%s blocked", raw)
		}
	}
	for _, raw := range []string{"https://10.0.0.1/x", "https://100.64.1.1/x", "https://[fd00::1]/x"} {
		if _, err := validateCallbackURL(raw); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	for _, v := range []string{"0", "on", "no"} {
		t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", v)
		if !callbackIPBlocked(net.ParseIP("10.0.0.1")) {
			t.Fatalf("override %q admitted private", v)
		}
	}
	t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", "1")
	for _, raw := range private {
		if callbackIPBlocked(net.ParseIP(raw)) {
			t.Fatalf("override did not admit %s", raw)
		}
	}
	for _, raw := range always {
		if !callbackIPBlocked(net.ParseIP(raw)) {
			t.Fatalf("override admitted %s", raw)
		}
	}
	if _, err := validateCallbackURL("https://10.0.0.1/x"); err != nil {
		t.Fatalf("override url: %v", err)
	}
}

func TestCallbackDialControlChecksConnectedIP(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	// A hostname that resolves to loopback is refused at connect time even
	// though validateCallbackURL was bypassed.
	if conn, err := callbackDialContext(context.Background(), "tcp", net.JoinHostPort("localhost", port)); err == nil {
		conn.Close()
		t.Fatal("dial to localhost-resolved loopback succeeded")
	}
	// A literal loopback address is the one form admitted.
	conn, err := callbackDialContext(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("literal loopback: %v", err)
	}
	conn.Close()
	// A private literal is refused at connect time without the override.
	t.Setenv("ADSSH_CALLBACK_ALLOW_PRIVATE", "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := callbackDialContext(ctx, "tcp", "10.255.255.1:443"); err == nil {
		conn.Close()
		t.Fatal("private dial succeeded")
	} else if !strings.Contains(err.Error(), errDialDenied.Error()) {
		t.Fatalf("private dial error %v", err)
	}
}

// --- P3: audit webhook ---

func TestAuditWebhookRejectsPlaintextAtEngineConstruction(t *testing.T) {
	dir := t.TempDir()
	for _, raw := range []string{"http://siem.example/hook", "http://127.0.0.1:9/hook", "https://169.254.169.254/x", "https://10.0.0.8/hook"} {
		_, err := NewEngine(EngineConfig{AuditLogPath: filepath.Join(dir, "audit.log"), AuditLogURL: raw, AuditLogToken: "bearer-xyz"})
		if err == nil || !strings.Contains(err.Error(), "audit webhook URL rejected") {
			t.Fatalf("%s: %v", raw, err)
		}
		if strings.Contains(err.Error(), "bearer-xyz") {
			t.Fatal("error leaked token")
		}
	}
}

func TestAuditWebhookPostsOverTLS(t *testing.T) {
	var mu sync.Mutex
	got := make(chan string, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		select {
		case got <- r.Header.Get("Authorization"):
		default:
		}
	}))
	t.Cleanup(server.Close)
	trustCallbackTLSServer(t, server)
	eng, err := NewEngine(EngineConfig{AuditLogPath: filepath.Join(t.TempDir(), "audit.log"), AuditLogURL: server.URL + "/hook", AuditLogToken: "bearer-xyz"})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.LogCommand("test", "echo hi"); err != nil {
		t.Fatal(err)
	}
	select {
	case auth := <-got:
		if auth != "Bearer bearer-xyz" {
			t.Fatalf("authorization %q", auth)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook not delivered")
	}
}

// --- Audit-before-identity ordering ---

func failAuditSync(t *testing.T) {
	t.Helper()
	orig := syncFile
	syncFile = func(*os.File) error { return errors.New("sync forced") }
	t.Cleanup(func() { syncFile = orig })
}

// --- Audience pinning: a token for one audience cannot serve another ---
