package sys

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// auditCapture installs an audit hook for one test.
type auditCapture struct {
	mu     sync.Mutex
	events []string
	fail   error
}

func captureAudit(t *testing.T) *auditCapture {
	t.Helper()
	c := &auditCapture{}
	setSSHAudit(func(e string) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.fail != nil {
			return c.fail
		}
		c.events = append(c.events, e)
		return nil
	})
	t.Cleanup(func() { setSSHAudit(nil) })
	return c
}

func (c *auditCapture) matching(prefix string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, e := range c.events {
		if strings.HasPrefix(e, prefix+" ") {
			out = append(out, e)
		}
	}
	return out
}

func (c *auditCapture) waitFor(t *testing.T, prefix string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m := c.matching(prefix); len(m) > 0 {
			return m[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s event; have %v", prefix, c.matching(""))
	return ""
}

// startAuthSSH serves SSH with the real publicKeyCallback and auth logging.
func startAuthSSH(t *testing.T, keys authorizedKeySet, start SessionStarter) string {
	t.Helper()
	config := &ssh.ServerConfig{PublicKeyCallback: publicKeyCallback(keys, SSHServerOptions{}), AuthLogCallback: authLogCallback}
	config.AddHostKey(newEd25519Signer(t))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			nConn, err := listener.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conns.Done()
				handleSSHConnection(nConn, config, preAuthSlots, handshakeTimeout, start, nil)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; conns.Wait() })
	return listener.Addr().String()
}

func keySetFor(signer ssh.Signer, user string) authorizedKeySet {
	return authorizedKeySet{userKeys: map[string][]string{string(signer.PublicKey().Marshal()): {user}}, authorities: map[string]bool{}}
}

func dialWith(addr, user string, signer ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
}

func TestLoginOKIsAuditedWithFingerprint(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	audit := captureAudit(t)
	key := newEd25519Signer(t)
	addr := startAuthSSH(t, keySetFor(key, "alice"), newBlockingStarter().start)
	client, err := dialWith(addr, "alice", key)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ev := audit.waitFor(t, "SSH_LOGIN_OK")
	for _, want := range []string{`user="alice"`, "method=publickey", "key_fp=" + ssh.FingerprintSHA256(key.PublicKey())} {
		if !strings.Contains(ev, want) {
			t.Errorf("%q lacks %q", ev, want)
		}
	}
}

func TestLoginFailIsAuditedOncePerConnection(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	audit := captureAudit(t)
	good, bad1, bad2 := newEd25519Signer(t), newEd25519Signer(t), newEd25519Signer(t)
	addr := startAuthSSH(t, keySetFor(good, "alice"), newBlockingStarter().start)
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(bad1, bad2)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("unauthorized keys logged in")
	}
	ev := audit.waitFor(t, "SSH_LOGIN_FAIL")
	time.Sleep(100 * time.Millisecond)
	if n := len(audit.matching("SSH_LOGIN_FAIL")); n != 1 {
		t.Fatalf("%d SSH_LOGIN_FAIL events for one connection, want 1", n)
	}
	for _, want := range []string{`user="alice"`, ssh.FingerprintSHA256(bad1.PublicKey()), ssh.FingerprintSHA256(bad2.PublicKey())} {
		if !strings.Contains(ev, want) {
			t.Errorf("%q lacks %q", ev, want)
		}
	}
}

func TestPortProbeIsNotAudited(t *testing.T) {
	audit := captureAudit(t)
	addr := startAuthSSH(t, keySetFor(newEd25519Signer(t), "alice"), newBlockingStarter().start)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("SSH-2.0-probe\r\n"))
	_ = c.Close()
	time.Sleep(200 * time.Millisecond)
	if n := len(audit.matching("SSH_LOGIN_FAIL")); n != 0 {
		t.Fatalf("a bare probe wrote %d SSH_LOGIN_FAIL events", n)
	}
}

func TestLoginRefusedWhenAuditFails(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	audit := captureAudit(t)
	audit.fail = errors.New("chain unavailable")
	key := newEd25519Signer(t)
	b := newBlockingStarter()
	addr := startAuthSSH(t, keySetFor(key, "alice"), b.start)
	client, err := dialWith(addr, "alice", key)
	if err == nil {
		defer client.Close()
		if sess, err := client.NewSession(); err == nil {
			_ = sess.Shell()
			_ = sess.Close()
		}
	}
	time.Sleep(200 * time.Millisecond)
	if b.count() != 0 {
		t.Fatal("a session started although the login could not be audited")
	}
}

func TestSessionStartAndEndAreAudited(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	audit := captureAudit(t)
	key := newEd25519Signer(t)
	starter := func(sessionID, user string, principals []string, in io.ReadCloser, out, errOut io.Writer) error {
		return errors.New("spawn failed")
	}
	addr := startAuthSSH(t, keySetFor(key, "alice"), starter)
	client, err := dialWith(addr, "alice", key)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	start := audit.waitFor(t, "SSH_SESSION_START")
	end := audit.waitFor(t, "SSH_SESSION_END")
	if !strings.Contains(start, `user="alice"`) || !strings.Contains(end, "exit=-1 reason=error") {
		t.Fatalf("start %q end %q", start, end)
	}
}

func TestLoginFailRecordsAreRateLimitedPerSource(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	loginFailMu.Lock()
	origNow, origSrc := loginFailNow, loginFailSrc
	loginFailNow, loginFailSrc = func() time.Time { return now }, map[string]*failWindow{}
	loginFailMu.Unlock()
	t.Cleanup(func() { loginFailMu.Lock(); loginFailNow, loginFailSrc = origNow, origSrc; loginFailMu.Unlock() })

	for i := 0; i < loginFailBurst; i++ {
		if ok, _ := allowLoginFailRecord("198.51.100.7"); !ok {
			t.Fatalf("record %d refused inside the burst", i)
		}
	}
	for i := 0; i < 3; i++ {
		if ok, _ := allowLoginFailRecord("198.51.100.7"); ok {
			t.Fatal("record past the burst was allowed")
		}
	}
	if ok, _ := allowLoginFailRecord("203.0.113.9"); !ok {
		t.Fatal("a different source was limited")
	}
	now = now.Add(loginFailWindow)
	ok, suppressed := allowLoginFailRecord("198.51.100.7")
	if !ok || suppressed != 3 {
		t.Fatalf("next window: ok=%v suppressed=%d, want true 3", ok, suppressed)
	}
}

func TestClientControlledFieldsCannotForgeFields(t *testing.T) {
	if got := q(`alice key_fp=SHA256:forged`); got != `"alice key_fp=SHA256:forged"` {
		t.Fatalf("q = %s", got)
	}
	if got := q(strings.Repeat("a", 500)); len(got) > 132 {
		t.Fatalf("q did not cap: %d bytes", len(got))
	}
	if got := q("x\n SSH_LOGIN_OK user=\"root\""); strings.Contains(got, "\n") {
		t.Fatalf("q left a newline: %s", got)
	}
}

func TestExecRequestDetailNeverLogsTheCommand(t *testing.T) {
	payload := ssh.Marshal(struct{ Command string }{"curl -H 'Authorization: Bearer s3cret' https://x"})
	if d := requestDetail("exec", payload); strings.Contains(d, "s3cret") || !strings.Contains(d, "bytes") {
		t.Fatalf("exec detail %q", d)
	}
	env := ssh.Marshal(struct{ Name, Value string }{"AWS_SECRET_ACCESS_KEY", "s3cret"})
	if d := requestDetail("env", env); strings.Contains(d, "s3cret") || !strings.Contains(d, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("env detail %q", d)
	}
}

// A CA-signed certificate's own extensions must not set the audit fields.
func TestCertificateExtensionsCannotSpoofAuditFields(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	ca, user := newEd25519Signer(t), newEd25519Signer(t)
	keys := authorizedKeySet{userKeys: map[string][]string{}, authorities: map[string]bool{string(ca.PublicKey().Marshal()): true}}
	cert := &ssh.Certificate{
		Key: user.PublicKey(), CertType: ssh.UserCert, Serial: 42, KeyId: "alice@laptop",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Minute).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			extCertSerial: "999", extPubkeyFP: "SHA256:forged", extAuthMethod: "publickey", "permit-pty": "",
		}},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	presented := ssh.FingerprintSHA256(cert)
	perms, err := publicKeyCallback(keys, SSHServerOptions{})(testConnMetadata{user: "alice"}, cert)
	if err != nil {
		t.Fatal(err)
	}
	ext := perms.Extensions
	if ext[extCertSerial] != "42" || ext[extAuthMethod] != "cert" || ext[extPubkeyFP] != presented ||
		ext[extCertKeyID] != "alice@laptop" || ext[extCertCAFP] != ssh.FingerprintSHA256(ca.PublicKey()) {
		t.Fatalf("audit extensions taken from the certificate: %v", ext)
	}
	if cert.Extensions[extCertSerial] != "999" || ssh.FingerprintSHA256(cert) != presented {
		t.Fatal("the auth callback modified the presented certificate")
	}
}
