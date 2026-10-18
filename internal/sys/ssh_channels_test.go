//go:build unix

package sys

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startTestSSH serves SSH on a loopback port. Every key authenticates; the
// session starter and gateway authorizer are the test's.
func startTestSSH(t *testing.T, start SessionStarter, gw GatewayAuthorizer) string {
	t.Helper()
	hostKey := newEd25519Signer(t)
	config := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return &ssh.Permissions{Extensions: map[string]string{}}, nil
	}}
	config.AddHostKey(hostKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// serveSSH without the untracked goroutines, so cleanup can wait for
	// every connection before the next test swaps package hooks.
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
				handleSSHConnection(nConn, config, preAuthSlots, handshakeTimeout, start, gw)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		conns.Wait()
	})
	return listener.Addr().String()
}

func dialTestSSH(t *testing.T, addr, user string) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(newEd25519Signer(t))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// blockingStarter records each start and holds the session until the client
// closes it.
type blockingStarter struct {
	mu      sync.Mutex
	started []string
	terms   []string
	notify  chan string
}

func newBlockingStarter() *blockingStarter {
	return &blockingStarter{notify: make(chan string, 64)}
}

func (b *blockingStarter) start(sessionID, user string, principals []string, in io.ReadCloser, out, errOut io.Writer) error {
	term := ""
	if s := GetSession(sessionID); s != nil {
		term, _ = s.OverlayGet("TERM")
	}
	b.mu.Lock()
	b.started = append(b.started, sessionID)
	b.terms = append(b.terms, term)
	b.mu.Unlock()
	b.notify <- sessionID
	_, _ = io.Copy(io.Discard, in)
	return nil
}

func (b *blockingStarter) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.started)
}

func withTimeout[T any](t *testing.T, what string, fn func() T) T {
	t.Helper()
	ch := make(chan T, 1)
	go func() { ch <- fn() }()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: no reply within 3s", what)
	}
	var zero T
	return zero
}

func openShell(t *testing.T, client *ssh.Client, b *blockingStarter) *ssh.Session {
	t.Helper()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	select {
	case <-b.notify:
	case <-time.After(3 * time.Second):
		t.Fatal("session did not start after shell")
	}
	return sess
}

func TestSSHSessionRequestReplies(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	b := newBlockingStarter()
	addr := startTestSSH(t, b.start, nil)
	client := dialTestSSH(t, addr, "alice")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	for _, req := range []struct {
		name    string
		payload []byte
	}{
		{"exec", ssh.Marshal(struct{ Command string }{"id"})},
		{"subsystem", ssh.Marshal(struct{ Name string }{"sftp"})},
		{"env", ssh.Marshal(struct{ Name, Value string }{"LD_PRELOAD", "/tmp/x.so"})},
		{"x-unknown@example.com", nil},
	} {
		ok := withTimeout(t, req.name, func() bool {
			ok, err := sess.SendRequest(req.name, true, req.payload)
			return err == nil && ok
		})
		if ok {
			t.Fatalf("%s request was accepted", req.name)
		}
	}
	if err := withTimeout(t, "pty-req", func() error {
		return sess.RequestPty("vt220", 40, 80, ssh.TerminalModes{})
	}); err != nil {
		t.Fatalf("pty-req: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if b.count() != 0 {
		t.Fatal("session process started before the shell request")
	}
	if err := withTimeout(t, "shell", func() error { return sess.Shell() }); err != nil {
		t.Fatalf("shell: %v", err)
	}
	select {
	case <-b.notify:
	case <-time.After(3 * time.Second):
		t.Fatal("session did not start after shell")
	}
	b.mu.Lock()
	term := b.terms[0]
	b.mu.Unlock()
	if term != "vt220" {
		t.Fatalf("TERM = %q, want vt220", term)
	}
}

func TestSSHSessionNotStartedWithoutShell(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	b := newBlockingStarter()
	addr := startTestSSH(t, b.start, nil)
	client := dialTestSSH(t, addr, "alice")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	_ = sess.Close()
	time.Sleep(50 * time.Millisecond)
	if b.count() != 0 {
		t.Fatal("a session without a shell request started a session process")
	}
}

func TestSSHSessionCapPerConnection(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	prevConn, prevUser := maxSessionsPerConn, maxSessionsPerUser
	maxSessionsPerConn, maxSessionsPerUser = 2, 100
	t.Cleanup(func() { maxSessionsPerConn, maxSessionsPerUser = prevConn, prevUser })
	b := newBlockingStarter()
	addr := startTestSSH(t, b.start, nil)
	client := dialTestSSH(t, addr, "alice")
	openShell(t, client, b)
	openShell(t, client, b)
	if _, err := client.NewSession(); err == nil {
		t.Fatal("a third session opened on a connection capped at 2")
	}
	other := dialTestSSH(t, addr, "alice")
	openShell(t, other, b)
}

func TestSSHSessionCapPerUser(t *testing.T) {
	stubUsers(t, map[string]string{"erin": "1001", "frank": "1002"})
	prevConn, prevUser := maxSessionsPerConn, maxSessionsPerUser
	maxSessionsPerConn, maxSessionsPerUser = 4, 2
	t.Cleanup(func() { maxSessionsPerConn, maxSessionsPerUser = prevConn, prevUser })
	b := newBlockingStarter()
	addr := startTestSSH(t, b.start, nil)
	first := dialTestSSH(t, addr, "erin")
	held := openShell(t, first, b)
	openShell(t, first, b)
	second := dialTestSSH(t, addr, "erin")
	if _, err := second.NewSession(); err == nil {
		t.Fatal("erin opened a third session past a per-user cap of 2")
	}
	openShell(t, dialTestSSH(t, addr, "frank"), b)

	_ = held.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		sess, err := second.NewSession()
		if err == nil {
			_ = sess.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closing a session did not release its per-user slot")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// holdListener accepts connections and keeps them open until the test ends.
func holdListener(t *testing.T) (string, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return "127.0.0.1", port
}

func TestGatewayDirectTCPIPCapPerConnection(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	prev := maxDirectTCPIPPerConn
	maxDirectTCPIPPerConn = 1
	t.Cleanup(func() { maxDirectTCPIPPerConn = prev })
	host, port := holdListener(t)
	addr := startTestSSH(t, newBlockingStarter().start, func(GatewayAuthRequest) error { return nil })
	client := dialTestSSH(t, addr, "alice")
	first, err := client.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := client.Dial("tcp", net.JoinHostPort(host, port)); err == nil {
		_ = second.Close()
		t.Fatal("a second forwarded channel opened past a cap of 1")
	}
	_ = first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := client.Dial("tcp", net.JoinHostPort(host, port))
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closing a forwarded channel did not release its slot")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestGatewayDirectTCPIPResolvesOnceAndAuthorizesOnce(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	_, port := holdListener(t)
	prevLookup := gatewayLookupIP
	var lookups int
	var lookupMu sync.Mutex
	gatewayLookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		lookupMu.Lock()
		lookups++
		lookupMu.Unlock()
		if host != "db.example" {
			return nil, errors.New("no such host")
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	t.Cleanup(func() { gatewayLookupIP = prevLookup })

	var mu sync.Mutex
	var seen []GatewayAuthRequest
	denyIP := false
	gw := func(req GatewayAuthRequest) error {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, req)
		if denyIP && req.TargetIP == "127.0.0.1" {
			return errors.New("address denied")
		}
		return nil
	}
	addr := startTestSSH(t, newBlockingStarter().start, gw)
	client := dialTestSSH(t, addr, "alice")
	c, err := client.Dial("tcp", net.JoinHostPort("db.example", port))
	if err != nil {
		t.Fatalf("dial through gateway: %v", err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through gateway: %q %v", buf, err)
	}
	_ = c.Close()

	mu.Lock()
	got := append([]GatewayAuthRequest(nil), seen...)
	mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("authorize calls = %d, want one decision: %+v", len(got), got)
	}
	if got[0].TargetHost != "db.example" || got[0].TargetIP != "127.0.0.1" || got[0].TargetPort == 0 {
		t.Fatalf("decision input = %+v", got[0])
	}
	lookupMu.Lock()
	n := lookups
	lookupMu.Unlock()
	if n != 1 {
		t.Fatalf("lookups = %d, want 1", n)
	}

	mu.Lock()
	denyIP = true
	mu.Unlock()
	if c, err := client.Dial("tcp", net.JoinHostPort("db.example", port)); err == nil {
		_ = c.Close()
		t.Fatal("a name was forwarded although its resolved address is denied")
	}
	if c, err := client.Dial("tcp", net.JoinHostPort("nowhere.example", port)); err == nil {
		_ = c.Close()
		t.Fatal("an unresolvable name was forwarded")
	}
}

func TestGatewayDirectTCPIPDialHasTimeout(t *testing.T) {
	if gatewayDialTimeout != 10*time.Second {
		t.Fatalf("gatewayDialTimeout = %v, want 10s", gatewayDialTimeout)
	}
	stubUsers(t, map[string]string{"alice": "1001"})
	prevDial := gatewayDial
	var gotTimeout time.Duration
	var gotAddr string
	gatewayDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		gotAddr, gotTimeout = address, timeout
		return nil, errors.New("refused")
	}
	t.Cleanup(func() { gatewayDial = prevDial })
	addr := startTestSSH(t, newBlockingStarter().start, func(GatewayAuthRequest) error { return nil })
	client := dialTestSSH(t, addr, "alice")
	if c, err := client.Dial("tcp", "127.0.0.1:5432"); err == nil {
		_ = c.Close()
		t.Fatal("dial error was ignored")
	}
	if gotTimeout != gatewayDialTimeout || gotAddr != "127.0.0.1:5432" {
		t.Fatalf("dial %q timeout %v", gotAddr, gotTimeout)
	}
}

func TestCertificatePrincipalsCarriedAsJSON(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	ca := newEd25519Signer(t)
	userKey := newEd25519Signer(t)
	keys, err := loadAuthorizedKeys(writeAuthorizedKeys(t, authorizedLine("cert-authority", ca.PublicKey())))
	if err != nil {
		t.Fatal(err)
	}
	callback := publicKeyCallback(keys, SSHServerOptions{})
	sign := func(principals []string) *ssh.Certificate {
		cert := &ssh.Certificate{
			Key:             userKey.PublicKey(),
			CertType:        ssh.UserCert,
			ValidPrincipals: principals,
			ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
			ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		}
		if err := cert.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	perms, err := callback(testConnMetadata{user: "alice"}, sign([]string{"alice", "ops,admin"}))
	if err != nil {
		t.Fatal(err)
	}
	var raw []string
	if err := json.Unmarshal([]byte(perms.Extensions["principals"]), &raw); err != nil {
		t.Fatalf("principals extension is not a JSON array: %q", perms.Extensions["principals"])
	}
	got, err := principalsFromPermissions(perms)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "alice" || got[1] != "ops,admin" {
		t.Fatalf("principals = %#v", got)
	}

	for _, bad := range []string{"-rf", "a\x00b", ""} {
		if _, err := callback(testConnMetadata{user: "alice"}, sign([]string{"alice", bad})); err == nil {
			t.Fatalf("principal %q was accepted", bad)
		}
	}

	if got, err := principalsFromPermissions(&ssh.Permissions{}); err != nil || got != nil {
		t.Fatalf("no principals = %#v %v", got, err)
	}
	for _, ext := range []string{"alice,bob", `["-x"]`, `[1]`, `["a"] x`} {
		if _, err := principalsFromPermissions(&ssh.Permissions{Extensions: map[string]string{"principals": ext}}); err == nil {
			t.Fatalf("extension %q was accepted", ext)
		}
	}
}

// A session's exit code or signal reaches the client, after its last output.
// Without exit-status, OpenSSH exits 255 whatever the session did.
func TestSSHSessionSendsExitStatusAfterOutput(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	for _, tc := range []struct {
		name   string
		script string
		code   int
		signal string
	}{
		{"exit code", "exit 3", 3, ""},
		{"clean exit", "exit 0", 0, ""},
		{"signal", "kill -TERM $$", -1, "TERM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := func(_, _ string, _ []string, _ io.ReadCloser, out, _ io.Writer) error {
				_, _ = io.WriteString(out, "last line of output\r\n")
				return exec.Command("/bin/sh", "-c", tc.script).Run()
			}
			addr := startTestSSH(t, start, nil)
			client := dialTestSSH(t, addr, "alice")
			sess, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			var stdout strings.Builder
			sess.Stdout = &stdout
			if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
				t.Fatal(err)
			}
			if err := sess.Shell(); err != nil {
				t.Fatal(err)
			}
			err = withTimeout(t, "session end", func() error { return sess.Wait() })
			if !strings.Contains(stdout.String(), "last line of output") {
				t.Fatalf("last output lost: %q", stdout.String())
			}
			if tc.code == 0 && tc.signal == "" {
				if err != nil {
					t.Fatalf("clean exit: %v", err)
				}
				return
			}
			var exitErr *ssh.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("got %v (%T), want *ssh.ExitError", err, err)
			}
			if tc.signal != "" && exitErr.Signal() != tc.signal {
				t.Fatalf("signal %q, want %q", exitErr.Signal(), tc.signal)
			}
			if tc.signal == "" && exitErr.ExitStatus() != tc.code {
				t.Fatalf("exit status %d, want %d", exitErr.ExitStatus(), tc.code)
			}
		})
	}
}

// Only LANG and LC_* with plain locale values are accepted, and only before
// the shell starts.
func TestSSHSessionAcceptsOnlyClientLocale(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001"})
	var lang, lcAll, path string
	gotEnv := make(chan struct{})
	start := func(sessionID, _ string, _ []string, in io.ReadCloser, _, _ io.Writer) error {
		if s := GetSession(sessionID); s != nil {
			lang, _ = s.OverlayGet("LANG")
			lcAll, _ = s.OverlayGet("LC_ALL")
			path, _ = s.OverlayGet("PATH")
		}
		close(gotEnv)
		_, _ = io.Copy(io.Discard, in)
		return nil
	}
	addr := startTestSSH(t, start, nil)
	client := dialTestSSH(t, addr, "alice")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	send := func(name, value string) bool {
		return withTimeout(t, "env "+name, func() bool {
			ok, err := sess.SendRequest("env", true, ssh.Marshal(struct{ Name, Value string }{name, value}))
			return err == nil && ok
		})
	}
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"LANG", "en_US.UTF-8", true},
		{"LC_ALL", "sr_RS@latin", true},
		{"LC_CTYPE", "en_US.UTF-8;rm -rf /", false},
		{"LC_TIME", "", false},
		{"LC_BOGUS", "C", false},
		{"PATH", "/tmp", false},
		{"LD_PRELOAD", "/tmp/x.so", false},
		{"LANG\x00X", "C", false},
	} {
		if got := send(tc.name, tc.value); got != tc.want {
			t.Errorf("env %q=%q accepted=%v, want %v", tc.name, tc.value, got, tc.want)
		}
	}
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gotEnv:
	case <-time.After(3 * time.Second):
		t.Fatal("session did not start")
	}
	if lang != "en_US.UTF-8" || lcAll != "sr_RS@latin" || path != "" {
		t.Fatalf("LANG %q LC_ALL %q PATH %q", lang, lcAll, path)
	}
	if send("LANG", "C") {
		t.Fatal("env after the shell started was accepted")
	}
}
