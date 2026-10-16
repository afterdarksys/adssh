//go:build unix

package sys

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// stubUsers makes lookupUser resolve only the given name -> uid pairs.
func stubUsers(t *testing.T, uids map[string]string) {
	t.Helper()
	orig := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		uid, ok := uids[name]
		if !ok {
			return nil, user.UnknownUserError(name)
		}
		return &user.User{Username: name, Uid: uid, Gid: uid}, nil
	}
	t.Cleanup(func() { lookupUser = orig })
}

func writeAuthorizedKeys(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func authorizedLine(options string, key ssh.PublicKey) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if options == "" {
		return line + "\n"
	}
	return options + " " + line + "\n"
}

func TestRawKeyIsBoundToLoginNames(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001", "bob": "1002", "root": "0", "toor": "0"})
	aliceKey := newEd25519Signer(t)
	rootKey := newEd25519Signer(t)
	toorKey := newEd25519Signer(t)
	unlisted := newEd25519Signer(t)
	path := writeAuthorizedKeys(t,
		authorizedLine(`user="alice"`, aliceKey.PublicKey())+
			authorizedLine(`user="root,alice"`, rootKey.PublicKey())+
			authorizedLine(`user="toor"`, toorKey.PublicKey()))
	keys, err := loadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}

	cases := []struct {
		name       string
		user       string
		key        ssh.PublicKey
		permitRoot bool
		ok         bool
	}{
		{"bound key accepted for its user", "alice", aliceKey.PublicKey(), false, true},
		{"bound key rejected for another user", "bob", aliceKey.PublicKey(), false, false},
		{"bound key rejected for root", "root", aliceKey.PublicKey(), false, false},
		{"root-bound key rejected when root is not permitted", "root", rootKey.PublicKey(), false, false},
		{"uid 0 alias rejected when root is not permitted", "toor", toorKey.PublicKey(), false, false},
		{"root-bound key accepted when root is permitted", "root", rootKey.PublicKey(), true, true},
		{"root permitted does not unbind the key", "root", aliceKey.PublicKey(), true, false},
		{"multi-name key accepted for second name", "alice", rootKey.PublicKey(), false, true},
		{"unlisted key rejected", "alice", unlisted.PublicKey(), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			callback := publicKeyCallback(keys, SSHServerOptions{PermitRoot: tc.permitRoot})
			_, err := callback(testConnMetadata{user: tc.user}, tc.key)
			if tc.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("accepted")
			}
			if err != nil && strings.Contains(err.Error(), tc.user) {
				t.Fatalf("error echoes the login name: %v", err)
			}
		})
	}
}

func TestRootGateFailsClosedOnLookupError(t *testing.T) {
	stubUsers(t, map[string]string{})
	key := newEd25519Signer(t)
	keys, err := loadAuthorizedKeys(writeAuthorizedKeys(t, authorizedLine(`user="ghost"`, key.PublicKey())))
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if _, err := publicKeyCallback(keys, SSHServerOptions{})(testConnMetadata{user: "ghost"}, key.PublicKey()); err == nil {
		t.Fatal("unresolvable login name was accepted")
	}
}

func TestLoadAuthorizedKeysRequiresUserOption(t *testing.T) {
	key := newEd25519Signer(t)
	cases := []struct {
		name    string
		options string
		wantErr string
	}{
		{"no options", "", "line 1"},
		{"empty value", `user=""`, "line 1"},
		{"empty name in list", `user="alice,"`, "line 1"},
		{"whitespace in name", `user="alice, bob"`, "line 1"},
		{"slash in name", `user="../alice"`, "line 1"},
		{"unquoted value", `user=alice`, "line 1"},
		{"user on a cert-authority line", `cert-authority,user="alice"`, "line 1"},
		{"unknown option", `no-pty`, "line 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadAuthorizedKeys(writeAuthorizedKeys(t, authorizedLine(tc.options, key.PublicKey())))
			if err == nil {
				t.Fatal("loaded")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not name %q", err, tc.wantErr)
			}
		})
	}
	_, err := loadAuthorizedKeys(writeAuthorizedKeys(t, authorizedLine("", key.PublicKey())))
	if err == nil || !strings.Contains(err.Error(), `user="`) {
		t.Fatalf("missing user= error does not say how to fix it: %v", err)
	}
}

func TestCertificateIsBoundToPrincipals(t *testing.T) {
	stubUsers(t, map[string]string{"alice": "1001", "bob": "1002"})
	ca := newEd25519Signer(t)
	otherCA := newEd25519Signer(t)
	userKey := newEd25519Signer(t)
	keys, err := loadAuthorizedKeys(writeAuthorizedKeys(t, authorizedLine("cert-authority", ca.PublicKey())))
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	callback := publicKeyCallback(keys, SSHServerOptions{})

	sign := func(principals []string, before time.Time, signer ssh.Signer) *ssh.Certificate {
		cert := &ssh.Certificate{
			Key:             userKey.PublicKey(),
			CertType:        ssh.UserCert,
			ValidPrincipals: principals,
			ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
			ValidBefore:     uint64(before.Unix()),
		}
		if err := cert.SignCert(rand.Reader, signer); err != nil {
			t.Fatalf("SignCert: %v", err)
		}
		return cert
	}
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name string
		user string
		cert *ssh.Certificate
		ok   bool
	}{
		{"principal matches", "alice", sign([]string{"alice"}, future, ca), true},
		{"principal does not match", "bob", sign([]string{"alice"}, future, ca), false},
		{"zero principals", "alice", sign(nil, future, ca), false},
		{"unlisted CA", "alice", sign([]string{"alice"}, future, otherCA), false},
		{"expired", "alice", sign([]string{"alice"}, time.Now().Add(-time.Minute), ca), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := callback(testConnMetadata{user: tc.user}, tc.cert)
			if tc.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestCertificateForRootIsGated(t *testing.T) {
	stubUsers(t, map[string]string{"root": "0"})
	ca := newEd25519Signer(t)
	userKey := newEd25519Signer(t)
	keys, err := loadAuthorizedKeys(writeAuthorizedKeys(t, authorizedLine("cert-authority", ca.PublicKey())))
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             userKey.PublicKey(),
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"root"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	if _, err := publicKeyCallback(keys, SSHServerOptions{})(testConnMetadata{user: "root"}, cert); err == nil {
		t.Fatal("root certificate accepted without PermitRoot")
	}
	if _, err := publicKeyCallback(keys, SSHServerOptions{PermitRoot: true})(testConnMetadata{user: "root"}, cert); err != nil {
		t.Fatalf("root certificate rejected with PermitRoot: %v", err)
	}
}

func sshString(s string) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	copy(b[4:], s)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func ptyPayload(term string, cols, rows uint32, modes string) []byte {
	var b []byte
	b = append(b, sshString(term)...)
	b = append(b, u32(cols)...)
	b = append(b, u32(rows)...)
	b = append(b, u32(0)...)
	b = append(b, u32(0)...)
	b = append(b, sshString(modes)...)
	return b
}

func TestApplyPTYRequestRejectsMalformedPayloads(t *testing.T) {
	valid := ptyPayload("xterm-256color", 132, 43, "\x00")
	cases := []struct {
		name     string
		payload  []byte
		ok       bool
		wantCols uint16
		wantRows uint16
	}{
		{"empty", nil, false, 0, 0},
		{"three bytes", []byte{0, 0, 0}, false, 0, 0},
		{"truncated term", append(u32(10), []byte("xte")...), false, 0, 0},
		{"term length exceeds payload", append(u32(0xffffffff), []byte("xterm")...), false, 0, 0},
		{"truncated dimensions", append(sshString("xterm"), 0, 0, 0, 80, 0, 0), false, 0, 0},
		{"trailing junk", append(append([]byte{}, valid...), 1), false, 0, 0},
		{"oversized term", ptyPayload(strings.Repeat("x", 65), 80, 24, ""), false, 0, 0},
		{"absurd dimensions are clamped", ptyPayload("xterm", 0xffffffff, 70000, ""), true, 1000, 1000},
		{"zero dimensions default", ptyPayload("xterm", 0, 0, ""), true, 80, 24},
		{"valid", valid, true, 132, 43},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *pty.Winsize
			ok := applyPTYRequest(func(ws *pty.Winsize) error { got = ws; return nil }, tc.payload)
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v", ok, tc.ok)
			}
			if !tc.ok {
				if got != nil {
					t.Fatalf("size applied on a rejected payload: %+v", got)
				}
				return
			}
			if got == nil || got.Cols != tc.wantCols || got.Rows != tc.wantRows {
				t.Fatalf("size %+v want %dx%d", got, tc.wantCols, tc.wantRows)
			}
		})
	}
	if applyPTYRequest(func(*pty.Winsize) error { return errors.New("no pty") }, valid) {
		t.Fatal("setter failure reported success")
	}
}

func TestApplyWindowChangeRejectsMalformedPayloads(t *testing.T) {
	dims := func(c, r uint32) []byte {
		return append(append(append(u32(c), u32(r)...), u32(0)...), u32(0)...)
	}
	cases := []struct {
		name     string
		payload  []byte
		ok       bool
		wantCols uint16
		wantRows uint16
	}{
		{"empty", nil, false, 0, 0},
		{"three bytes", []byte{0, 0, 0}, false, 0, 0},
		{"truncated dimensions", u32(80), false, 0, 0},
		{"absurd dimensions are clamped", dims(5000, 0xffffffff), true, 1000, 1000},
		{"valid", dims(200, 50), true, 200, 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *pty.Winsize
			ok := applyWindowChange(func(ws *pty.Winsize) error { got = ws; return nil }, tc.payload)
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v", ok, tc.ok)
			}
			if !tc.ok {
				if got != nil {
					t.Fatalf("size applied on a rejected payload: %+v", got)
				}
				return
			}
			if got == nil || got.Cols != tc.wantCols || got.Rows != tc.wantRows {
				t.Fatalf("size %+v want %dx%d", got, tc.wantCols, tc.wantRows)
			}
		})
	}
}

// readBanner reads the server's version line, or returns "" if the server
// closed the connection without sending one.
func readBanner(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil && err != io.EOF {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("no banner and no close within 5s")
		}
	}
	return line
}

func TestServeSSHBoundsPreAuthHandshakes(t *testing.T) {
	origSlots, origTimeout := preAuthSlots, handshakeTimeout
	preAuthSlots = make(chan struct{}, 1)
	handshakeTimeout = 700 * time.Millisecond
	t.Cleanup(func() { preAuthSlots, handshakeTimeout = origSlots, origTimeout })

	hostKey := newEd25519Signer(t)
	config := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, errors.New("no")
	}}
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { serveSSH(listener, config, nil, nil); close(done) }()
	t.Cleanup(func() { _ = listener.Close(); <-done })

	addr := listener.Addr().String()
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	firstReader := bufio.NewReader(first)
	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	banner, err := firstReader.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "SSH-2.0-") {
		t.Fatalf("first connection got no banner: %q %v", banner, err)
	}
	start := time.Now()

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := readBanner(t, second); got != "" {
		t.Fatalf("second connection was served while the slot was held: %q", got)
	}
	if elapsed := time.Since(start); elapsed >= handshakeTimeout {
		t.Fatalf("second connection was not refused immediately (%v)", elapsed)
	}

	// The stalled first connection is closed by the server at the deadline.
	_, err = firstReader.ReadByte()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("first connection still open")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("server never closed the stalled handshake")
	}
	if elapsed < handshakeTimeout/2 {
		t.Fatalf("first connection closed before the deadline (%v)", elapsed)
	}

	// The slot is released: a later connection gets a real handshake.
	deadline := time.Now().Add(3 * time.Second)
	for {
		third, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		got := readBanner(t, third)
		_ = third.Close()
		if strings.HasPrefix(got, "SSH-2.0-") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot was not released after the stalled handshake closed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
