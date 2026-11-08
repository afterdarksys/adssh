//go:build ee

package security

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"golang.org/x/crypto/ssh"
	"mvdan.cc/sh/v3/interp"
)

func writeProxyFixture(t *testing.T, cfg proxyConfig) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_PROXY_CONFIG", path)
	return path
}

func TestProxyUserIsolationAndNativeForwarding(t *testing.T) {
	writeProxyFixture(t, proxyConfig{Users: map[string][]proxyTarget{
		"alice": {{Host: "app.internal", IP: "10.0.0.10", Port: 22}},
		"bob":   {{Host: "db.internal", IP: "10.0.0.20", Port: 5432}},
	}})
	eng, chain, _ := chainEngine(t)
	if err := eng.BindSessionIdentity("proxy-alice", "alice", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveProxy(eng, "proxy-alice", "app.internal", 22); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		sid, host string
		port      uint32
	}{
		{"proxy-alice", "db.internal", 5432}, {"proxy-alice", "app.internal", 23}, {"unknown", "app.internal", 22},
	} {
		if _, err := resolveProxy(eng, tc.sid, tc.host, tc.port); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	for _, action := range []string{"direct-tcpip", "connect", "start"} {
		req := GatewayPolicyRequest{User: "alice", Action: action, TargetHost: "app.internal", TargetIP: "10.0.0.10", TargetPort: 22}
		if err := eng.AuthorizeGateway(req); err != nil {
			t.Fatal(err)
		}
		req.TargetIP = "169.254.169.254"
		if err := eng.AuthorizeGateway(req); err == nil {
			t.Fatal("accepted changed address")
		}
		req.TargetHost, req.TargetIP, req.TargetPort = "db.internal", "10.0.0.20", 5432
		if err := eng.AuthorizeGateway(req); err == nil {
			t.Fatal("native forwarding bypassed user's list")
		}
	}
	data, err := os.ReadFile(chain)
	if err != nil || !strings.Contains(string(data), "app.internal") {
		t.Fatalf("missing audit: %s %v", data, err)
	}
}

func TestProxyConfigurationFailsClosed(t *testing.T) {
	for _, data := range []string{
		`{}`, `{"users":null}`, `{"users":{},"unexpected":true}`, `{"users":{}} {}`,
		`{"users":{"alice":[{"host":"app","ip":"not-ip","port":22}]}}`,
		`{"users":{"alice":[{"host":"app","ip":"10.0.0.1","port":0}]}}`,
		`{"users":{"alice":[{"host":"app","ip":"10.0.0.1","port":70000}]}}`,
		`{"users":{"alice":[{"host":"app","ip":"10.0.0.1","port":22,"user":"bob","host_key":"bad"}]}}`,
		strings.Repeat(" ", maxProxyConfig+1),
	} {
		if _, err := decodeProxyConfig([]byte(data)); err == nil {
			t.Fatal("accepted invalid configuration")
		}
	}
	path := writeProxyFixture(t, proxyConfig{Users: map[string][]proxyTarget{}})
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readProxyConfig(); err == nil {
		t.Fatal("accepted writable config")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADSSH_PROXY_CONFIG", link)
	if _, err := readProxyConfig(); err == nil {
		t.Fatal("accepted symlink")
	}
	t.Setenv("ADSSH_PROXY_CONFIG", path+"-missing")
	if _, err := readProxyConfig(); err == nil {
		t.Fatal("accepted missing config")
	}
	t.Setenv("ADSSH_PROXY_CONFIG", "")
	if _, err := readProxyConfig(); err == nil {
		t.Fatal("accepted unset config")
	}
}

func TestProxyPolicyAndAuditFailuresDeny(t *testing.T) {
	path := writeProxyFixture(t, proxyConfig{Users: map[string][]proxyTarget{"alice": {{Host: "app", IP: "10.0.0.1", Port: 22}}}})
	eng, chain, _ := chainEngine(t)
	if err := eng.BindSessionIdentity("proxy-deny", "alice", nil); err != nil {
		t.Fatal(err)
	}
	policy := []byte("package adssh.authz\ndefault allow = false\n")
	if err := eng.compilePolicy("proxy-deny.rego", policy); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveProxy(eng, "proxy-deny", "app", 22); err == nil {
		t.Fatal("bypassed policy")
	}
	src, err := os.ReadFile(filepath.Join("..", "policy", "examples", "proxy-only.rego"))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.compilePolicy("proxy-only.rego", src); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveProxy(eng, "proxy-deny", "app", 22); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"sh", "bash", "ssh", "curl", "http", "sys.exec_cmd"} {
		allowed, _, err := eng.EvaluatePolicy(PolicyContext{User: "alice", Command: cmd})
		if err != nil || allowed {
			t.Fatalf("policy permits %s: %v", cmd, err)
		}
	}
	breakChain(t, eng, chain)
	if _, err := resolveProxy(eng, "proxy-deny", "app", 22); err == nil {
		t.Fatal("bypassed failed audit")
	}
	if err := os.WriteFile(path, []byte(`{"users":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveProxy(eng, "proxy-deny", "app", 22); err == nil {
		t.Fatal("ignored removed grant")
	}
}

func TestProxyMonitorUsesBoundUserAndListsOnlyOwnTargets(t *testing.T) {
	writeProxyFixture(t, proxyConfig{Users: map[string][]proxyTarget{
		"alice": {{Host: "app", IP: "10.0.0.1", Port: 22}},
		"bob":   {{Host: "secret", IP: "10.0.0.2", Port: 22}},
	}})
	eng, _, _ := chainEngine(t)
	const sid = "proxy-monitor-alice"
	registerTestSession(t, &sys.Session{ID: sid, User: "alice"})
	c := dialMonitorRun(t, sid, func(ctx context.Context, args []string) error {
		return eng.AuthorizeCommandContext(ctx, args, sid)
	}, func(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) (int, error) {
		return eng.RunVBinForSession(ctx, sid, args, in, out, errOut)
	})
	sendRun(t, c, 1, []string{"proxy", "list"}, nil)
	res := readRun(t, c, 1)
	if res.exit.Code != 0 || strings.Contains(res.stdout.String(), "secret") || !strings.Contains(res.stdout.String(), "app") {
		t.Fatalf("list: %+v %s", res.exit, res.stdout.String())
	}
	sendRun(t, c, 2, []string{"proxy", "_resolve", "app", "22"}, nil)
	res = readRun(t, c, 2)
	if res.exit.Code != 0 {
		t.Fatalf("resolve: %+v %s", res.exit, res.stderr.String())
	}
	sendRun(t, c, 3, []string{"proxy", "_resolve", "secret", "22"}, nil)
	res = readRun(t, c, 3)
	if res.exit.Code == 0 {
		t.Fatal("resolved another user's target")
	}
	if err := sshListenerRunRefusal([]string{"proxy", "app", "22"}); err == nil {
		t.Fatal("listener accepted interactive session")
	}
}

func TestProxyTCPRoundTripAndCancellation(t *testing.T) {
	addr, stop := startGatewayEchoServer(t)
	defer stop()
	host, port, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(port)
	target := proxyTarget{Host: host, IP: host, Port: uint32(n)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var out bytes.Buffer
	err := proxyTCP(ctx, interp.HandlerContext{Stdin: strings.NewReader("hello\n"), Stdout: &out, Stderr: io.Discard}, target)
	if err != nil || out.String() != "echo: hello\n" {
		t.Fatalf("roundtrip: %q %v", out.String(), err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	cctx, ccancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxyTCP(cctx, interp.HandlerContext{Stdin: r, Stdout: io.Discard}, target) }()
	ccancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel stuck")
	}
}

func proxyTestKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(block)
}

func TestProxySSHAuthenticatesAndRejectsWrongHostKey(t *testing.T) {
	serverKey, _ := proxyTestKey(t)
	userKey, private := proxyTestKey(t)
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), private, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "target-user" || !bytes.Equal(key.Marshal(), userKey.PublicKey().Marshal()) {
			return nil, io.EOF
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(serverKey)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2; i++ {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				s, chans, reqs, e := ssh.NewServerConn(conn, config)
				if e != nil {
					return
				}
				defer s.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					stream, requests, e := ch.Accept()
					if e != nil {
						return
					}
					for req := range requests {
						if req.Type == "shell" {
							req.Reply(true, nil)
							stream.Write([]byte("internal-shell\n"))
							stream.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							stream.Close()
							return
						}
						req.Reply(false, nil)
					}
				}
			}()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(port)
	target := proxyTarget{Host: "app.internal", IP: host, Port: uint32(n), User: "target-user", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(serverKey.PublicKey())))}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out bytes.Buffer
	hc := interp.HandlerContext{Stdin: strings.NewReader(""), Stdout: &out, Stderr: io.Discard}
	if err := proxySSH(ctx, hc, target); err != nil || out.String() != "internal-shell\n" {
		t.Fatalf("SSH: %q %v", out.String(), err)
	}
	target.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(userKey.PublicKey())))
	if err := proxySSH(ctx, hc, target); err == nil {
		t.Fatal("accepted wrong host key")
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("server stuck")
	}
}
