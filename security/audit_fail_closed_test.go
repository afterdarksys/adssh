package security

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
	"golang.org/x/crypto/ssh"
)

// These tests prove that each audited action below does not happen when its
// audit record cannot be written: breakChain makes every later append fail.

func TestMirrorKillFailsClosedWhenAuditFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &sys.Session{ID: "mirror-kill-audit-fail", User: "alice"}
	session.SetContext(ctx, cancel)
	registerTestSession(t, session)
	eng, chain, _ := chainEngine(t)
	breakChain(t, eng, chain)
	if _, err := runMirrorVBin(t, eng, []string{"mirror", "kill", session.ID}); err == nil {
		t.Fatal("mirror kill succeeded with a failing audit sink")
	}
	if ctx.Err() != nil {
		t.Fatal("session was terminated although the audit write failed")
	}
}

func TestGatewayStartFailsClosedWhenAuditFails(t *testing.T) {
	target, closeTarget := startGatewayEchoServer(t)
	defer closeTarget()
	t.Setenv("ADSSH_GATEWAY_LOG", filepath.Join(t.TempDir(), "gateway.jsonl"))
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	eng, chain, _ := chainEngine(t)
	breakChain(t, eng, chain)
	if _, err := runGatewayVBin(t, eng, []string{"gateway", "start", "--listen", listen, "--target", target}); err == nil {
		t.Fatal("gateway started with a failing audit sink")
	}
	for _, g := range adminGatewaySnapshot() {
		if g["listen"] == listen {
			t.Fatalf("gateway registered although the audit write failed: %v", g)
		}
	}
	if conn, err := net.DialTimeout("tcp", listen, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("gateway listener left open although the audit write failed")
	}
}

func TestGatewayStopFailsClosedWhenAuditFails(t *testing.T) {
	target, closeTarget := startGatewayEchoServer(t)
	defer closeTarget()
	t.Setenv("ADSSH_GATEWAY_LOG", filepath.Join(t.TempDir(), "gateway.jsonl"))
	eng, chain, _ := chainEngine(t)
	output, err := runGatewayVBin(t, eng, []string{"gateway", "start", "--listen", "127.0.0.1:0", "--target", target})
	if err != nil {
		t.Fatal(err)
	}
	id, listen := parseGatewayStartOutput(t, output)
	t.Cleanup(func() {
		gatewayMu.Lock()
		g := gatewaySessions[id]
		delete(gatewaySessions, id)
		gatewayMu.Unlock()
		if g != nil {
			g.cancel()
		}
	})
	breakChain(t, eng, chain)
	if _, err := runGatewayVBin(t, eng, []string{"gateway", "stop", id}); err == nil {
		t.Fatal("gateway stop succeeded with a failing audit sink")
	}
	gatewayMu.RLock()
	_, live := gatewaySessions[id]
	gatewayMu.RUnlock()
	if !live {
		t.Fatal("gateway removed although the audit write failed")
	}
	conn, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		t.Fatalf("gateway stopped listening although the audit write failed: %v", err)
	}
	_ = conn.Close()
}

func TestIdentitySSHCAInitFailsClosedWhenAuditFails(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	breakChain(t, eng, chain)
	out := filepath.Join(t.TempDir(), "ca")
	if _, err := runVBin(t, eng, "", []string{"identity", "ssh-ca", "init", "--out", out}); err == nil {
		t.Fatal("ssh-ca init succeeded with a failing audit sink")
	}
	for _, p := range []string{out, out + ".pub"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s written although the audit write failed: %v", p, err)
		}
	}
}

func TestIdentitySSHCertIssueFailsClosedWhenAuditFails(t *testing.T) {
	eng, chain, _ := chainEngine(t)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	if _, err := runVBin(t, eng, "", []string{"identity", "ssh-ca", "init", "--out", ca}); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	userPub := filepath.Join(dir, "user.pub")
	if err := os.WriteFile(userPub, ssh.MarshalAuthorizedKey(sshPub), 0o600); err != nil {
		t.Fatal(err)
	}
	breakChain(t, eng, chain)
	cert := filepath.Join(dir, "user-cert.pub")
	if _, err := runVBin(t, eng, "", []string{"identity", "ssh-ca", "issue", "--ca", ca, "--pub", userPub,
		"--principal", "alice", "--for", "5m", "--out", cert}); err == nil {
		t.Fatal("ssh cert issued with a failing audit sink")
	}
	if _, err := os.Stat(cert); !os.IsNotExist(err) {
		t.Fatalf("certificate written although the audit write failed: %v", err)
	}
}

func TestGrantFailsClosedWhenAuditFails(t *testing.T) {
	session := &sys.Session{ID: "grant-audit-fail", User: "alice", Principals: []string{"held"}}
	registerTestSession(t, session)
	eng, chain, _ := chainEngine(t)
	breakChain(t, eng, chain)
	if _, err := runVBin(t, eng, session.ID, []string{"grant", "request", "ops"}); err == nil {
		t.Fatal("grant request succeeded with a failing audit sink")
	}
	if _, err := runVBin(t, eng, session.ID, []string{"grant", "drop", "held"}); err == nil {
		t.Fatal("grant drop succeeded with a failing audit sink")
	}
	got := session.PrincipalList()
	if len(got) != 1 || got[0] != "held" {
		t.Fatalf("principals changed although the audit write failed: %v", got)
	}
}
