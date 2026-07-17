//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestSSHRoundTrip starts `adssh --serve` on a random localhost port with a
// temp host key and authorized_keys, connects with x/crypto/ssh, runs a
// command, and asserts the output. It also asserts an unauthorized key is
// rejected.
//
// IMPORTANT: sys.EnableSSH hard-requires euid == 0 ("only root can enable the
// SSH server"). When not run as root — which includes default GitHub Actions
// runners and a normal macOS/Linux dev login — the whole scenario cannot bind
// the server, so the test skips with a precise reason rather than failing.
func TestSSHRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("adssh --serve requires root: sys.EnableSSH enforces os.Geteuid()==0; " +
			"cannot start the SSH server as a non-root user (run this test as root to exercise it)")
	}

	sb := newSandbox(t)

	// Client keypair (authorized) and an unauthorized keypair.
	authSigner, authPub := genED25519Signer(t)
	badSigner, _ := genED25519Signer(t)

	// authorized_keys contains only the authorized public key.
	authKeysPath := filepath.Join(sb.dir, "authorized_keys")
	if err := os.WriteFile(authKeysPath, ssh.MarshalAuthorizedKey(authPub), 0o600); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}
	hostKeyPath := filepath.Join(sb.dir, "host_key")

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	env := mergeEnv(sb.env(""), map[string]string{
		"ADSSH_HOST_KEY":        hostKeyPath,
		"ADSSH_AUTHORIZED_KEYS": authKeysPath,
	})

	// Launch the server. The --serve path starts the SSH daemon and then drops
	// into the REPL reading stdin, so we keep stdin open to hold the process up.
	cmd := exec.Command(adsshBin, "--serve", addr)
	cmd.Env = env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	cmd.Stdout = os.Stderr // surface server logs into the test log on failure
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start adssh --serve: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	waitForListen(t, addr, 10*time.Second)

	// Authorized connection: run a command and check output.
	out := sshRunCommand(t, addr, "e2e-user", authSigner, "echo ssh-roundtrip-ok")
	if !strings.Contains(out, "ssh-roundtrip-ok") {
		t.Fatalf("expected command output over SSH, got %q", out)
	}

	// Unauthorized key: handshake must fail.
	if err := sshDialOnly(addr, "e2e-user", badSigner); err == nil {
		t.Fatalf("expected unauthorized key to be rejected, but handshake succeeded")
	}
}

// genED25519Signer returns a new ssh.Signer plus its public key.
func genED25519Signer(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	return signer, sshPub
}

// freePort asks the OS for a free TCP port and returns it (the listener is
// closed immediately; a brief race window exists but is acceptable for tests).
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// waitForListen polls until addr accepts TCP connections or the deadline hits.
func waitForListen(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("SSH server did not start listening on %s within %s", addr, timeout)
}

// sshDialOnly performs only the SSH handshake and returns any error.
func sshDialOnly(addr, user string, signer ssh.Signer) error {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	_ = client.Close()
	return nil
}

// sshRunCommand connects, opens a session, runs cmd, and returns combined output.
func sshRunCommand(t *testing.T, addr, user string, signer ssh.Signer, command string) string {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("ssh new session: %v", err)
	}
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type outcome struct {
		out []byte
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		out, err := session.CombinedOutput(command)
		ch <- outcome{out: out, err: err}
	}()

	select {
	case <-ctx.Done():
		t.Fatalf("ssh command timed out")
	case o := <-ch:
		// The interactive REPL may exit nonzero on the command channel; we only
		// assert on the produced output.
		return string(o.out)
	}
	return ""
}
