//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestSSHRoundTrip starts `adssh --serve` on a random localhost port with a
// temp host key and authorized_keys, connects with x/crypto/ssh as the user
// running the test, opens a shell, runs a command, and asserts the output.
// It also asserts that an exec request is refused and an unauthorized key is
// rejected. The key line is bound to that login with user="...". Under sudo
// the login is root, so the server gets ADSSH_SSH_PERMIT_ROOT=1. The session
// process reads the login's real ~/.adsshrc and ~/.adsshprofile and writes
// its ~/.adssh/history.
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

	// The session runs as a real login: the listener setuids to it.
	login, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	loginName := login.Username

	// authorized_keys contains only the authorized public key, bound to
	// the login it may use.
	authKeysPath := filepath.Join(sb.dir, "authorized_keys")
	keyLine := fmt.Sprintf("user=%q %s", loginName, ssh.MarshalAuthorizedKey(authPub))
	if err := os.WriteFile(authKeysPath, []byte(keyLine), 0o600); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}
	hostKeyPath := filepath.Join(sb.dir, "host_key")

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	serverEnv := map[string]string{
		"ADSSH_HOST_KEY":        hostKeyPath,
		"ADSSH_AUTHORIZED_KEYS": authKeysPath,
	}
	if login.Uid == "0" {
		serverEnv["ADSSH_SSH_PERMIT_ROOT"] = "1"
	}
	env := mergeEnv(sb.env(""), serverEnv)

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

	// Authorized connection: run a command in a shell and check output.
	// The marker is computed so the PTY echo of the typed line cannot match.
	out := sshShellCommand(t, addr, loginName, authSigner, "echo ssh-roundtrip-$((40+2))", "ssh-roundtrip-42")
	if !strings.Contains(out, "ssh-roundtrip-42") {
		t.Fatalf("expected command output over SSH, got %q", out)
	}

	// exec requests are refused rather than left unanswered.
	if err := sshExec(addr, loginName, authSigner, "echo should-not-run"); err == nil {
		t.Fatalf("expected an exec request to be refused")
	}

	// Unauthorized key: handshake must fail.
	if err := sshDialOnly(addr, loginName, badSigner); err == nil {
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

// lockedBuffer is a bytes.Buffer safe for one writer and one reader.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func sshClient(addr, user string, signer ssh.Signer) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return ssh.Dial("tcp", addr, cfg)
}

// sshShellCommand opens a PTY shell, types command, and returns the output
// once want appears or 10s pass.
func sshShellCommand(t *testing.T, addr, user string, signer ssh.Signer, command, want string) string {
	t.Helper()
	client, err := sshClient(addr, user, signer)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("ssh new session: %v", err)
	}
	defer session.Close()
	out := &lockedBuffer{}
	session.Stdout = out
	session.Stderr = out
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := session.RequestPty("xterm", 40, 120, ssh.TerminalModes{}); err != nil {
		t.Fatalf("pty-req: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	if _, err := io.WriteString(stdin, command+"\n"); err != nil {
		t.Fatalf("write command: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), want) {
		time.Sleep(50 * time.Millisecond)
	}
	_, _ = io.WriteString(stdin, "exit\n")
	return out.String()
}

// sshExec sends an exec request and returns its error.
func sshExec(addr, user string, signer ssh.Signer, command string) error {
	client, err := sshClient(addr, user, signer)
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	done := make(chan error, 1)
	go func() { done <- session.Start(command) }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return nil
	}
}
