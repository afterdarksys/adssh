//go:build ee

package security

// Threats: the monitor supplies a destination checked under its bound identity;
// the SSH child never reads the administrator's config or supplies a username
// to that check. Dials use the approved literal IP, not a second DNS lookup.
// SSH verifies the configured host key and uses only the session user's key.
// TCP mode is a byte stream, not TLS termination. Payloads and keys are not
// audited. Like other child-side networking, this does not contain a native
// exploit in the session process. Authorization changes affect new connections.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/adssh/internal/safefile"
	"github.com/afterdarksys/adssh/internal/sys"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"mvdan.cc/sh/v3/interp"
)

type proxyBinary struct{}

func (proxyBinary) Name() string { return "proxy" }
func (proxyBinary) Description() string {
	return "Connect to administrator-approved internal SSH and TCP destinations"
}
func (proxyBinary) Usage() string {
	return "proxy list | proxy host port | proxy tcp host port\nSSH uses ~/.ssh/id_ed25519 and the administrator-pinned host key. tcp relays stdin/stdout; use SSH -L for local applications."
}
func init() { Register(proxyBinary{}) }

func (proxyBinary) Run(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	eng := engineFromContext(ctx)
	sid := SessionIDFromContext(ctx)
	if len(args) == 5 && args[1] == "_result" {
		if RemoteGateProcess() {
			return errors.New("proxy: result must run in the listener")
		}
		user, err := proxyIdentity(eng, sid)
		if err != nil {
			return err
		}
		port, err := strconv.ParseUint(args[3], 10, 16)
		if err != nil || port == 0 || !proxyToken(args[2]) || (args[4] != "completed" && args[4] != "failed") {
			return errors.New("proxy: invalid result")
		}
		return eng.LogEvent(fmt.Sprintf("PROXY_RESULT user=%s session=%s target=%s outcome=%s", user, sid, net.JoinHostPort(args[2], args[3]), args[4]))
	}
	if len(args) == 2 && args[1] == "list" {
		if RemoteGateProcess() {
			return runInListener(ctx, false, args, sid)
		}
		cfg, err := readProxyConfig()
		if err != nil {
			return err
		}
		user, err := proxyIdentity(eng, sid)
		if err != nil {
			return err
		}
		return json.NewEncoder(hc.Stdout).Encode(cfg.Users[user])
	}
	mode := "ssh"
	offset := 1
	if len(args) > 1 && (args[1] == "tcp" || args[1] == "_resolve") {
		mode = args[1]
		offset = 2
	}
	if len(args) != offset+2 || !proxyToken(args[offset]) {
		return errors.New("proxy: usage: proxy list | proxy host port | proxy tcp host port")
	}
	port, err := strconv.ParseUint(args[offset+1], 10, 16)
	if err != nil || port == 0 {
		return errors.New("proxy: invalid port")
	}
	host := args[offset]
	if mode == "_resolve" {
		if RemoteGateProcess() {
			return errors.New("proxy: resolution must run in the listener")
		}
		target, err := resolveProxy(eng, sid, host, uint32(port))
		if err != nil {
			return err
		}
		return json.NewEncoder(hc.Stdout).Encode(target)
	}
	var target proxyTarget
	if RemoteGateProcess() {
		fn := currentRemoteRun()
		if fn == nil {
			return errors.New("proxy: monitor unavailable")
		}
		var out, stderr limitedBuffer
		out.limit, stderr.limit = 16384, 4096
		code, err := fn([]string{"proxy", "_resolve", host, strconv.FormatUint(port, 10)}, sys.MonitorStdinNone, nil, &out, &stderr)
		if err != nil {
			return fmt.Errorf("proxy: authorization: %w", err)
		}
		if code != 0 {
			return errors.New("proxy: destination authorization refused")
		}
		if err := json.Unmarshal(out.Bytes(), &target); err != nil {
			return errors.New("proxy: invalid listener response")
		}
		if target.Host != host || target.Port != uint32(port) {
			return errors.New("proxy: listener destination mismatch")
		}
		if err := target.validate(); err != nil {
			return err
		}
	} else {
		target, err = resolveProxy(eng, sid, host, uint32(port))
		if err != nil {
			return err
		}
	}
	if mode == "ssh" {
		err = proxySSH(ctx, hc, target)
	} else {
		err = proxyTCP(ctx, hc, target)
	}
	outcome := "completed"
	if err != nil {
		outcome = "failed"
	}
	resultArgs := []string{"proxy", "_result", host, strconv.FormatUint(port, 10), outcome}
	var auditErr error
	if RemoteGateProcess() {
		fn := currentRemoteRun()
		if fn == nil {
			auditErr = errors.New("proxy: result monitor unavailable")
		} else {
			code, e := fn(resultArgs, sys.MonitorStdinNone, nil, io.Discard, io.Discard)
			auditErr = e
			if e == nil && code != 0 {
				auditErr = errors.New("proxy: result audit refused")
			}
		}
	} else {
		auditErr = (proxyBinary{}).Run(ctx, resultArgs)
	}
	return errors.Join(err, auditErr)
}

func proxyIdentity(eng *Engine, sid string) (string, error) {
	pctx := eng.buildPolicyContext("proxy", nil, sid)
	if pctx.IdentityUnknown || pctx.User == "" {
		return "", errors.New("proxy: session identity unknown")
	}
	if s := sys.GetSession(sid); s != nil && s.IdentitySource() != "" {
		return "", errors.New("proxy: renamed session identity refused; reconnect")
	}
	return pctx.User, nil
}

func resolveProxy(eng *Engine, sid, host string, port uint32) (proxyTarget, error) {
	user, err := proxyIdentity(eng, sid)
	if err != nil {
		return proxyTarget{}, err
	}
	cfg, err := readProxyConfig()
	if err != nil {
		return proxyTarget{}, err
	}
	target, err := cfg.target(user, host, port)
	if err != nil {
		return proxyTarget{}, err
	}
	// The configured literal IP is intentional: aliases need no DNS record.
	err = eng.AuthorizeGateway(GatewayPolicyRequest{SessionID: sid, Action: "proxy", TargetHost: host, TargetIP: target.IP, TargetPort: port})
	return target, err
}

func proxyDial(ctx context.Context, target proxyTarget) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(target.IP, strconv.Itoa(int(target.Port))))
}

// proxyInput checks cancellation before reading terminal/pipe input. A raw
// os.File read alone could survive disconnect and steal the next shell input.
type proxyInput struct {
	ctx context.Context
	r   io.Reader
}

// Only accept file descriptors we can poll or finite in-memory readers. An
// arbitrary blocking reader cannot be canceled without closing caller-owned IO.
func validateProxyInput(r io.Reader) error {
	switch r.(type) {
	case nil, *os.File, *bytes.Reader, *bytes.Buffer, *strings.Reader:
		return nil
	default:
		return errors.New("proxy: input must be a terminal, file, shell pipe, or finite byte buffer")
	}
}

func (r proxyInput) Read(p []byte) (int, error) {
	f, ok := r.r.(*os.File)
	if !ok {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		if r.r == nil {
			return 0, io.EOF
		}
		return r.r.Read(p)
	}
	for {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		fds := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return f.Read(p)
		}
	}
}

func proxyTCP(ctx context.Context, hc interp.HandlerContext, target proxyTarget) error {
	if err := validateProxyInput(hc.Stdin); err != nil {
		return err
	}
	if f, ok := hc.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return errors.New("proxy: tcp needs redirected byte-stream input; use ssh -L for local applications")
	}
	conn, err := proxyDial(ctx, target)
	if err != nil {
		return fmt.Errorf("proxy: connect: %w", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	inputDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, proxyInput{ctx, hc.Stdin})
		if tc, ok := conn.(*net.TCPConn); ok {
			if e := tc.CloseWrite(); err == nil {
				err = e
			}
		}
		inputDone <- err
	}()
	_, err = io.Copy(hc.Stdout, conn)
	cancel()
	if e := <-inputDone; err == nil && e != nil && !errors.Is(e, context.Canceled) {
		err = e
	}
	return err
}

func proxySigner() (ssh.Signer, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	f, info, err := safefile.Open(nil, filepath.Join(home, ".ssh", "id_ed25519"))
	if err != nil {
		return nil, errors.New("proxy: cannot open ~/.ssh/id_ed25519")
	}
	defer f.Close()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("proxy: private key must be owned by this user and mode 0600")
	}
	data, err := safefile.ReadAll(f, info, 16384)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, errors.New("proxy: key must be an unencrypted SSH private key")
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("proxy: private key must be Ed25519")
	}
	return signer, nil
}

func proxySSH(ctx context.Context, hc interp.HandlerContext, target proxyTarget) error {
	if err := validateProxyInput(hc.Stdin); err != nil {
		return err
	}
	if target.User == "" || target.HostKey == "" {
		return errors.New("proxy: destination has no SSH login and pinned host key configured")
	}
	key, err := proxyHostKey(target.HostKey)
	if err != nil {
		return err
	}
	signer, err := proxySigner()
	if err != nil {
		return err
	}
	conn, err := proxyDial(ctx, target)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	config := &ssh.ClientConfig{User: target.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(key)}
	c, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))), config)
	if err != nil {
		return fmt.Errorf("proxy: SSH handshake refused: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout, session.Stderr = hc.Stdout, hc.Stderr
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	if f, ok := hc.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		w, h, err := term.GetSize(int(f.Fd()))
		if err != nil {
			return err
		}
		if err := session.RequestPty("xterm-256color", h, w, ssh.TerminalModes{}); err != nil {
			return err
		}
		state, err := term.MakeRaw(int(f.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(f.Fd()), state)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	// Clear the connection deadline before requesting the shell: a remote
	// shell may exit and close the transport immediately after acknowledging
	// the request. Its already-buffered output and exit status remain valid.
	startupTimer := time.AfterFunc(15*time.Second, func() { conn.Close() })
	err = session.Shell()
	startupTimer.Stop()
	if err != nil {
		return err
	}
	inputCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if f, ok := hc.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		go func() {
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			width, height, _ := term.GetSize(int(f.Fd()))
			for {
				select {
				case <-inputCtx.Done():
					return
				case <-ticker.C:
					w, h, e := term.GetSize(int(f.Fd()))
					if e != nil {
						return
					}
					if w != width || h != height {
						if e := session.WindowChange(h, w); e != nil {
							return
						}
						width, height = w, h
					}
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { defer close(done); io.Copy(stdin, proxyInput{inputCtx, hc.Stdin}); stdin.Close() }()
	err = session.Wait()
	cancel()
	<-done
	return err
}
