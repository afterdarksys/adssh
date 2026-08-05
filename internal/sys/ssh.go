package sys

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// loadOrGenerateHostKey loads the persistent SSH host key from keyPath,
// generating and saving a new RSA 4096 key if one does not exist.
func loadOrGenerateHostKey(keyPath string) (ssh.Signer, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %v", err)
	}

	if data, err := os.ReadFile(keyPath); err == nil {
		if signer, err := ssh.ParsePrivateKey(data); err == nil {
			return signer, nil
		}
		log.Printf("Warning: could not parse existing host key at %s, regenerating", keyPath)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	if err := os.WriteFile(keyPath, privateKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to save host key to %s: %v", keyPath, err)
	}
	log.Printf("Generated new SSH host key: %s", keyPath)

	return ssh.ParsePrivateKey(privateKeyPEM)
}

type authorizedKeySet struct {
	userKeys    map[string]bool
	authorities map[string]bool
}

func (k authorizedKeySet) empty() bool {
	return len(k.userKeys) == 0 && len(k.authorities) == 0
}

// loadAuthorizedKeys reads direct user keys and explicitly marked certificate
// authorities from an OpenSSH authorized_keys file.
func loadAuthorizedKeys(authKeysPath string) (authorizedKeySet, error) {
	keys := authorizedKeySet{
		userKeys:    make(map[string]bool),
		authorities: make(map[string]bool),
	}

	data, err := os.ReadFile(authKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return keys, nil
		}
		return keys, fmt.Errorf("failed to read %s: %v", authKeysPath, err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pubKey, _, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return keys, fmt.Errorf("failed to parse %s line %d: %v", authKeysPath, lineNumber, err)
		}
		isAuthority := false
		for _, option := range options {
			if option == "cert-authority" {
				isAuthority = true
				continue
			}
			return keys, fmt.Errorf("unsupported authorized_keys option %q on line %d", option, lineNumber)
		}
		if isAuthority {
			keys.authorities[string(pubKey.Marshal())] = true
		} else {
			keys.userKeys[string(pubKey.Marshal())] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return keys, fmt.Errorf("failed to scan %s: %v", authKeysPath, err)
	}
	return keys, nil
}

func publicKeyCallback(keys authorizedKeySet) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	checker := &ssh.CertChecker{
		IsUserAuthority: func(key ssh.PublicKey) bool {
			return keys.authorities[string(key.Marshal())]
		},
		UserKeyFallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !keys.userKeys[string(key.Marshal())] {
				return nil, fmt.Errorf("unauthorized key from %s", conn.RemoteAddr())
			}
			return &ssh.Permissions{}, nil
		},
	}

	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if cert, ok := key.(*ssh.Certificate); ok {
			if cert.Key == nil || cert.SignatureKey == nil || cert.Signature == nil {
				return nil, fmt.Errorf("ssh: malformed user certificate")
			}
		}
		permissions, err := checker.Authenticate(conn, key)
		if err != nil {
			return nil, err
		}
		if permissions.Extensions == nil {
			permissions.Extensions = make(map[string]string)
		}
		permissions.Extensions["pubkey-fp"] = ssh.FingerprintSHA256(key)
		if cert, ok := key.(*ssh.Certificate); ok {
			permissions.Extensions["principals"] = strings.Join(cert.ValidPrincipals, ",")
		}
		return permissions, nil
	}
}

var (
	sshListener net.Listener
	sshMu       sync.Mutex
)

// SessionStarter starts an interactive session for one accepted SSH channel. It
// receives the per-connection identity and PTY-backed I/O and is responsible for
// building the session's OWN isolated Starlark globals (never a shared or
// shallow-copied dict) and running the REPL or menu. Defined here (in sys) so
// that sys/ssh.go never has to import starlarkext/engine and create an import
// cycle; the concrete starter is supplied by the binary/engine layer.
type SessionStarter func(sessionID, user string, principals []string, in io.ReadCloser, out, errOut io.Writer)

type GatewayAuthRequest struct {
	SessionID      string
	User           string
	Principals     []string
	TargetHost     string
	TargetPort     uint32
	OriginatorHost string
	OriginatorPort uint32
}

type GatewayAuthorizer func(GatewayAuthRequest) error

// EnableSSH starts the SSH daemon in the background. It returns an error if
// already running or if not root. Each accepted channel is handed to start,
// which builds that session's own isolated globals.
func EnableSSH(address, hostKeyPath, authorizedKeysPath string, start SessionStarter, authorizeGateway GatewayAuthorizer) error {
	sshMu.Lock()
	defer sshMu.Unlock()

	if sshListener != nil {
		return fmt.Errorf("ssh server is already running")
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("permission denied: only root can enable the SSH server")
	}

	authorizedKeys, err := loadAuthorizedKeys(authorizedKeysPath)
	if err != nil {
		return fmt.Errorf("failed to load authorized keys: %v", err)
	}
	if authorizedKeys.empty() {
		return fmt.Errorf(
			"no authorized keys found in %s\n"+
				"add your public key to allow SSH access:\n"+
				"  cat ~/.ssh/id_ed25519.pub >> %s",
			authorizedKeysPath, authorizedKeysPath,
		)
	}

	config := &ssh.ServerConfig{PublicKeyCallback: publicKeyCallback(authorizedKeys)}

	signer, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load/generate host key: %v", err)
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", address, err)
	}
	sshListener = listener

	fmt.Printf("adssh SSH daemon listening on %s\n", address)

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				// Stop the loop if the listener was closed
				if strings.Contains(err.Error(), "use of closed network connection") {
					break
				}
				log.Printf("Failed to accept incoming connection: %v", err)
				continue
			}
			go handleSSHConnection(nConn, config, start, authorizeGateway)
		}
	}()

	return nil
}

// DisableSSH stops the background SSH daemon.
func DisableSSH() error {
	sshMu.Lock()
	defer sshMu.Unlock()

	if os.Geteuid() != 0 {
		return fmt.Errorf("permission denied: only root can disable the SSH server")
	}

	if sshListener == nil {
		return fmt.Errorf("ssh server is not running")
	}

	err := sshListener.Close()
	sshListener = nil
	return err
}

type sshReadCloser struct {
	ssh.Channel
}

type CtrlCInterceptor struct {
	r       io.Reader
	session *Session
}

func (c *CtrlCInterceptor) Read(p []byte) (n int, err error) {
	n, err = c.r.Read(p)
	if n > 0 {
		for i := 0; i < n; i++ {
			if p[i] == 3 { // ETX / Ctrl+C
				// Check if PTY is in cooked mode
				if IsCookedMode(c.session.PTYMaster.Fd()) {
					c.session.CancelCommand()
					// Drop the byte so it doesn't echo or pass to the child
					copy(p[i:], p[i+1:])
					n--
					i--
				}
			}
		}
	}
	return n, err
}

func handleSSHConnection(nConn net.Conn, config *ssh.ServerConfig, start SessionStarter, authorizeGateway GatewayAuthorizer) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	fp := conn.Permissions.Extensions["pubkey-fp"]
	log.Printf("New SSH connection from %s (%s) key=%s", conn.RemoteAddr(), conn.ClientVersion(), fp)

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() == "direct-tcpip" {
			go handleDirectTCPIP(conn, newChannel, authorizeGateway)
			continue
		}
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type") // best-effort
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		ptyMaster, ptySlave, err := pty.Open()
		if err != nil {
			log.Printf("Could not start pty: %v", err)
			channel.Close()
			continue
		}

		if err := DisableISIG(ptyMaster.Fd()); err != nil {
			log.Printf("Warning: failed to disable ISIG on pty: %v", err)
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell":
					_ = req.Reply(true, nil) // best-effort
				case "pty-req":
					termLen := req.Payload[3]
					w, h := parseDims(req.Payload[termLen+4:])
					_ = pty.Setsize(ptyMaster, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)}) // best-effort
					_ = req.Reply(true, nil)                                                   // best-effort
				case "window-change":
					w, h := parseDims(req.Payload)
					_ = pty.Setsize(ptyMaster, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)}) // best-effort
					_ = req.Reply(true, nil)                                                   // best-effort
				}
			}
		}(requests)

		sessionID := GenerateSessionID()
		outCast := NewOutputBroadcaster(channel)

		var principals []string
		if pExt, ok := conn.Permissions.Extensions["principals"]; ok && pExt != "" {
			principals = strings.Split(pExt, ",")
		}

		session := &Session{
			ID:         sessionID,
			User:       conn.User(),
			Principals: principals,
			PTYMaster:  ptyMaster,
			Out:        outCast,
		}
		RegisterSession(session)

		go func(user string, principals []string) {
			defer channel.Close()
			defer ptyMaster.Close()
			defer ptySlave.Close()
			defer UnregisterSession(sessionID)

			interceptedChannel := &CtrlCInterceptor{r: channel, session: session}

			go func() { _, _ = io.Copy(outCast, ptyMaster) }()            // best-effort: stream ends on session close
			go func() { _, _ = io.Copy(ptyMaster, interceptedChannel) }() // best-effort: stream ends on session close

			// start builds this session's OWN fresh globals (no shared/shallow
			// copy) and runs the REPL/menu on the PTY slave.
			start(sessionID, user, principals, ptySlave, ptySlave, ptySlave)
		}(session.User, principals)
	}
}

func parseDims(b []byte) (uint32, uint32) {
	if len(b) < 8 {
		return 80, 24
	}
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

type directTCPIPPayload struct {
	TargetHost     string
	TargetPort     uint32
	OriginatorHost string
	OriginatorPort uint32
}

func handleDirectTCPIP(conn *ssh.ServerConn, newChannel ssh.NewChannel, authorize GatewayAuthorizer) {
	payload, err := parseDirectTCPIPPayload(newChannel.ExtraData())
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	if authorize == nil {
		_ = newChannel.Reject(ssh.Prohibited, "gateway forwarding is disabled")
		return
	}
	sessionID := GenerateSessionID()
	var principals []string
	if pExt, ok := conn.Permissions.Extensions["principals"]; ok && pExt != "" {
		principals = strings.Split(pExt, ",")
	}
	if err := authorize(GatewayAuthRequest{
		SessionID:      sessionID,
		User:           conn.User(),
		Principals:     principals,
		TargetHost:     payload.TargetHost,
		TargetPort:     payload.TargetPort,
		OriginatorHost: payload.OriginatorHost,
		OriginatorPort: payload.OriginatorPort,
	}); err != nil {
		_ = newChannel.Reject(ssh.Prohibited, err.Error())
		return
	}
	target := net.JoinHostPort(payload.TargetHost, fmt.Sprintf("%d", payload.TargetPort))
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = targetConn.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	go func() {
		defer channel.Close()
		defer targetConn.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = io.Copy(targetConn, channel)
		}()
		go func() {
			defer wg.Done()
			_, _ = io.Copy(channel, targetConn)
		}()
		wg.Wait()
	}()
}

func parseDirectTCPIPPayload(data []byte) (directTCPIPPayload, error) {
	var payload directTCPIPPayload
	rest := data
	var ok bool
	payload.TargetHost, rest, ok = parseSSHString(rest)
	if !ok || len(rest) < 4 {
		return payload, fmt.Errorf("malformed direct-tcpip payload")
	}
	payload.TargetPort = binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	payload.OriginatorHost, rest, ok = parseSSHString(rest)
	if !ok || len(rest) < 4 {
		return payload, fmt.Errorf("malformed direct-tcpip payload")
	}
	payload.OriginatorPort = binary.BigEndian.Uint32(rest[:4])
	if payload.TargetHost == "" || payload.TargetPort == 0 || payload.TargetPort > 65535 {
		return payload, fmt.Errorf("invalid direct-tcpip target")
	}
	return payload, nil
}

func parseSSHString(data []byte) (string, []byte, bool) {
	if len(data) < 4 {
		return "", nil, false
	}
	length := binary.BigEndian.Uint32(data[:4])
	if length > uint32(len(data)-4) {
		return "", nil, false
	}
	value := string(data[4 : 4+length])
	return value, data[4+length:], true
}
