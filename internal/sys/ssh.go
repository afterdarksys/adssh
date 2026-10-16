// Threats: the SSH listener runs as root and a session child setuids to the
// login name, so the login name is the authority. A raw key authenticates
// only for the names its authorized_keys line lists in user="..."; a line
// without user= fails the load. A certificate authenticates only for a name
// in its ValidPrincipals, and a certificate with no principals is refused
// (x/crypto/ssh would accept it for every name). Root, and any name that
// resolves to uid 0, is refused unless SSHServerOptions.PermitRoot is set; a
// lookup failure at that check refuses the login. pty-req and window-change
// payloads are decoded strictly and sizes are clamped. A handshake holds one
// of a bounded set of pre-auth slots and must finish before a deadline.
// Certificate principals must be non-empty, NUL-free, and must not start
// with '-'; they travel to the session as a JSON array, so a comma inside a
// principal stays one principal. A session process starts only after a
// "shell" request; exec, env, subsystem, and unknown requests are refused.
// Sessions are capped per connection (maxSessionsPerConn) and per login
// name (maxSessionsPerUser), and direct-tcpip channels per connection
// (maxDirectTCPIPPerConn). A direct-tcpip target name is resolved once;
// one gateway decision sees both the name (TargetHost) and the resolved
// address (TargetIP), and the listener dials that address with a timeout,
// so a DNS answer that changes after the check is not used. Ctrl-C is not intercepted: ISIG on the PTY
// sends SIGINT to the session's foreground process group.
// Not covered: per-source-IP auth throttling beyond internal/guard, expiry
// or revocation of raw keys, certificate revocation lists, and the global
// session cap (ADSSH_MAX_SESSIONS), which still bounds all users together.
package sys

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/afterdarksys/adssh/internal/guard"
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
	// userKeys maps a marshaled raw key to the login names it may use.
	userKeys    map[string][]string
	authorities map[string]bool
}

func (k authorizedKeySet) empty() bool {
	return len(k.userKeys) == 0 && len(k.authorities) == 0
}

// SSHServerOptions are listener-wide login rules.
type SSHServerOptions struct {
	// PermitRoot allows a login as "root" or as any name that resolves to
	// uid 0. The key or certificate must still be bound to that name.
	PermitRoot bool
}

const userOptionPrefix = "user="

// parseUserOption decodes user="alice,bob" into its login names.
func parseUserOption(option string) ([]string, error) {
	value := strings.TrimPrefix(option, userOptionPrefix)
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return nil, fmt.Errorf("user= value must be quoted, e.g. user=\"alice\"")
	}
	value = value[1 : len(value)-1]
	if value == "" {
		return nil, fmt.Errorf("user= names no login")
	}
	names := strings.Split(value, ",")
	for _, name := range names {
		if name == "" {
			return nil, fmt.Errorf("user= has an empty login name")
		}
		for _, r := range name {
			if unicode.IsSpace(r) || unicode.IsControl(r) || r == '/' || r == '"' {
				return nil, fmt.Errorf("user= login name %q contains a space, control character, '/' or '\"'", name)
			}
		}
	}
	return names, nil
}

// loadAuthorizedKeys reads direct user keys and explicitly marked certificate
// authorities from an OpenSSH authorized_keys file. A direct key must carry
// user="name[,name...]"; there is no implicit any-user key.
func loadAuthorizedKeys(authKeysPath string) (authorizedKeySet, error) {
	keys := authorizedKeySet{
		userKeys:    make(map[string][]string),
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
		var names []string
		for _, option := range options {
			switch {
			case option == "cert-authority":
				isAuthority = true
			case strings.HasPrefix(option, userOptionPrefix):
				if names != nil {
					return keys, fmt.Errorf("%s line %d: user= appears more than once", authKeysPath, lineNumber)
				}
				parsed, err := parseUserOption(option)
				if err != nil {
					return keys, fmt.Errorf("%s line %d: %v", authKeysPath, lineNumber, err)
				}
				names = parsed
			default:
				return keys, fmt.Errorf("unsupported authorized_keys option %q on line %d", option, lineNumber)
			}
		}
		marshaled := string(pubKey.Marshal())
		switch {
		case isAuthority && names != nil:
			return keys, fmt.Errorf("%s line %d: user= is not valid on a cert-authority line; certificates are bound by their principals", authKeysPath, lineNumber)
		case isAuthority:
			keys.authorities[marshaled] = true
		case names == nil:
			return keys, fmt.Errorf("%s line %d: key has no user= option; bind it to its login names, e.g. user=\"alice\" %s", authKeysPath, lineNumber, pubKey.Type()+" AAAA...")
		default:
			keys.userKeys[marshaled] = append(keys.userKeys[marshaled], names...)
		}
	}
	if err := scanner.Err(); err != nil {
		return keys, fmt.Errorf("failed to scan %s: %v", authKeysPath, err)
	}
	return keys, nil
}

// loginIsRoot reports whether name is root or resolves to uid 0. A lookup
// failure is an error; the caller rejects the login.
func loginIsRoot(name string) (bool, error) {
	if name == "root" {
		return true, nil
	}
	u, err := lookupUser(name)
	if err != nil {
		return false, err
	}
	return u.Uid == "0", nil
}

func publicKeyCallback(keys authorizedKeySet, opts SSHServerOptions) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	checker := &ssh.CertChecker{
		IsUserAuthority: func(key ssh.PublicKey) bool {
			return keys.authorities[string(key.Marshal())]
		},
		UserKeyFallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fp := ssh.FingerprintSHA256(key)
			names, ok := keys.userKeys[string(key.Marshal())]
			if !ok || !slices.Contains(names, conn.User()) {
				log.Printf("ssh: key %s from %s is not authorized for the requested login", fp, conn.RemoteAddr())
				return nil, fmt.Errorf("ssh: key %s is not authorized for this login", fp)
			}
			return &ssh.Permissions{}, nil
		},
	}

	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if cert, ok := key.(*ssh.Certificate); ok {
			if cert.Key == nil || cert.SignatureKey == nil || cert.Signature == nil {
				return nil, fmt.Errorf("ssh: malformed user certificate")
			}
			// x/crypto/ssh treats an empty principal list as valid for
			// every login. adssh does not.
			if len(cert.ValidPrincipals) == 0 {
				return nil, fmt.Errorf("ssh: certificate has no principals")
			}
			for _, principal := range cert.ValidPrincipals {
				if !validSessionToken(principal) {
					return nil, fmt.Errorf("ssh: certificate has an invalid principal")
				}
			}
		}
		permissions, err := checker.Authenticate(conn, key)
		if err != nil {
			return nil, err
		}
		if !opts.PermitRoot {
			isRoot, err := loginIsRoot(conn.User())
			if err != nil || isRoot {
				log.Printf("ssh: key %s from %s refused: root login is not permitted or the login does not resolve", ssh.FingerprintSHA256(key), conn.RemoteAddr())
				return nil, fmt.Errorf("ssh: login refused")
			}
		}
		if permissions.Extensions == nil {
			permissions.Extensions = make(map[string]string)
		}
		permissions.Extensions["pubkey-fp"] = ssh.FingerprintSHA256(key)
		if cert, ok := key.(*ssh.Certificate); ok {
			encoded, err := json.Marshal(cert.ValidPrincipals)
			if err != nil {
				return nil, fmt.Errorf("ssh: certificate principals: %v", err)
			}
			permissions.Extensions[principalsExtension] = string(encoded)
		}
		return permissions, nil
	}
}

const principalsExtension = "principals"

// validSessionToken is the rule for a value that reaches a session process
// argv: non-empty, no NUL, and no leading '-' that could read as a flag.
func validSessionToken(v string) bool {
	return v != "" && strings.IndexByte(v, 0) < 0 && !strings.HasPrefix(v, "-")
}

// principalsFromPermissions decodes the JSON principal list set by
// publicKeyCallback. No extension is no principals. Anything that is not a
// JSON array of valid tokens is an error.
func principalsFromPermissions(perms *ssh.Permissions) ([]string, error) {
	if perms == nil {
		return nil, nil
	}
	raw, ok := perms.Extensions[principalsExtension]
	if !ok {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	var principals []string
	if err := dec.Decode(&principals); err != nil {
		return nil, fmt.Errorf("ssh: malformed principals")
	}
	if dec.More() {
		return nil, fmt.Errorf("ssh: malformed principals")
	}
	if _, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("ssh: malformed principals")
	}
	for _, principal := range principals {
		if !validSessionToken(principal) {
			return nil, fmt.Errorf("ssh: malformed principals")
		}
	}
	return principals, nil
}

var (
	sshListener net.Listener
	sshMu       sync.Mutex
)

// SessionStarter starts one accepted SSH channel. The binary supplies it so
// this package does not import the security engine. The SSH path execs a
// session process; it does not build Starlark globals in the listener.
type SessionStarter func(sessionID, user string, principals []string, in io.ReadCloser, out, errOut io.Writer)

// GatewayAuthRequest is one direct-tcpip check. TargetHost is the requested
// name and TargetIP the address it resolved to, which the listener dials.
// Both go into one policy decision.
type GatewayAuthRequest struct {
	SessionID      string
	User           string
	Principals     []string
	TargetHost     string
	TargetIP       string
	TargetPort     uint32
	OriginatorHost string
	OriginatorPort uint32
}

type GatewayAuthorizer func(GatewayAuthRequest) error

// EnableSSH starts the SSH daemon with root login refused. See
// EnableSSHWithOptions.
func EnableSSH(address, hostKeyPath, authorizedKeysPath string, start SessionStarter, authorizeGateway GatewayAuthorizer) error {
	return EnableSSHWithOptions(address, hostKeyPath, authorizedKeysPath, SSHServerOptions{}, start, authorizeGateway)
}

// EnableSSHWithOptions starts the SSH daemon in the background. It returns an
// error if already running or if not root. Each accepted channel is handed to
// start. The starter is supplied by the binary so this package does not
// import the security engine.
func EnableSSHWithOptions(address, hostKeyPath, authorizedKeysPath string, opts SSHServerOptions, start SessionStarter, authorizeGateway GatewayAuthorizer) error {
	sshMu.Lock()
	defer sshMu.Unlock()

	if sshListener != nil {
		return fmt.Errorf("ssh server is already running")
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("permission denied: only root can enable the SSH server")
	}
	if err := guard.Ready(); err != nil {
		return fmt.Errorf("guard: %v", err)
	}
	if err := SessionCapReady(); err != nil {
		return err
	}

	authorizedKeys, err := loadAuthorizedKeys(authorizedKeysPath)
	if err != nil {
		return fmt.Errorf("failed to load authorized keys: %v", err)
	}
	if authorizedKeys.empty() {
		return fmt.Errorf(
			"no authorized keys found in %s\n"+
				"add your public key, bound to your login name, to allow SSH access:\n"+
				"  echo \"user=\\\"$USER\\\" $(cat ~/.ssh/id_ed25519.pub)\" >> %s",
			authorizedKeysPath, authorizedKeysPath,
		)
	}

	config := &ssh.ServerConfig{PublicKeyCallback: publicKeyCallback(authorizedKeys, opts)}

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

	go serveSSH(listener, config, start, authorizeGateway)

	return nil
}

var (
	// maxSessionsPerConn bounds session channels on one connection.
	maxSessionsPerConn = 4
	// maxSessionsPerUser bounds session channels for one login name across
	// all connections.
	maxSessionsPerUser = 8
	// maxDirectTCPIPPerConn bounds concurrent forwarded channels on one
	// connection.
	maxDirectTCPIPPerConn = 16
	// gatewayDialTimeout bounds the resolve and the dial of a forwarded
	// target.
	gatewayDialTimeout = 10 * time.Second
	gatewayLookupIP    = func(ctx context.Context, host string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip", host)
	}
	gatewayDial = net.DialTimeout

	userSessionsMu sync.Mutex
	userSessions   = make(map[string]int)
)

// acquireUserSession takes one of name's session slots. It returns false at
// the cap.
func acquireUserSession(name string, limit int) bool {
	userSessionsMu.Lock()
	defer userSessionsMu.Unlock()
	if limit > 0 && userSessions[name] >= limit {
		return false
	}
	userSessions[name]++
	return true
}

func releaseUserSession(name string) {
	userSessionsMu.Lock()
	defer userSessionsMu.Unlock()
	if userSessions[name] <= 1 {
		delete(userSessions, name)
		return
	}
	userSessions[name]--
}

// trySlot takes a slot from a semaphore without blocking.
func trySlot(slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

var (
	// preAuthSlots bounds connections that have not finished the SSH
	// handshake. serveSSH reads it once at start.
	preAuthSlots = make(chan struct{}, 64)
	// handshakeTimeout bounds the handshake and authentication of one
	// connection. serveSSH reads it once at start.
	handshakeTimeout = 30 * time.Second
)

// serveSSH accepts connections until listener is closed. It does not need
// root. A connection that arrives while every pre-auth slot is held is
// closed at once.
func serveSSH(listener net.Listener, config *ssh.ServerConfig, start SessionStarter, authorizeGateway GatewayAuthorizer) {
	slots, timeout := preAuthSlots, handshakeTimeout
	for {
		nConn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("Failed to accept incoming connection: %v", err)
			continue
		}
		go handleSSHConnection(nConn, config, slots, timeout, start, authorizeGateway)
	}
}

// StopAcceptingSSH closes the SSH listener so no new connection is
// accepted. Connections and sessions already running are left alone. It
// does not check the uid: it is the listener's SIGHUP action.
func StopAcceptingSSH() error {
	sshMu.Lock()
	defer sshMu.Unlock()
	if sshListener == nil {
		return fmt.Errorf("ssh server is not running")
	}
	err := sshListener.Close()
	sshListener = nil
	return err
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

// handshake runs the SSH handshake under a deadline while holding one
// pre-auth slot. The slot is released on every return. The deadline is
// cleared only after a successful handshake.
func handshake(nConn net.Conn, config *ssh.ServerConfig, slots chan struct{}, timeout time.Duration) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	defer func() { <-slots }()
	if err := nConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = nConn.Close()
		return nil, nil, nil, err
	}
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := nConn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	return conn, chans, reqs, nil
}

func handleSSHConnection(nConn net.Conn, config *ssh.ServerConfig, slots chan struct{}, timeout time.Duration, start SessionStarter, authorizeGateway GatewayAuthorizer) {
	peer := nConn.RemoteAddr().String()
	decision := guard.Admit(peer)
	if !decision.Allow {
		log.Printf("guard: refused addr=%s reason=%s", peer, decision.Reason)
		_ = nConn.Close()
		return
	}
	select {
	case slots <- struct{}{}:
	default:
		// Not the peer's fault: no guard strike.
		log.Printf("ssh: refused addr=%s reason=pre-auth slots full", peer)
		_ = nConn.Close()
		return
	}
	conn, chans, reqs, err := handshake(nConn, config, slots, timeout)
	if err != nil {
		guard.NoteHandshake(peer, false)
		log.Printf("Failed to handshake: %v", err)
		return
	}
	guard.NoteHandshake(peer, true)
	fp := conn.Permissions.Extensions["pubkey-fp"]
	log.Printf("New SSH connection from %s (%s) key=%s", conn.RemoteAddr(), conn.ClientVersion(), fp)

	go ssh.DiscardRequests(reqs)

	principals, err := principalsFromPermissions(conn.Permissions)
	if err != nil {
		log.Printf("ssh: refusing connection from %s: %v", conn.RemoteAddr(), err)
		_ = conn.Close()
		return
	}
	name := conn.User()
	sessionSlots := make(chan struct{}, max(maxSessionsPerConn, 1))
	tcpSlots := make(chan struct{}, max(maxDirectTCPIPPerConn, 1))
	userLimit := maxSessionsPerUser

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			if !trySlot(tcpSlots) {
				_ = newChannel.Reject(ssh.ResourceShortage, "too many forwarded channels on this connection") // best-effort
				continue
			}
			go func(nc ssh.NewChannel) {
				defer func() { <-tcpSlots }()
				handleDirectTCPIP(conn, nc, principals, authorizeGateway)
			}(newChannel)
		case "session":
			if !trySlot(sessionSlots) {
				_ = newChannel.Reject(ssh.ResourceShortage, "too many sessions on this connection") // best-effort
				continue
			}
			if !acquireUserSession(name, userLimit) {
				<-sessionSlots
				_ = newChannel.Reject(ssh.ResourceShortage, "too many sessions for this user") // best-effort
				continue
			}
			var once sync.Once
			release := func() {
				once.Do(func() {
					releaseUserSession(name)
					<-sessionSlots
				})
			}
			serveSessionChannel(newChannel, name, principals, start, release)
		default:
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type") // best-effort
		}
	}
}

// serveSessionChannel accepts one session channel and starts the session
// process when the client sends "shell". release runs exactly once, when the
// channel is refused or the session ends.
func serveSessionChannel(newChannel ssh.NewChannel, name string, principals []string, start SessionStarter, release func()) {
	if err := RequireResolvableSSHUser(name); err != nil {
		log.Printf("ssh: refusing session: %v", err)
		_ = newChannel.Reject(ssh.Prohibited, "login does not resolve") // best-effort
		release()
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel: %v", err)
		release()
		return
	}

	// ISIG stays on. The child is its own session leader, so Ctrl-C and
	// Ctrl-Z reach its foreground process group and not the listener.
	ptyMaster, ptySlave, err := pty.Open()
	if err == nil {
		if ptyMaster, err = pollablePTY(ptyMaster); err != nil {
			ptySlave.Close()
		}
	}
	if err != nil {
		log.Printf("Could not start pty: %v", err)
		channel.Close()
		release()
		return
	}
	sessionID := GenerateSessionID()
	outCast := NewOutputBroadcaster(channel)
	session := &Session{
		ID:         sessionID,
		User:       name,
		Principals: principals,
		PTYMaster:  ptyMaster,
		Out:        outCast,
	}
	session.SetDropPrivileges(true)
	if err := RegisterSession(session); err != nil {
		log.Printf("ssh: register session: %v", err)
		channel.Close()
		ptyMaster.Close()
		ptySlave.Close()
		release()
		return
	}
	session.SetPromptWriter(outCast)

	setSize := func(ws *pty.Winsize) error { return setPTYSize(ptyMaster, ws) }
	shell := make(chan struct{})
	requestsDone := make(chan struct{})
	go func() {
		defer close(requestsDone)
		started := false
		for req := range requests {
			ok := false
			switch req.Type {
			case "shell":
				ok = !started
				if ok {
					started = true
					// Reply before the process starts, so the client is
					// ready for output.
					_ = req.Reply(true, nil) // best-effort
					close(shell)
					continue
				}
			case "pty-req":
				ok = applyPTYRequest(setSize, req.Payload)
				if ok && !started {
					if term := ptyTerm(req.Payload); term != "" {
						_ = session.SetEnv("TERM", term) // validated above
					}
				}
			case "window-change":
				ok = applyWindowChange(setSize, req.Payload)
			}
			// exec, env, subsystem, and anything unknown are refused.
			_ = req.Reply(ok, nil) // best-effort
		}
	}()

	go func() {
		defer release()
		defer channel.Close()
		defer ptyMaster.Close()
		defer ptySlave.Close()
		defer UnregisterSession(sessionID)

		select {
		case <-shell:
		case <-requestsDone:
			select {
			case <-shell:
			default:
				return
			}
		}
		go func() { _, _ = io.Copy(outCast, ptyMaster) }() // best-effort: stream ends on session close
		// EOF on the client's stdin does not end a pty session.
		go func() { _, _ = io.Copy(ptyMaster, channel) }() // best-effort
		// The request stream ends when the client closes the channel or
		// the connection drops. Closing the master hangs up the pty, so
		// the session process gets SIGHUP and the slots are released.
		go func() {
			<-requestsDone
			_ = ptyMaster.Close()
		}()
		// The starter blocks until the session process exits.
		start(sessionID, name, principals, ptySlave, ptySlave, ptySlave)
	}()
}

const (
	maxTermLen = 64
	maxPTYDim  = 1000
)

// ptyRequest is the RFC 4254 section 6.2 pty-req payload.
type ptyRequest struct {
	Term   string
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
	Modes  string
}

// windowChange is the RFC 4254 section 6.7 window-change payload.
type windowChange struct {
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
}

// clampDims maps 0 to 80x24 and caps each side at maxPTYDim.
func clampDims(cols, rows uint32) *pty.Winsize {
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	return &pty.Winsize{Cols: uint16(min(cols, maxPTYDim)), Rows: uint16(min(rows, maxPTYDim))}
}

// applyPTYRequest decodes a pty-req payload and applies its size. A payload
// that does not decode exactly, or a term longer than maxTermLen, is refused
// and setSize is not called.
func applyPTYRequest(setSize func(*pty.Winsize) error, payload []byte) bool {
	var req ptyRequest
	if err := ssh.Unmarshal(payload, &req); err != nil || len(req.Term) > maxTermLen {
		return false
	}
	return setSize(clampDims(req.Cols, req.Rows)) == nil
}

// ptyTerm returns the pty-req terminal name when it is a plain terminfo
// name, and "" otherwise.
func ptyTerm(payload []byte) string {
	var req ptyRequest
	if err := ssh.Unmarshal(payload, &req); err != nil || req.Term == "" || len(req.Term) > maxTermLen {
		return ""
	}
	for _, r := range req.Term {
		if ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '+'; !ok {
			return ""
		}
	}
	return req.Term
}

// applyWindowChange decodes a window-change payload and applies its size.
func applyWindowChange(setSize func(*pty.Winsize) error, payload []byte) bool {
	var req windowChange
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return false
	}
	return setSize(clampDims(req.Cols, req.Rows)) == nil
}

type directTCPIPPayload struct {
	TargetHost     string
	TargetPort     uint32
	OriginatorHost string
	OriginatorPort uint32
}

// resolveGatewayTarget returns host as an address, resolving a name once
// under gatewayDialTimeout.
func resolveGatewayTarget(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), gatewayDialTimeout)
	defer cancel()
	ips, err := gatewayLookupIP(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("gateway target does not resolve")
	}
	return ips[0], nil
}

// handleDirectTCPIP authorizes, dials, and copies one forwarded channel. It
// returns when the copy ends, so the caller's slot is held for the life of
// the channel.
func handleDirectTCPIP(conn *ssh.ServerConn, newChannel ssh.NewChannel, principals []string, authorize GatewayAuthorizer) {
	payload, err := parseDirectTCPIPPayload(newChannel.ExtraData())
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	if authorize == nil {
		_ = newChannel.Reject(ssh.Prohibited, "gateway forwarding is disabled")
		return
	}
	ip, err := resolveGatewayTarget(payload.TargetHost)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	address := ip.String()
	req := GatewayAuthRequest{
		SessionID:      GenerateSessionID(),
		User:           conn.User(),
		Principals:     principals,
		TargetHost:     payload.TargetHost,
		TargetIP:       address,
		TargetPort:     payload.TargetPort,
		OriginatorHost: payload.OriginatorHost,
		OriginatorPort: payload.OriginatorPort,
	}
	if err := authorize(req); err != nil {
		_ = newChannel.Reject(ssh.Prohibited, err.Error())
		return
	}
	target := net.JoinHostPort(address, strconv.FormatUint(uint64(payload.TargetPort), 10))
	targetConn, err := gatewayDial("tcp", target, gatewayDialTimeout)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "gateway target is unreachable")
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = targetConn.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	defer channel.Close()
	defer targetConn.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, channel)
		// Half-close so the far side sees EOF and the reverse copy ends.
		if tc, ok := targetConn.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = targetConn.Close()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(channel, targetConn)
		_ = channel.CloseWrite()
	}()
	wg.Wait()
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
