package sys

import (
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
	"go.starlark.net/starlark"
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

// loadAuthorizedKeys reads public keys from authKeysPath.
// Returns nil, nil if the file does not exist.
func loadAuthorizedKeys(authKeysPath string) (map[string]bool, error) {

	data, err := os.ReadFile(authKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read %s: %v", authKeysPath, err)
	}

	authorizedKeys := make(map[string]bool)
	for len(data) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			break
		}
		authorizedKeys[string(pubKey.Marshal())] = true
		data = rest
	}
	return authorizedKeys, nil
}

var (
	sshListener net.Listener
	sshMu       sync.Mutex
)

// EnableSSH starts the SSH daemon in the background. It returns an error if already running or if not root.
func EnableSSH(address, hostKeyPath, authorizedKeysPath string, globals starlark.StringDict, restricted bool, replStartFn func(starlark.StringDict, bool, string, io.ReadCloser, io.Writer, io.Writer)) error {
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
	if len(authorizedKeys) == 0 {
		return fmt.Errorf(
			"no authorized keys found in %s\n"+
				"add your public key to allow SSH access:\n"+
				"  cat ~/.ssh/id_ed25519.pub >> %s",
			authorizedKeysPath, authorizedKeysPath,
		)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			perms := &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(key),
				},
			}

			if cert, ok := key.(*ssh.Certificate); ok {
				perms.Extensions["principals"] = strings.Join(cert.ValidPrincipals, ",")
				if authorizedKeys[string(cert.SignatureKey.Marshal())] {
					return perms, nil
				}
			}

			if authorizedKeys[string(key.Marshal())] {
				return perms, nil
			}
			return nil, fmt.Errorf("unauthorized key from %s", conn.RemoteAddr())
		},
	}

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
			go handleSSHConnection(nConn, config, globals, restricted, hostKeyPath, replStartFn)
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

func handleSSHConnection(nConn net.Conn, config *ssh.ServerConfig, globals starlark.StringDict, restricted bool, historyFile string, replStartFn func(starlark.StringDict, bool, string, io.ReadCloser, io.Writer, io.Writer)) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	fp := conn.Permissions.Extensions["pubkey-fp"]
	log.Printf("New SSH connection from %s (%s) key=%s", conn.RemoteAddr(), conn.ClientVersion(), fp)

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
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
					req.Reply(true, nil)
				case "pty-req":
					termLen := req.Payload[3]
					w, h := parseDims(req.Payload[termLen+4:])
					pty.Setsize(ptyMaster, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
					req.Reply(true, nil)
				case "window-change":
					w, h := parseDims(req.Payload)
					pty.Setsize(ptyMaster, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
					req.Reply(true, nil)
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

		sessionGlobals := make(starlark.StringDict)
		for k, v := range globals {
			sessionGlobals[k] = v
		}
		sessionGlobals["SESSION_ID"] = starlark.String(sessionID)

		go func(env starlark.StringDict) {
			defer channel.Close()
			defer ptyMaster.Close()
			defer ptySlave.Close()
			defer UnregisterSession(sessionID)

			interceptedChannel := &CtrlCInterceptor{r: channel, session: session}

			go io.Copy(outCast, ptyMaster)
			go io.Copy(ptyMaster, interceptedChannel)

			replStartFn(env, restricted, historyFile, ptySlave, ptySlave, ptySlave)
		}(sessionGlobals)
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
