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

	"github.com/creack/pty"
	"go.starlark.net/starlark"
	"golang.org/x/crypto/ssh"
)

func adsshDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(homeDir, ".adssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create %s: %v", dir, err)
	}
	return dir, nil
}

// loadOrGenerateHostKey loads the persistent SSH host key from ~/.adssh/host_key,
// generating and saving a new RSA 4096 key if one does not exist.
func loadOrGenerateHostKey() (ssh.Signer, error) {
	dir, err := adsshDir()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "host_key")

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

// loadAuthorizedKeys reads public keys from ~/.adssh/authorized_keys.
// Returns nil, nil if the file does not exist.
func loadAuthorizedKeys() (map[string]bool, error) {
	dir, err := adsshDir()
	if err != nil {
		return nil, err
	}
	authKeysPath := filepath.Join(dir, "authorized_keys")

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

func StartSSHServer(address string, globals starlark.StringDict, restricted bool, replStartFn func(starlark.StringDict, bool, io.ReadCloser, io.Writer, io.Writer)) {
	authorizedKeys, err := loadAuthorizedKeys()
	if err != nil {
		log.Fatalf("Failed to load authorized keys: %v", err)
	}
	if len(authorizedKeys) == 0 {
		log.Fatalf(
			"No authorized keys found.\n"+
				"Add your public key to allow SSH access:\n"+
				"  mkdir -p ~/.adssh\n"+
				"  cat ~/.ssh/id_ed25519.pub >> ~/.adssh/authorized_keys",
		)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeys[string(key.Marshal())] {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(key),
					},
				}, nil
			}
			return nil, fmt.Errorf("unauthorized key from %s", conn.RemoteAddr())
		},
	}

	signer, err := loadOrGenerateHostKey()
	if err != nil {
		log.Fatalf("Failed to load/generate host key: %v", err)
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", address, err)
	}

	fmt.Printf("adssh SSH daemon listening on %s\n", address)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %v", err)
			continue
		}
		go handleSSHConnection(nConn, config, globals, restricted, replStartFn)
	}
}

type sshReadCloser struct {
	ssh.Channel
}

func handleSSHConnection(nConn net.Conn, config *ssh.ServerConfig, globals starlark.StringDict, restricted bool, replStartFn func(starlark.StringDict, bool, io.ReadCloser, io.Writer, io.Writer)) {
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

		session := &Session{
			ID:        sessionID,
			PTYMaster: ptyMaster,
			Out:       outCast,
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

			go io.Copy(outCast, ptyMaster)
			go io.Copy(ptyMaster, channel)

			replStartFn(env, restricted, ptySlave, ptySlave, ptySlave)
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
