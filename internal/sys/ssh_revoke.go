package sys

// Threats: without revocation a leaked key stays good until it is removed
// from authorized_keys and a leaked certificate stays good until it expires.
// ADSSH_REVOKED_KEYS names a file the listener checks on every login. It is
// re-read when its size or modification time changes, so a revocation takes
// effect on the next login without a restart. When the setting is present,
// a missing, unreadable, oversized, or malformed file refuses every login:
// a broken revocation list must not let a revoked key back in.
//
// One entry per line; blank lines and lines starting with # are ignored:
//
//	SHA256:<base64>   a key fingerprint: a raw key, a certificate's key, a
//	                  presented certificate, or a CA (revoking a CA refuses
//	                  every certificate it signed)
//	serial:<n>        a certificate serial number
//	keyid:<id>        a certificate key id

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const revokedKeysMax = 1 << 20

type revocationList struct {
	fingerprints map[string]bool
	serials      map[uint64]bool
	keyIDs       map[string]bool
}

func parseRevocationList(data []byte) (*revocationList, error) {
	rl := &revocationList{fingerprints: map[string]bool{}, serials: map[uint64]bool{}, keyIDs: map[string]bool{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 4096)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "SHA256:") && len(line) > len("SHA256:") && !strings.ContainsAny(line, " \t"):
			rl.fingerprints[line] = true
		case strings.HasPrefix(line, "serial:"):
			v, err := strconv.ParseUint(strings.TrimPrefix(line, "serial:"), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad serial", n)
			}
			rl.serials[v] = true
		case strings.HasPrefix(line, "keyid:") && len(line) > len("keyid:"):
			rl.keyIDs[strings.TrimPrefix(line, "keyid:")] = true
		default:
			return nil, fmt.Errorf("line %d: not SHA256:..., serial:N, or keyid:ID", n)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rl, nil
}

// revocationChecker reloads the list when the file changes.
type revocationChecker struct {
	path    string
	mu      sync.Mutex
	size    int64
	modTime time.Time
	list    *revocationList
	loadErr error
}

func newRevocationChecker(path string) *revocationChecker {
	return &revocationChecker{path: path}
}

func (c *revocationChecker) current() (*revocationList, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, err := os.Stat(c.path)
	if err != nil {
		c.list, c.loadErr = nil, fmt.Errorf("revoked keys %s: %w", c.path, err)
		return nil, c.loadErr
	}
	if c.list != nil && info.Size() == c.size && info.ModTime().Equal(c.modTime) {
		return c.list, nil
	}
	if !info.Mode().IsRegular() || info.Size() > revokedKeysMax {
		c.list, c.loadErr = nil, fmt.Errorf("revoked keys %s: not a regular file of at most %d bytes", c.path, revokedKeysMax)
		return nil, c.loadErr
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		c.list, c.loadErr = nil, fmt.Errorf("revoked keys %s: %w", c.path, err)
		return nil, c.loadErr
	}
	list, err := parseRevocationList(data)
	if err != nil {
		c.list, c.loadErr = nil, fmt.Errorf("revoked keys %s: %w", c.path, err)
		return nil, c.loadErr
	}
	c.list, c.loadErr, c.size, c.modTime = list, nil, info.Size(), info.ModTime()
	return list, nil
}

// check returns an error when key is revoked or the list cannot be read.
func (c *revocationChecker) check(key ssh.PublicKey) error {
	list, err := c.current()
	if err != nil {
		return err
	}
	if list.fingerprints[ssh.FingerprintSHA256(key)] {
		return fmt.Errorf("ssh: key is revoked")
	}
	if cert, ok := key.(*ssh.Certificate); ok {
		switch {
		case cert.Key != nil && list.fingerprints[ssh.FingerprintSHA256(cert.Key)]:
			return fmt.Errorf("ssh: certificate key is revoked")
		case cert.SignatureKey != nil && list.fingerprints[ssh.FingerprintSHA256(cert.SignatureKey)]:
			return fmt.Errorf("ssh: certificate authority is revoked")
		case list.serials[cert.Serial]:
			return fmt.Errorf("ssh: certificate serial %d is revoked", cert.Serial)
		case list.keyIDs[cert.KeyId]:
			return fmt.Errorf("ssh: certificate key id is revoked")
		}
	}
	return nil
}
