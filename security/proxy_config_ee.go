//go:build ee

package security

// Threats: only a listener-owned, bounded regular file may grant destinations.
// Unknown users, malformed/oversized files, writable files, unpinned addresses,
// and unknown fields fail closed. The parent directory must be administrator
// controlled. This is an application gate, not an OS network sandbox; shell
// escapes and arbitrary Starlark networking require separate confinement.

import (
	"bytes"
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

	"github.com/afterdarksys/adssh/internal/safefile"
	"golang.org/x/crypto/ssh"
)

const maxProxyConfig = 1 << 20

type proxyTarget struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port uint32 `json:"port"`
	// User and HostKey are required only for interactive SSH.
	User    string `json:"user,omitempty"`
	HostKey string `json:"host_key,omitempty"`
}

type proxyConfig struct {
	Users map[string][]proxyTarget `json:"users"`
}

func readProxyConfig() (*proxyConfig, error) {
	path := os.Getenv("ADSSH_PROXY_CONFIG")
	if path == "" {
		return nil, errors.New("proxy: ADSSH_PROXY_CONFIG is required")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("proxy: configuration path must be absolute")
	}
	f, info, err := safefile.Open(nil, path)
	if err != nil {
		return nil, fmt.Errorf("proxy: configuration unavailable: %w", err)
	}
	defer f.Close()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("proxy: configuration must be administrator-owned and not group/world writable")
	}
	data, err := safefile.ReadAll(f, info, maxProxyConfig)
	if err != nil {
		return nil, fmt.Errorf("proxy: configuration: %w", err)
	}
	return decodeProxyConfig(data)
}

func decodeProxyConfig(data []byte) (*proxyConfig, error) {
	if len(data) > maxProxyConfig {
		return nil, errors.New("proxy: configuration too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg proxyConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("proxy: invalid configuration: %w", err)
	}
	if dec.Decode(new(any)) != io.EOF || cfg.Users == nil {
		return nil, errors.New("proxy: invalid configuration")
	}
	for user, targets := range cfg.Users {
		if !proxyToken(user) {
			return nil, errors.New("proxy: invalid user")
		}
		seen := map[string]bool{}
		for _, target := range targets {
			if err := target.validate(); err != nil {
				return nil, err
			}
			key := net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port)))
			if seen[key] {
				return nil, errors.New("proxy: duplicate destination")
			}
			seen[key] = true
		}
	}
	return &cfg, nil
}

func proxyToken(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("._-:@", c) {
			return false
		}
	}
	return true
}

func (t proxyTarget) validate() error {
	ip := net.ParseIP(t.IP)
	if !proxyToken(t.Host) || ip == nil || ip.IsUnspecified() || ip.IsMulticast() || t.Port == 0 || t.Port > 65535 {
		return errors.New("proxy: invalid destination")
	}
	if t.User != "" || t.HostKey != "" {
		if !proxyToken(t.User) {
			return errors.New("proxy: invalid SSH user")
		}
		if _, err := proxyHostKey(t.HostKey); err != nil {
			return err
		}
	}
	return nil
}

func proxyHostKey(s string) (ssh.PublicKey, error) {
	if len(s) > 1024 {
		return nil, errors.New("proxy: pinned host key too large")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("proxy: invalid pinned host key")
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("proxy: host key must be Ed25519")
	}
	return key, nil
}

func (c *proxyConfig) target(user, host string, port uint32) (proxyTarget, error) {
	for _, t := range c.Users[user] {
		if t.Host == host && t.Port == port {
			return t, nil
		}
	}
	return proxyTarget{}, errors.New("proxy: destination is not authorized for this user")
}

// checkProxyGateway also covers native direct-tcpip and gateway start, so those
// entry points cannot bypass the configured per-user destination list.
func checkProxyGateway(user string, req GatewayPolicyRequest) error {
	if os.Getenv("ADSSH_PROXY_CONFIG") == "" {
		return nil
	}
	cfg, err := readProxyConfig()
	if err != nil {
		return err
	}
	t, err := cfg.target(user, req.TargetHost, req.TargetPort)
	if err != nil {
		return err
	}
	ip := net.ParseIP(req.TargetIP)
	if ip == nil || !ip.Equal(net.ParseIP(t.IP)) {
		return errors.New("proxy: resolved address does not match authorized destination")
	}
	return nil
}
