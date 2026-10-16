package main

// Threats: adsshadm holds an admin API key, and a named key can approve,
// deny, unban, and attach to sessions. The key is read only from a regular
// 0600 file owned by this user, opened without following a symlink, and never
// from argv or the environment value itself, so it does not show in ps or a
// shell history. The key is sent only to a loopback HTTP address or a Unix
// socket: the admin API listens nowhere else, and an http:// URL to any other
// host would hand the key to the network in clear text. Response bodies are
// size-capped. This does not protect a key that leaks from this machine or
// authenticate the server beyond the loopback/socket path.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	keyFileMax      = 4 << 10
	keyMinBytes     = 32
	responseMax     = 8 << 20
	requestTimeout  = 30 * time.Second
	defaultAdminURL = "http://127.0.0.1:8787" // admin serve default
)

// endpoint is where the admin API listens: a loopback http URL or a socket.
type endpoint struct {
	base   string // http://host:port, used for request URLs
	socket string // non-empty for unix:/path
}

// parseEndpoint accepts unix:/abs/path or http://<loopback>:port. Anything
// else is refused before a key is read.
func parseEndpoint(raw string) (endpoint, error) {
	if raw == "" {
		raw = defaultAdminURL
	}
	if path, ok := strings.CutPrefix(raw, "unix:"); ok {
		if !strings.HasPrefix(path, "/") {
			return endpoint{}, fmt.Errorf("admin socket must be an absolute path: %q", raw)
		}
		return endpoint{base: "http://adssh-admin", socket: path}, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return endpoint{}, fmt.Errorf("admin URL must be http://<loopback>:port or unix:/path: %q", raw)
	}
	host := u.Hostname()
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return endpoint{}, fmt.Errorf("admin URL must be a loopback address; the admin API never listens elsewhere: %q", raw)
	}
	if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
		return endpoint{}, fmt.Errorf("admin URL needs a port: %q", raw)
	}
	return endpoint{base: "http://" + net.JoinHostPort(host, u.Port())}, nil
}

// checkSocket refuses a socket path that is not a socket or that belongs to
// someone other than this user or root, so another local user cannot stand
// up a fake admin API to collect the key while adssh is down. A loopback TCP
// port cannot be checked this way; prefer unix: where that matters.
func checkSocket(ep endpoint) error {
	if ep.socket == "" {
		return nil
	}
	info, err := os.Lstat(ep.socket)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("admin socket %s is not a socket", ep.socket)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() && st.Uid != 0 {
		return fmt.Errorf("admin socket %s belongs to uid %d, not you or root", ep.socket, st.Uid)
	}
	return nil
}

// loadKey reads one key from path. The file must be a regular file owned by
// this user with mode 0600 or stricter, and must not be a symlink.
func loadKey(path string) (string, error) {
	if path == "" {
		return "", errors.New("no admin key file: pass --key-file or set ADSSH_ADMIN_KEY_FILE")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("admin key file: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("admin key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("admin key file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("admin key file mode %04o grants group or other access; chmod 600 it", info.Mode().Perm())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return "", errors.New("admin key file is owned by another user")
	}
	data, err := io.ReadAll(io.LimitReader(f, keyFileMax+1))
	if err != nil {
		return "", fmt.Errorf("admin key file: %w", err)
	}
	if len(data) > keyFileMax {
		return "", errors.New("admin key file is too large")
	}
	key := strings.TrimSpace(string(data))
	if len(key) < keyMinBytes || strings.ContainsAny(key, " \t\r\n") {
		return "", fmt.Errorf("admin key file must hold one key of at least %d bytes with no whitespace", keyMinBytes)
	}
	return key, nil
}

// client talks to one admin API endpoint with one key.
type client struct {
	ep   endpoint
	key  string
	http *http.Client
}

func newClient(ep endpoint, key string) *client {
	tr := &http.Transport{Proxy: nil, DisableCompression: true}
	if ep.socket != "" {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", ep.socket)
		}
	}
	return &client{ep: ep, key: key, http: &http.Client{Transport: tr, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// apiError is a non-2xx answer from the admin API.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "unauthorized: the admin API did not accept this key"
	case http.StatusForbidden:
		if e.Message != "" {
			return "forbidden: " + clean(e.Message)
		}
		return "forbidden"
	}
	if e.Message != "" {
		return fmt.Sprintf("admin API %d: %s", e.Status, clean(e.Message))
	}
	return fmt.Sprintf("admin API %d", e.Status)
}

// do sends one request and decodes a JSON answer into out (when non-nil).
func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.ep.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("admin API unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, responseMax+1))
	if err != nil {
		return fmt.Errorf("admin API: %w", err)
	}
	if len(data) > responseMax {
		return errors.New("admin API response is too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return &apiError{Status: resp.StatusCode, Message: e.Error}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("admin API returned invalid JSON: %w", err)
	}
	return nil
}
